// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Build-time validation for logical upstream binding.
//!
//! A pipeline that uses binding (a `bound_upstream` condition, a
//! `cluster_source: bound_upstream` load balancer, a bound-upstream body
//! participant, or an IRR step that reads the binding) gets its routers
//! promoted to binding publishers. These checks prove every consumer sees a
//! binding, no path republishes one, every bindable cluster reaches a load
//! balancer that can serve it, and cluster metadata declarations agree.
//!
//! Called from [`FilterPipeline::ordering_errors`] through the re-exports in
//! the parent `checks` module.
//!
//! [`FilterPipeline::ordering_errors`]: crate::pipeline::FilterPipeline::ordering_errors

use praxis_core::config::Condition;

use crate::{
    any_filter::AnyFilter,
    body::{BodyAccess, BodyMode},
    pipeline::{
        branch::{RejoinTarget, ResolvedBranch},
        filter::PipelineFilter,
    },
};

// -----------------------------------------------------------------------------
// Error Checks
// -----------------------------------------------------------------------------

/// Cluster declarations in a binding-enabled pipeline that disagree on
/// application metadata.
///
/// The binding router resolves a matched cluster's opaque protocol and
/// provider through the pipeline catalog. When two filters declare the same
/// cluster name with differing tags, the catalog cannot resolve a single
/// value: [`build_catalog`] keeps the first-seen declaration for determinism,
/// and this check turns every disagreement into a configuration error before
/// the pipeline serves traffic, so the runtime map is only consulted once no
/// conflicts remain. The caller skips this check for ordinary routing, where
/// each load balancer owns its selected endpoint metadata and declarations in
/// independent dispatch paths need not agree. Agreeing re-declarations in a
/// binding-enabled pipeline are silent.
///
/// [`build_catalog`]: crate::pipeline::catalog::build_catalog
pub(in crate::pipeline) fn check_cluster_metadata_conflicts(filters: &[PipelineFilter], errors: &mut Vec<String>) {
    let (_, conflicts) =
        crate::pipeline::catalog::build_catalog(crate::pipeline::collect_cluster_declarations(filters));
    for conflict in conflicts {
        errors.push(format!(
            "cluster '{cluster}' is declared with conflicting application metadata \
             (protocol {first_protocol:?} / provider {first_provider:?} vs \
             protocol {second_protocol:?} / provider {second_provider:?}); every \
             declaration of a cluster must agree on its protocol and provider",
            cluster = conflict.cluster,
            first_protocol = conflict.first.protocol(),
            first_provider = conflict.first.provider(),
            second_protocol = conflict.second.protocol(),
            second_provider = conflict.second.provider(),
        ));
    }
}

/// A `bound_upstream` condition requires a guaranteed preceding binding.
///
/// A `bound_upstream` condition reads the logical binding published by a
/// binding filter ([`binds_upstream`]). When no binding is *guaranteed* to run
/// before such a condition on every path that reaches it, the condition can
/// silently never match — a fail-open footgun. Reject it at build time.
///
/// Path sensitivity: only an *unconditional* binding filter guarantees a
/// binding (a conditional router may be skipped), and a `SkipTo` branch that
/// jumps over the binding, or an unreachable path, leaves the binding
/// un-guaranteed. [`compute_binding_guaranteed`] resolves this over the
/// pipeline control-flow graph; branch sub-chains inherit the guarantee
/// established up to and including their host filter (a branch runs after its
/// host's `on_request`). A binding publisher inside a branch is never credited:
/// the request-scoped binding router must be top-level, which keeps the freeze
/// point unique and visible.
///
/// `entry_binding_guaranteed` is `true` when this pipeline runs as an
/// `iterative_request_router` step: the parent already guarantees a binding
/// before the IRR (its own reachability check enforces this), so a step's bound
/// consumer inherits that guarantee on entry.
///
/// [`binds_upstream`]: crate::HttpFilter::binds_upstream
pub(in crate::pipeline) fn check_bound_upstream_requires_binding(
    filters: &[PipelineFilter],
    entry_binding_guaranteed: bool,
    errors: &mut Vec<String>,
) {
    let guaranteed = compute_binding_guaranteed(filters, entry_binding_guaranteed);
    for (&binding_here, pf) in guaranteed.iter().zip(filters) {
        if !binding_here && let Some(reason) = binding_requirement_reason(pf) {
            errors.push(format!(
                "filter '{name}' requires a bound logical upstream ({reason}) but no \
                 preceding filter is guaranteed to bind one; place an unconditional \
                 binding router earlier in the pipeline",
                name = pf.filter.name(),
            ));
        }

        // The host filter's on_request runs before its branches are evaluated,
        // so a binding guaranteed on entry — or an unconditional binding by the
        // host itself — is visible inside its branches.
        let branch_binding_before = binding_here || unconditional_binds(pf);
        for branch in &pf.branches {
            walk_branch_bound_upstream_binding(&branch.filters, branch_binding_before, errors);
        }
    }
}

/// Whether this pipeline or one of its branches observes or consumes the
/// logical upstream binding.
///
/// Binding publishers are deliberately excluded: a router is enabled only
/// because some other filter needs the binding, never merely because the
/// router exists.
pub(in crate::pipeline) fn uses_bound_upstream(filters: &[PipelineFilter]) -> bool {
    filters.iter().any(|pf| {
        has_bound_upstream_condition(pf)
            || matches!(&pf.filter, AnyFilter::Http(filter)
                if crate::pipeline::body::participates_in_bound_upstream_body(filter.as_ref())
                    || filter.consumes_bound_upstream()
                    || filter.requires_bound_upstream_on_entry())
            || pf.branches.iter().any(|branch| uses_bound_upstream(&branch.filters))
    })
}

/// Walk a branch sub-chain in order, tracking whether a binding is guaranteed,
/// and report every `bound_upstream` condition reached without one.
///
/// Branch sub-chains run `on_request` linearly, so a plain left-to-right walk
/// suffices; nested branches inherit the guarantee up to and including their
/// host filter.
fn walk_branch_bound_upstream_binding(filters: &[PipelineFilter], mut binding_before: bool, errors: &mut Vec<String>) {
    for pf in filters {
        if !binding_before && let Some(reason) = binding_requirement_reason(pf) {
            errors.push(format!(
                "filter '{name}' requires a bound logical upstream ({reason}) but no \
                 preceding filter is guaranteed to bind one; place an unconditional \
                 binding router earlier in the pipeline",
                name = pf.filter.name(),
            ));
        }
        let branch_binding_before = binding_before || unconditional_binds(pf);
        for branch in &pf.branches {
            walk_branch_bound_upstream_binding(&branch.filters, branch_binding_before, errors);
        }
        binding_before = branch_binding_before;
    }
}

/// Forward dataflow over the top-level pipeline control-flow graph: for each
/// filter index, whether a logical binding is guaranteed on entry (every path
/// from the pipeline start to that filter passes through an unconditional
/// binding filter).
///
/// Edges: the normal fall-through `i -> i+1`, plus each branch rejoin that
/// transfers control elsewhere — `SkipTo(t)` and `ReEnter(t)` add `i -> t`.
/// `Next` is the fall-through already modeled; `Terminal` stops the pipeline
/// and so reaches no later filter. A binding is guaranteed at a node only when
/// it is guaranteed on *every* incoming edge, so a node's value is the
/// intersection (logical AND) of its incoming edge values. Values start
/// optimistic and iterate to a fixpoint because `ReEnter` introduces back
/// edges. An unreachable node (no incoming edge) resolves to `false`, which is
/// the safe (reject) direction.
///
/// `entry_binding_guaranteed` seeds the pipeline-entry node: `false` for a
/// top-level pipeline (nothing is bound before it starts), `true` for an
/// `iterative_request_router` step, which runs as a continuation of a parent
/// that already guarantees a binding before the IRR.
fn compute_binding_guaranteed(filters: &[PipelineFilter], entry_binding_guaranteed: bool) -> Vec<bool> {
    let len = filters.len();
    let mut guaranteed = vec![true; len];
    if len == 0 {
        return guaranteed;
    }

    let edges = binding_control_flow_edges(filters);
    let reachable = binding_reachable_nodes(len, &edges);
    // Values start optimistic (`true`) and only ever weaken; iterate the
    // relaxation pass until it reaches a fixpoint (needed for `ReEnter` back
    // edges).
    while relax_binding_guarantees(filters, &edges, &reachable, &mut guaranteed, entry_binding_guaranteed) {}
    guaranteed
}

/// Nodes reachable from pipeline entry, independent of binding state.
fn binding_reachable_nodes(len: usize, edges: &[(usize, usize, bool)]) -> Vec<bool> {
    let mut reachable = vec![false; len];
    if let Some(entry) = reachable.first_mut() {
        *entry = true;
    }
    loop {
        let mut changed = false;
        for &(from, to, _) in edges {
            if reachable.get(from).copied().unwrap_or(false)
                && let Some(target) = reachable.get_mut(to)
                && !*target
            {
                *target = true;
                changed = true;
            }
        }
        if !changed {
            return reachable;
        }
    }
}

/// Control-flow edges `(from, to, fall_through)` over the top-level pipeline: the
/// fall-through `i -> i+1` (`fall_through = true`), plus each `SkipTo`/`ReEnter`
/// branch rejoin that transfers control to another in-range filter
/// (`fall_through = false`). `Next` is the fall-through already modeled and
/// `Terminal` reaches no later filter, so neither adds an edge.
///
/// The fall-through flag is retained to mirror the rest of the control-flow
/// analysis. Both edge kinds currently use only top-level unconditional
/// publishers because branch-local binding is rejected.
fn binding_control_flow_edges(filters: &[PipelineFilter]) -> Vec<(usize, usize, bool)> {
    let len = filters.len();
    let mut edges: Vec<(usize, usize, bool)> = Vec::new();
    for (idx, pf) in filters.iter().enumerate() {
        let unconditional_terminal = pf.conditions.is_empty()
            && matches!(&pf.filter, AnyFilter::Http(filter) if filter.produces_terminal_response());
        let unconditional_skip = pf.conditions.is_empty()
            && pf.branches.iter().any(|branch| {
                branch.condition.is_none() && matches!(branch.rejoin, RejoinTarget::SkipTo(_) | RejoinTarget::Terminal)
            });
        if idx + 1 < len && !unconditional_terminal && !unconditional_skip {
            edges.push((idx, idx + 1, true));
        }
        for branch in &pf.branches {
            match branch.rejoin {
                RejoinTarget::SkipTo(target) | RejoinTarget::ReEnter(target) if target < len => {
                    edges.push((idx, target, false));
                },
                RejoinTarget::SkipTo(_) | RejoinTarget::ReEnter(_) | RejoinTarget::Terminal | RejoinTarget::Next => {},
            }
        }
    }
    edges
}

/// One relaxation pass: recompute each node's guaranteed-on-entry value as the
/// intersection (AND) of its incoming edges' exit values, and return whether any
/// value changed.
fn relax_binding_guarantees(
    filters: &[PipelineFilter],
    edges: &[(usize, usize, bool)],
    reachable: &[bool],
    guaranteed: &mut [bool],
    entry_binding_guaranteed: bool,
) -> bool {
    let (out_fall_through, out_jump) = binding_exit_values(filters, guaranteed);

    let mut incoming: Vec<Option<bool>> = vec![None; guaranteed.len()];
    // The entry node's inbound binding state: nothing bound for a top-level
    // pipeline, or the parent's guaranteed binding for an IRR step.
    if let Some(entry) = incoming.first_mut() {
        *entry = Some(entry_binding_guaranteed);
    }
    for &(from, to, fall_through) in edges {
        if !reachable.get(from).copied().unwrap_or(false) {
            continue;
        }
        let out = if fall_through { &out_fall_through } else { &out_jump };
        let Some(&edge_out) = out.get(from) else { continue };
        if let Some(slot) = incoming.get_mut(to) {
            *slot = Some(slot.map_or(edge_out, |acc| acc && edge_out));
        }
    }

    let mut changed = false;
    for (slot, incoming_val) in guaranteed.iter_mut().zip(&incoming) {
        // Unreachable nodes resolve to `false`, but do not contribute to the
        // meet at reachable successors.
        let next = incoming_val.unwrap_or(false);
        if next != *slot {
            *slot = next;
            changed = true;
        }
    }
    changed
}

/// Compute the binding guarantee carried by each kind of outgoing edge.
fn binding_exit_values(filters: &[PipelineFilter], guaranteed: &[bool]) -> (Vec<bool>, Vec<bool>) {
    let fall_through = guaranteed
        .iter()
        .zip(filters)
        .map(|(&bound, pf)| bound || filter_exit_binds(pf))
        .collect();
    let jump = guaranteed
        .iter()
        .zip(filters)
        .map(|(&bound, pf)| bound || unconditional_binds(pf))
        .collect();
    (fall_through, jump)
}

/// `iterative_request_router` coexisting with a top-level `router` or
/// `load_balancer`.
///
/// The blanket router/IRR incompatibility is replaced by a control-flow-aware
/// rule:
///
/// - A top-level `load_balancer` still conflicts: it selects a physical endpoint before the IRR owns the exchange
///   lifecycle.
/// - A top-level `router` may coexist with the IRR *only* when some reachable consumer uses the binding — a
///   bound-consuming load balancer in a direct branch or inside an IRR step. A binding router with no bound consumer
///   anywhere is the old conflict: the router publishes a logical cluster nothing resolves.
///
/// The companion requirement — a binding must be *guaranteed* before the IRR
/// and every other bound consumer — is enforced by
/// [`check_bound_upstream_requires_binding`], because the IRR reports
/// [`consumes_bound_upstream`] once any step consumes the binding.
///
/// [`consumes_bound_upstream`]: crate::HttpFilter::consumes_bound_upstream
pub(in crate::pipeline) fn check_irr_coexistence(filters: &[PipelineFilter], names: &[&str], errors: &mut Vec<String>) {
    if !names.contains(&"iterative_request_router") {
        return;
    }
    if names.contains(&"load_balancer") {
        errors.push(
            "iterative_request_router and a top-level load_balancer in the \
             same chain: the IRR owns endpoint selection within its step \
             chains, and a top-level load_balancer selects a physical endpoint \
             before the IRR owns the exchange lifecycle"
                .to_owned(),
        );
    }
    if names.contains(&"router") && !any_consumes_bound_upstream(filters) {
        errors.push(
            "iterative_request_router and a top-level router in the same chain, \
             but no reachable consumer uses the logical binding: add a \
             load_balancer with cluster_source: bound_upstream on the direct \
             path or inside an IRR step, or remove the router"
                .to_owned(),
        );
    }
}

/// A bound-upstream load balancer must be able to resolve every bindable
/// cluster.
///
/// For each cluster a router may bind, the check follows the pipeline in order
/// and requires a load balancer that is guaranteed to execute for that
/// binding. An unconditional load balancer, or one guarded solely by a matching
/// `bound_upstream` predicate, supplies coverage. Request-dependent conditions
/// and result-dependent branch chains do not: they may bypass endpoint
/// selection at runtime. Both bound-source load balancers and ordinary
/// fallthrough load balancers count, because either can complete transport for
/// the bound cluster. Pipelines with no declared bound consumer are unaffected.
pub(in crate::pipeline) fn check_bound_cluster_coverage(filters: &[PipelineFilter], errors: &mut Vec<String>) {
    let coverage = guaranteed_bound_cluster_coverage(filters, true);
    if !declares_bound_cluster_consumer(filters) {
        return;
    }
    let mut bindable: Vec<String> = crate::pipeline::clusters::bindable_clusters(filters)
        .into_iter()
        .collect();
    bindable.sort();
    for cluster in bindable {
        if !coverage.contains(cluster.as_str()) {
            errors.push(format!(
                "cluster '{cluster}' can be bound as the logical upstream but no \
                 guaranteed load_balancer can serve it on its reachable path; \
                 requests bound to it could fail endpoint selection"
            ));
        }
    }
}

/// Whether this pipeline or one of its branches declares a bound-source
/// cluster consumer.
fn declares_bound_cluster_consumer(filters: &[PipelineFilter]) -> bool {
    filters.iter().any(|pf| {
        !pf.filter.bound_upstream_clusters().is_empty()
            || pf
                .branches
                .iter()
                .any(|branch| declares_bound_cluster_consumer(&branch.filters))
    })
}

/// Bound clusters for which a consumer is structurally guaranteed by
/// unconditional control flow or a condition composed solely of a decidable
/// `bound_upstream` predicate.
pub(super) fn guaranteed_bound_cluster_coverage(
    filters: &[PipelineFilter],
    include_router_source_load_balancers: bool,
) -> std::collections::HashSet<String> {
    let bindable = crate::pipeline::clusters::bindable_clusters(filters);
    let (catalog, _) = crate::pipeline::catalog::build_catalog(crate::pipeline::collect_cluster_declarations(filters));
    bindable
        .into_iter()
        .filter(|cluster| {
            cluster_has_guaranteed_bound_consumer(
                filters,
                cluster,
                catalog.lookup(cluster),
                include_router_source_load_balancers,
            )
        })
        .collect()
}

/// Bound-source clusters a pipeline guarantees to consume whenever it runs.
///
/// Unlike [`guaranteed_bound_cluster_coverage`], candidates come from the
/// consumers themselves rather than local routers. This lets a framework
/// owner such as the IRR fold up only its initial step's guaranteed coverage
/// without crediting optional or later steps.
#[cfg(feature = "iterative-request-router")]
pub(in crate::pipeline) fn guaranteed_bound_consumer_clusters(
    filters: &[PipelineFilter],
) -> std::collections::HashSet<String> {
    let mut candidates = std::collections::HashSet::new();
    collect_bound_consumer_clusters(filters, &mut candidates);
    let (catalog, _) = crate::pipeline::catalog::build_catalog(crate::pipeline::collect_cluster_declarations(filters));
    candidates
        .into_iter()
        .filter(|cluster| cluster_has_guaranteed_bound_consumer(filters, cluster, catalog.lookup(cluster), false))
        .collect()
}

/// Collect bound-source cluster declarations at every branch depth.
#[cfg(feature = "iterative-request-router")]
fn collect_bound_consumer_clusters(filters: &[PipelineFilter], out: &mut std::collections::HashSet<String>) {
    for pf in filters {
        out.extend(pf.filter.bound_upstream_clusters());
        for branch in &pf.branches {
            collect_bound_consumer_clusters(&branch.filters, out);
        }
    }
}

/// Whether the given cluster is guaranteed to reach a compatible consumer
/// before an unconditional terminal filter stops the path.
fn cluster_has_guaranteed_bound_consumer(
    filters: &[PipelineFilter],
    cluster: &str,
    metadata: Option<&crate::pipeline::catalog::ClusterApplicationMetadata>,
    include_router_source_load_balancers: bool,
) -> bool {
    BoundConsumerSearch {
        cluster,
        metadata,
        include_router_source_load_balancers,
    }
    .pipeline_has_consumer(filters)
}

/// Immutable inputs for exploring whether every path reaches a consumer.
struct BoundConsumerSearch<'a> {
    /// Cluster whose binding must be consumed.
    cluster: &'a str,
    /// Application metadata associated with `cluster`.
    metadata: Option<&'a crate::pipeline::catalog::ClusterApplicationMetadata>,
    /// Whether a router-source load balancer counts as a consumer.
    include_router_source_load_balancers: bool,
}

/// Mutable worklist state for one pipeline exploration.
struct BoundConsumerTraversal {
    /// Filter indexes still to explore.
    pending: Vec<usize>,
    /// Filter indexes already explored in this pipeline.
    visited: std::collections::HashSet<usize>,
    /// Outcomes observed across all explored paths.
    outcomes: std::collections::HashSet<BoundConsumerOutcome>,
}

/// Outcome of one path through a bound-consumer search.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
enum BoundConsumerOutcome {
    /// A compatible endpoint consumer ran.
    Consumed,
    /// The pipeline ended without a compatible consumer.
    Unconsumed,
    /// An incompatible or terminal filter stopped the path.
    Blocked,
}

impl BoundConsumerSearch<'_> {
    /// Explore one pipeline, including its nested branches.
    fn pipeline_has_consumer(&self, filters: &[PipelineFilter]) -> bool {
        let coverage = self.pipeline_coverage(filters);
        coverage.outcomes.len() == 1 && coverage.outcomes.contains(&BoundConsumerOutcome::Consumed)
    }

    /// Classify every path through one pipeline for a caller that will apply a
    /// branch rejoin to paths that reach the end unconsumed.
    fn pipeline_coverage(&self, filters: &[PipelineFilter]) -> BoundConsumerTraversal {
        let mut traversal = BoundConsumerTraversal {
            pending: vec![0],
            visited: std::collections::HashSet::new(),
            outcomes: std::collections::HashSet::new(),
        };
        if filters.is_empty() {
            traversal.outcomes.insert(BoundConsumerOutcome::Unconsumed);
            return traversal;
        }
        while let Some(idx) = traversal.pending.pop() {
            self.visit_filter(filters, idx, &mut traversal);
        }
        traversal
    }

    /// Explore one reachable filter and enqueue its surviving continuations.
    fn visit_filter(&self, filters: &[PipelineFilter], idx: usize, traversal: &mut BoundConsumerTraversal) {
        let Some(pf) = filters.get(idx) else {
            traversal.outcomes.insert(BoundConsumerOutcome::Unconsumed);
            return;
        };
        if !traversal.visited.insert(idx) {
            return;
        }
        if !self.filter_can_execute(pf, idx, traversal) {
            return;
        }
        if filter_itself_guarantees_bound_consumer(pf, self.cluster, self.include_router_source_load_balancers) {
            traversal.outcomes.insert(BoundConsumerOutcome::Consumed);
            return;
        }
        if filter_blocks_bound_cluster(pf, self.cluster, self.include_router_source_load_balancers) {
            traversal.outcomes.insert(BoundConsumerOutcome::Blocked);
            return;
        }
        if is_unconditional_terminal(pf) {
            traversal.outcomes.insert(BoundConsumerOutcome::Blocked);
            return;
        }
        let Some(fall_through) = self.enqueue_branches(pf, idx, traversal) else {
            traversal.outcomes.insert(BoundConsumerOutcome::Blocked);
            return;
        };
        if fall_through {
            traversal.pending.push(idx + 1);
        }
    }

    /// Enqueue a request-condition miss and report whether the filter can run.
    fn filter_can_execute(&self, pf: &PipelineFilter, idx: usize, traversal: &mut BoundConsumerTraversal) -> bool {
        match binding_condition_state(&pf.conditions, self.metadata) {
            BindingConditionState::Never => {
                traversal.pending.push(idx + 1);
                false
            },
            BindingConditionState::Maybe => {
                traversal.pending.push(idx + 1);
                true
            },
            BindingConditionState::Always => true,
        }
    }

    /// Add branch continuations and report whether the host can fall through.
    fn enqueue_branches(
        &self,
        pf: &PipelineFilter,
        idx: usize,
        traversal: &mut BoundConsumerTraversal,
    ) -> Option<bool> {
        let mut fall_through = true;
        for branch in &pf.branches {
            let branch_coverage = self.pipeline_coverage(&branch.filters);
            if branch_coverage.outcomes.contains(&BoundConsumerOutcome::Blocked) {
                return None;
            }
            if branch_coverage.outcomes.contains(&BoundConsumerOutcome::Consumed) {
                traversal.outcomes.insert(BoundConsumerOutcome::Consumed);
            }
            if branch_coverage.outcomes.contains(&BoundConsumerOutcome::Unconsumed) {
                enqueue_unconsumed_branch_rejoin(&branch.rejoin, idx, &mut traversal.pending)?;
            }
            if branch.condition.is_none() {
                fall_through = unconditional_branch_falls_through(&branch.rejoin, idx, &mut traversal.pending);
            }
        }
        Some(fall_through)
    }
}

/// Whether this filter always stops request-pipeline execution when reached.
fn is_unconditional_terminal(pf: &PipelineFilter) -> bool {
    pf.conditions.is_empty() && matches!(&pf.filter, AnyFilter::Http(filter) if filter.produces_terminal_response())
}

/// Follow a branch that did not contain a compatible bound consumer.
fn enqueue_unconsumed_branch_rejoin(rejoin: &RejoinTarget, idx: usize, pending: &mut Vec<usize>) -> Option<()> {
    match rejoin {
        RejoinTarget::Next => pending.push(idx + 1),
        RejoinTarget::SkipTo(target) | RejoinTarget::ReEnter(target) => pending.push(*target),
        RejoinTarget::Terminal => return None,
    }
    Some(())
}

/// Account for the host pipeline path when an unconditional branch is taken.
fn unconditional_branch_falls_through(rejoin: &RejoinTarget, idx: usize, pending: &mut Vec<usize>) -> bool {
    if matches!(rejoin, RejoinTarget::ReEnter(_)) {
        pending.push(idx + 1);
        true
    } else {
        false
    }
}

/// Whether the executing filter itself serves `cluster`.
fn filter_itself_guarantees_bound_consumer(
    pf: &PipelineFilter,
    cluster: &str,
    include_router_source_load_balancers: bool,
) -> bool {
    pf.filter
        .bound_upstream_clusters()
        .iter()
        .any(|declared| declared == cluster)
        || include_router_source_load_balancers
            && pf
                .filter
                .load_balancer_clusters()
                .iter()
                .any(|declared| declared == cluster)
}

/// Whether running this selector for `cluster` deterministically fails before
/// a later consumer can run.
fn filter_blocks_bound_cluster(pf: &PipelineFilter, cluster: &str, include_router_source_load_balancers: bool) -> bool {
    let declared = if pf.filter.consumes_bound_upstream() {
        pf.filter.bound_upstream_clusters()
    } else if include_router_source_load_balancers && pf.filter.name() == "load_balancer" {
        pf.filter.load_balancer_clusters()
    } else {
        return false;
    };
    !declared.iter().any(|candidate| candidate == cluster)
}

/// Whether request conditions always, never, or only sometimes match for the
/// bound cluster's application metadata.
fn binding_condition_state(
    conditions: &[Condition],
    metadata: Option<&crate::pipeline::catalog::ClusterApplicationMetadata>,
) -> BindingConditionState {
    let mut state = BindingConditionState::Always;
    for condition in conditions {
        match single_binding_condition_state(condition, metadata) {
            BindingConditionState::Never => return BindingConditionState::Never,
            BindingConditionState::Maybe => state = BindingConditionState::Maybe,
            BindingConditionState::Always => {},
        }
    }
    state
}

/// Classify one `when` or `unless` condition for a known bound cluster.
fn single_binding_condition_state(
    condition: &Condition,
    metadata: Option<&crate::pipeline::catalog::ClusterApplicationMetadata>,
) -> BindingConditionState {
    let (kind_when, matcher) = match condition {
        Condition::When(matcher) => (true, matcher),
        Condition::Unless(matcher) => (false, matcher),
    };
    let has_unknown = matcher.grpc.is_some()
        || matcher.path.is_some()
        || matcher.path_prefix.is_some()
        || matcher.methods.is_some()
        || matcher.headers.is_some()
        || matcher.selected_upstream.is_some();
    let Some(bound) = &matcher.bound_upstream else {
        return BindingConditionState::Maybe;
    };
    let matches = bound.application_protocol.as_deref().is_none_or(|expected| {
        metadata.and_then(crate::pipeline::catalog::ClusterApplicationMetadata::protocol) == Some(expected)
    }) && bound.application_provider.as_deref().is_none_or(|expected| {
        metadata.and_then(crate::pipeline::catalog::ClusterApplicationMetadata::provider) == Some(expected)
    });
    match (kind_when, matches, has_unknown) {
        (true, false, _) | (false, true, false) => BindingConditionState::Never,
        (_, true, true) => BindingConditionState::Maybe,
        (true, true, false) | (false, false, _) => BindingConditionState::Always,
    }
}

/// Static truth value of request conditions for one bound cluster.
#[derive(Clone, Copy)]
enum BindingConditionState {
    /// Every predicate is determined by the bound metadata and matches.
    Always,
    /// Bound metadata alone proves at least one predicate cannot match.
    Never,
    /// Request-dependent predicates can either match or miss.
    Maybe,
}

/// A different logical binding must not be publishable after any earlier path
/// may already have established one.
///
/// The executor freezes the first actual binding. A later binding filter—or a
/// `ReEnter` edge that reaches the same router again—could therefore publish a
/// different cluster and fail closed at runtime. A forward may-be-bound
/// analysis rejects every such path at build time, including conditional
/// publishers and back edges.
///
/// Every successful binding is frozen, even when no bound-body participant is
/// registered, so this invariant applies to every pipeline.
pub(in crate::pipeline) fn check_no_rebind_after_binding(
    filters: &[PipelineFilter],
    entry_binding_guaranteed: bool,
    errors: &mut Vec<String>,
) {
    let may_be_bound = compute_binding_may_be_bound(filters, entry_binding_guaranteed);
    for (&bound_before, pf) in may_be_bound.iter().zip(filters) {
        if bound_before
            && matches!(&pf.filter, AnyFilter::Http(filter) if filter.conflicts_with_inherited_bound_upstream())
        {
            errors.push(format!(
                "filter '{}' owns a nested pipeline that publishes a logical upstream binding, but the parent binding may already be frozen; remove the nested router or the parent binding router",
                pf.filter.name(),
            ));
        }
        if bound_before && filter_binds_upstream(pf) {
            errors.push(rebind_error(pf.filter.name()));
        }
        collect_branch_binding_publishers(&pf.branches, errors);
    }
}

/// Report binding publishers nested inside branches.
fn collect_branch_binding_publishers(branches: &[ResolvedBranch], errors: &mut Vec<String>) {
    for branch in branches {
        for pf in &branch.filters {
            if filter_binds_upstream(pf) {
                errors.push(format!(
                    "filter '{}' publishes a logical upstream binding inside a branch; the request-scoped binding router must be top-level",
                    pf.filter.name(),
                ));
            }
            collect_branch_binding_publishers(&pf.branches, errors);
        }
    }
}

/// Forward OR dataflow computing whether any path reaches each filter with a
/// logical binding already published.
fn compute_binding_may_be_bound(filters: &[PipelineFilter], entry_binding: bool) -> Vec<bool> {
    let edges = binding_control_flow_edges(filters);
    let mut may_be_bound = vec![false; filters.len()];
    loop {
        let mut incoming = vec![false; filters.len()];
        if let Some(entry) = incoming.first_mut() {
            *entry = entry_binding;
        }
        for &(from, to, _fall_through) in &edges {
            let Some(source) = filters.get(from) else { continue };
            let edge_bound = may_be_bound.get(from).copied().unwrap_or(false) || filter_binds_upstream(source);
            if let Some(target) = incoming.get_mut(to) {
                *target |= edge_bound;
            }
        }
        if incoming == may_be_bound {
            return may_be_bound;
        }
        may_be_bound = incoming;
    }
}

/// The diagnostic for a binding filter that would rebind after the barrier.
fn rebind_error(name: &str) -> String {
    format!(
        "filter '{name}' publishes a logical upstream binding, but a binding is already \
         possible before it; the first actual binding freezes and a later binding could \
         try to publish a different logical cluster (fail-closed). \
         Keep exactly one binding router before the bound-body barrier"
    )
}

/// A `bound_upstream` condition on a filter that also runs an ordinary pre-read
/// request-body hook.
///
/// An ordinary pre-read body hook ([`request_body_access`]) runs before any
/// binding exists, so pairing it with a `bound_upstream` condition on the same
/// filter is contradictory: the condition cannot be evaluated when the hook
/// runs. Body processing that needs the binding must move to the bound-upstream
/// request-body phase.
///
/// [`request_body_access`]: crate::HttpFilter::request_body_access
pub(in crate::pipeline) fn check_bound_condition_with_pre_read_body(
    filters: &[PipelineFilter],
    request_body_mode: BodyMode,
    errors: &mut Vec<String>,
) {
    if !matches!(request_body_mode, BodyMode::StreamBuffer { .. }) {
        return;
    }
    for pf in filters {
        if has_bound_upstream_condition(pf)
            && let AnyFilter::Http(f) = &pf.filter
            && f.request_body_access() != BodyAccess::None
        {
            errors.push(format!(
                "filter '{name}' combines an ordinary pre-read request-body hook with a \
                 bound_upstream condition, but a pre-read body hook runs before any binding \
                 exists; drop the condition, or move body processing to the experimental \
                 bound-upstream request-body phase (bound_upstream_request_body_access)",
                name = pf.filter.name(),
            ));
        }
    }
}

/// Bound-upstream request-body participants must buffer a bounded body, sit
/// on the top-level path, and stay out of IRR steps.
///
/// `in_irr_step` is `true` when validating an `iterative_request_router` step,
/// which inherits an already-frozen binding and must not declare the phase.
#[cfg(feature = "bound-upstream-request-body")]
pub(in crate::pipeline) fn check_bound_upstream_body_participants(
    filters: &[PipelineFilter],
    in_irr_step: bool,
    errors: &mut Vec<String>,
) {
    check_bound_upstream_body_mode(filters, errors);
    check_branch_bound_upstream_body_filters(filters, errors);
    if in_irr_step {
        check_step_bound_upstream_body_filters(filters, errors);
    }
}

/// Bound-upstream body participants must buffer the full body.
///
/// A filter that participates in the bound-upstream request-body phase runs
/// against the complete, frozen request body, which requires a bounded
/// [`BodyMode::StreamBuffer`]. Reject a participant whose [`request_body_mode`]
/// is `Stream`, `SizeLimit`, or an unbounded `StreamBuffer`, mirroring
/// [`check_selected_upstream_body_mode`]. Branch nesting is a separate concern
/// handled by [`check_branch_bound_upstream_body_filters`], so this walks only
/// top-level filters.
///
/// [`check_selected_upstream_body_mode`]: super::check_selected_upstream_body_mode
///
/// [`BodyMode::StreamBuffer`]: crate::BodyMode::StreamBuffer
/// [`request_body_mode`]: crate::HttpFilter::request_body_mode
#[cfg(feature = "bound-upstream-request-body")]
fn check_bound_upstream_body_mode(filters: &[PipelineFilter], errors: &mut Vec<String>) {
    for pf in filters {
        let AnyFilter::Http(filter) = &pf.filter else {
            continue;
        };
        if filter.bound_upstream_request_body_access() == BodyAccess::None {
            continue;
        }
        if super::filter_has_selected_upstream_condition(pf) {
            errors.push(format!(
                "filter '{}' participates in the bound-upstream request-body phase but has a selected_upstream condition; endpoint metadata does not exist at the binding barrier",
                filter.name(),
            ));
        }
        if !matches!(
            filter.request_body_mode(),
            BodyMode::StreamBuffer { max_bytes: Some(_) }
        ) {
            errors.push(format!(
                "filter '{name}' participates in the bound-upstream request body phase but \
                 its request_body_mode is not a bounded StreamBuffer; declare \
                 request_body_mode = StreamBuffer with a max_bytes limit",
                name = filter.name(),
            ));
        }
    }
}

/// Bound-upstream body-access filters inside branch chains.
///
/// The bound-upstream request-body phase, like the request-, response-, and
/// selected-upstream body phases, runs only top-level filters: branch
/// sub-chains run `on_request` only, so a filter declaring
/// [`bound_upstream_request_body_access`] inside a branch would silently enable
/// buffering for a hook that never runs. Move such a filter to the main
/// pipeline path or gate it with filter conditions.
///
/// [`bound_upstream_request_body_access`]: crate::HttpFilter::bound_upstream_request_body_access
#[cfg(feature = "bound-upstream-request-body")]
fn check_branch_bound_upstream_body_filters(filters: &[PipelineFilter], errors: &mut Vec<String>) {
    for pf in filters {
        for branch in &pf.branches {
            collect_branch_bound_upstream_body_errors(&branch.name, &branch.filters, errors);
        }
    }
}

/// IRR step pipelines inherit an already-frozen downstream binding and must not
/// declare the once-per-downstream-request bound-body phase again.
#[cfg(feature = "bound-upstream-request-body")]
fn check_step_bound_upstream_body_filters(filters: &[PipelineFilter], errors: &mut Vec<String>) {
    for pf in filters {
        if let AnyFilter::Http(filter) = &pf.filter
            && filter.bound_upstream_request_body_access() != BodyAccess::None
        {
            errors.push(format!(
                "filter '{}' declares bound-upstream request-body access inside an iterative_request_router step; move it to the parent pipeline before the IRR",
                filter.name(),
            ));
        }
        for branch in &pf.branches {
            check_step_bound_upstream_body_filters(&branch.filters, errors);
        }
    }
}

/// Recursively collect bound-upstream body-access violations inside one branch
/// sub-chain.
#[cfg(feature = "bound-upstream-request-body")]
fn collect_branch_bound_upstream_body_errors(branch_name: &str, filters: &[PipelineFilter], errors: &mut Vec<String>) {
    for pf in filters {
        if let AnyFilter::Http(filter) = &pf.filter
            && filter.bound_upstream_request_body_access() != BodyAccess::None
        {
            errors.push(format!(
                "filter '{name}' in branch '{branch_name}' declares bound-upstream request \
                 body access, but branch filters only run on_request and body hooks never \
                 execute; move it to the main pipeline or gate it with filter conditions",
                name = filter.name(),
            ));
        }
        for branch in &pf.branches {
            collect_branch_bound_upstream_body_errors(&branch.name, &branch.filters, errors);
        }
    }
}

/// Reject a `bound_upstream` matcher that no bindable cluster can satisfy.
///
/// Untagged or differently tagged clusters are valid fallthrough destinations;
/// they simply do not match. The configuration is erroneous only when the
/// matcher as a whole (including a protocol/provider pair) matches no cluster
/// the binding router can publish.
pub(in crate::pipeline) fn check_untagged_bound_cluster_fields(filters: &[PipelineFilter], errors: &mut Vec<String>) {
    let bindable = crate::pipeline::clusters::bindable_clusters(filters);
    if bindable.is_empty() {
        return;
    }
    let (catalog, _) = crate::pipeline::catalog::build_catalog(crate::pipeline::collect_cluster_declarations(filters));
    check_bound_matchers(filters, &bindable, &catalog, errors);
}

/// Recurse through pipeline conditions and flag unsatisfiable bound matchers.
fn check_bound_matchers(
    filters: &[PipelineFilter],
    bindable: &std::collections::HashSet<String>,
    catalog: &crate::pipeline::catalog::ClusterApplicationCatalog,
    errors: &mut Vec<String>,
) {
    for pf in filters {
        for condition in &pf.conditions {
            let Condition::When(matcher) = condition else {
                continue;
            };
            let Some(bound) = &matcher.bound_upstream else {
                continue;
            };
            let satisfiable = bindable.iter().any(|cluster| {
                let metadata = catalog.lookup(cluster);
                bound.application_protocol.as_deref().is_none_or(|expected| {
                    metadata.and_then(crate::pipeline::catalog::ClusterApplicationMetadata::protocol) == Some(expected)
                }) && bound.application_provider.as_deref().is_none_or(|expected| {
                    metadata.and_then(crate::pipeline::catalog::ClusterApplicationMetadata::provider) == Some(expected)
                })
            });
            if !satisfiable {
                errors.push(format!(
                    "filter '{}' has a bound_upstream condition that matches no bindable cluster's application metadata",
                    pf.filter.name(),
                ));
            }
        }
        for branch in &pf.branches {
            check_bound_matchers(&branch.filters, bindable, catalog, errors);
        }
    }
}

/// Whether any filter in `filters` (including branch sub-chains and IRR steps)
/// selects its cluster from the frozen logical binding.
pub(super) fn any_consumes_bound_upstream(filters: &[PipelineFilter]) -> bool {
    !guaranteed_bound_cluster_coverage(filters, false).is_empty()
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Whether any request condition on the filter gates on `bound_upstream`.
///
/// Only request-phase conditions are consulted: a response-phase condition
/// always runs after routing, so the binding it reads is guaranteed to exist.
fn has_bound_upstream_condition(pf: &PipelineFilter) -> bool {
    pf.conditions.iter().any(|condition| {
        let (Condition::When(m) | Condition::Unless(m)) = condition;
        m.bound_upstream.is_some()
    })
}

/// Whether the filter publishes a logical upstream binding.
fn filter_binds_upstream(pf: &PipelineFilter) -> bool {
    matches!(&pf.filter, AnyFilter::Http(f) if f.binds_upstream())
}

/// Whether the filter *unconditionally* publishes a logical upstream binding.
///
/// Only an unconditional binding filter guarantees a binding: a conditional
/// router runs only when its request conditions match, so it cannot be relied
/// on to have bound an upstream by the time a later `bound_upstream` condition
/// is evaluated.
fn unconditional_binds(pf: &PipelineFilter) -> bool {
    pf.conditions.is_empty() && filter_binds_upstream(pf)
}

/// Whether control leaving `pf` toward the next filter in its enclosing chain is
/// guaranteed to have published a logical binding.
///
/// Branch-local binding publishers are rejected by
/// [`check_no_rebind_after_binding`], so only the host filter itself can
/// establish the request-scoped guarantee.
fn filter_exit_binds(pf: &PipelineFilter) -> bool {
    unconditional_binds(pf)
}

/// Describe why a filter depends on a preceding binding, or `None` if it does
/// not. Used to name the offending feature in the reachability diagnostic.
///
/// Three features consume the logical binding and therefore require one to be
/// guaranteed before the filter runs: a `bound_upstream` request condition
/// (reads the binding), a bound-upstream request-body hook (runs only after the
/// binding freezes), and a bound-consuming load balancer (selects its cluster
/// from the binding). Any of them without a guaranteed preceding binding is a
/// fail-closed misconfiguration.
fn binding_requirement_reason(pf: &PipelineFilter) -> Option<&'static str> {
    if has_bound_upstream_condition(pf) {
        return Some("a bound_upstream condition");
    }
    let AnyFilter::Http(f) = &pf.filter else {
        return None;
    };
    if f.requires_bound_upstream_on_entry() && f.name() == "iterative_request_router" {
        Some("an iterative_request_router step that observes or consumes bound_upstream")
    } else if crate::pipeline::body::participates_in_bound_upstream_body(f.as_ref()) {
        Some("a bound-upstream request-body hook")
    } else if f.consumes_bound_upstream() {
        Some("a bound_upstream load balancer")
    } else if f.requires_bound_upstream_on_entry() {
        Some("a nested pipeline that reads the logical binding on entry")
    } else {
        None
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use std::sync::Arc;

    use praxis_core::config::ConditionMatch;

    use super::*;
    #[cfg(feature = "bound-upstream-request-body")]
    use crate::pipeline::{checks::tests::selected_upstream_cond, test_filters::bound_body_filter};
    use crate::pipeline::{
        checks::tests::{
            body_filter, bound_condition, conditional_branch, conditional_host_with_branch, host_with_branch,
            host_with_named_branch, make_branch_with_filters, make_condition, make_skip_branch, make_terminal_branch,
            named_noop_filter,
        },
        test_filters::{
            binding_router, bound_lb, lb_filter, metadata_filter, noop_filter_with_conditions, selector_filter,
        },
    };

    #[test]
    fn conflicting_cluster_metadata_errors() {
        let filters = vec![
            cluster_metadata_filter("inference", Some("openai_responses"), Some("openai")),
            cluster_metadata_filter("inference", Some("openai_responses"), Some("azure")),
        ];
        let mut errors = Vec::new();
        check_cluster_metadata_conflicts(&filters, &mut errors);
        assert_eq!(errors.len(), 1, "disagreeing declarations must error: {errors:?}");
        assert!(
            errors[0].contains("inference") && errors[0].contains("conflicting application metadata"),
            "error should name the cluster and the conflict: {}",
            errors[0]
        );
    }

    #[test]
    fn agreeing_cluster_metadata_no_error() {
        let filters = vec![
            cluster_metadata_filter("inference", Some("openai_responses"), Some("openai")),
            cluster_metadata_filter("inference", Some("openai_responses"), Some("openai")),
        ];
        let mut errors = Vec::new();
        check_cluster_metadata_conflicts(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "agreeing re-declarations are the normal multi-LB case: {errors:?}"
        );
    }

    #[test]
    fn conflicting_cluster_metadata_in_branch_errors() {
        let top = cluster_metadata_filter("inference", Some("openai_responses"), Some("openai"));
        let branch = host_with_branch(vec![cluster_metadata_filter(
            "inference",
            Some("openai_responses"),
            Some("azure"),
        )]);
        let filters = vec![top, branch];
        let mut errors = Vec::new();
        check_cluster_metadata_conflicts(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a branch declaration disagreeing with a top-level one must error: {errors:?}"
        );
    }

    #[test]
    fn bound_condition_without_binding_errors() {
        let filters = vec![noop_filter_with_conditions(
            "guardrails",
            vec![bound_condition(Some("openai_responses"), None)],
        )];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a bound_upstream condition with no preceding binding must error: {errors:?}"
        );
        assert!(
            errors[0].contains("guardrails") && errors[0].contains("bound_upstream condition"),
            "error should name the filter and the missing binding: {}",
            errors[0]
        );
    }

    #[test]
    fn bound_condition_after_router_no_error() {
        let filters = vec![
            binding_filter(),
            noop_filter_with_conditions("guardrails", vec![bound_condition(Some("openai_responses"), None)]),
        ];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        assert!(
            errors.is_empty(),
            "a binding filter before the bound condition satisfies the requirement: {errors:?}"
        );
    }

    #[test]
    fn bound_condition_in_branch_after_router_no_error() {
        let branch_host = host_with_branch(vec![noop_filter_with_conditions(
            "guardrails",
            vec![bound_condition(Some("openai_responses"), None)],
        )]);
        let filters = vec![binding_filter(), branch_host];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        assert!(
            errors.is_empty(),
            "a branch inherits the binding established before its host: {errors:?}"
        );
    }

    #[test]
    fn bound_condition_in_branch_of_binding_host_no_error() {
        let mut host = binding_filter();
        host.branches = vec![make_branch_with_filters(
            "br",
            vec![noop_filter_with_conditions(
                "guardrails",
                vec![bound_condition(Some("openai_responses"), None)],
            )],
        )];
        let filters = vec![host];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        assert!(
            errors.is_empty(),
            "the host's own binding is visible to its branches: {errors:?}"
        );
    }

    #[test]
    fn bound_condition_in_branch_without_binding_errors() {
        let branch_host = host_with_branch(vec![noop_filter_with_conditions(
            "guardrails",
            vec![bound_condition(Some("openai_responses"), None)],
        )]);
        let filters = vec![branch_host];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a bound condition in a branch with no binding anywhere must error: {errors:?}"
        );
    }

    #[test]
    fn no_bound_dependency_no_binding_no_error() {
        let filters = vec![named_noop_filter("headers", vec![])];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        assert!(
            errors.is_empty(),
            "a pipeline with no bound-upstream dependency needs no binding: {errors:?}"
        );
    }

    #[test]
    fn bound_condition_after_conditional_router_errors() {
        // A conditional router may be skipped when its request conditions do not
        // match, so it does not *guarantee* a binding for a later bound
        // condition on a path where it did not run.
        let mut conditional_router = binding_filter();
        conditional_router.conditions = vec![make_condition()];
        let filters = vec![
            conditional_router,
            noop_filter_with_conditions("guardrails", vec![bound_condition(Some("openai_responses"), None)]),
        ];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a conditional router does not guarantee a binding for a later bound condition: {errors:?}"
        );
        assert!(
            errors[0].contains("guardrails") && errors[0].contains("guaranteed"),
            "error should name the filter and call out the missing guaranteed binding: {}",
            errors[0]
        );
    }

    #[test]
    fn bound_condition_after_skip_to_bypassing_router_errors() {
        // A SkipTo branch on the first filter jumps directly to the guardrails at
        // index 2, bypassing the binding router at index 1 on that path.
        let mut gate = named_noop_filter("gate", vec![]);
        gate.branches = vec![make_skip_branch("skip", 2)];
        let filters = vec![
            gate,
            binding_filter(),
            noop_filter_with_conditions("guardrails", vec![bound_condition(Some("openai_responses"), None)]),
        ];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a SkipTo that jumps over the binding router must error: {errors:?}"
        );
        assert!(
            errors[0].contains("guardrails"),
            "error should name the reachable-without-binding filter: {}",
            errors[0]
        );
    }

    #[test]
    fn bound_condition_with_skip_to_after_binding_no_error() {
        // The binding router runs before the SkipTo host, so every path into the
        // guardrails — including the skip — has already bound an upstream.
        let mut gate = named_noop_filter("gate", vec![]);
        gate.branches = vec![make_skip_branch("skip", 3)];
        let filters = vec![
            binding_filter(),
            gate,
            named_noop_filter("headers", vec![]),
            noop_filter_with_conditions("guardrails", vec![bound_condition(Some("openai_responses"), None)]),
        ];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        assert!(
            errors.is_empty(),
            "a binding before the SkipTo host covers every path into the bound condition: {errors:?}"
        );
    }

    #[test]
    fn bound_condition_after_unconditional_branch_router_errors() {
        let branch_host = host_with_branch(vec![binding_filter()]);
        let filters = vec![
            branch_host,
            noop_filter_with_conditions("guardrails", vec![bound_condition(Some("openai_responses"), None)]),
        ];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a request binding must be published by a top-level router"
        );
    }

    #[test]
    fn bound_condition_after_nested_unconditional_branch_router_errors() {
        let inner = host_with_named_branch("inner", vec![binding_filter()]);
        let outer = host_with_named_branch("outer", vec![inner]);
        let filters = vec![
            outer,
            noop_filter_with_conditions("guardrails", vec![bound_condition(Some("openai_responses"), None)]),
        ];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "nested branch publishers cannot establish the root binding"
        );
    }

    #[test]
    fn bound_condition_after_conditional_branch_router_errors() {
        // The binding router sits in a *conditional* branch that may not fire, so
        // it does not guarantee a binding for a later top-level bound consumer.
        let mut branch_host = named_noop_filter("headers", vec![]);
        branch_host.branches = vec![conditional_branch("br", vec![binding_filter()], RejoinTarget::Next)];
        let filters = vec![
            branch_host,
            noop_filter_with_conditions("guardrails", vec![bound_condition(Some("openai_responses"), None)]),
        ];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a binding in a conditional branch does not guarantee one for a later consumer: {errors:?}"
        );
    }

    #[test]
    fn bound_condition_after_conditional_host_branch_router_errors() {
        // The branch is unconditional, but its host carries request conditions
        // and may be skipped, so the binding inside is not guaranteed.
        let host = conditional_host_with_branch(vec![make_condition()], vec![binding_filter()]);
        let filters = vec![
            host,
            noop_filter_with_conditions("guardrails", vec![bound_condition(Some("openai_responses"), None)]),
        ];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a binding under a conditional host is not guaranteed for a later consumer: {errors:?}"
        );
    }

    #[test]
    fn bound_condition_via_skip_past_unconditional_branch_router_errors() {
        // The gate's unconditional SkipTo(2) jumps straight to the guardrails,
        // bypassing the binding router in the branch host's unconditional branch.
        // The branch binding is credited only to the fall-through, never to the
        // jump target, so the skip path reaches the bound condition unbound.
        let mut gate = named_noop_filter("gate", vec![]);
        gate.branches = vec![make_skip_branch("skip", 2)];
        let branch_host = host_with_branch(vec![binding_filter()]);
        let filters = vec![
            gate,
            branch_host,
            noop_filter_with_conditions("guardrails", vec![bound_condition(Some("openai_responses"), None)]),
        ];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a SkipTo bypassing a branch binding must still error: {errors:?}"
        );
    }

    #[test]
    fn irr_with_router_and_no_bound_consumer_errors() {
        // A binding router with no reachable consumer is the old conflict.
        let filters = vec![
            named_noop_filter("iterative_request_router", vec![]),
            selector_filter("router", &["web"]),
        ];
        let names = vec!["iterative_request_router", "router"];
        let mut errors = Vec::new();
        check_irr_coexistence(&filters, &names, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "IRR + router without a bound consumer should error once"
        );
        assert!(
            errors[0].contains("router") && errors[0].contains("logical binding"),
            "error should name the missing bound consumer: {}",
            errors[0]
        );
    }

    #[test]
    fn irr_with_router_and_bound_consumer_ok() {
        // A binding router whose IRR step consumes the binding is accepted
        // (rule 11). The bound consumer lives in a branch here, standing in for
        // an IRR step pipeline that folds its consumption up.
        let mut irr = named_noop_filter("iterative_request_router", vec![]);
        irr.branches = vec![make_branch_with_filters("inference", vec![bound_lb(&["inference"])])];
        let filters = vec![binding_router(&["inference"]), irr];
        let names = vec!["router", "iterative_request_router"];
        let mut errors = Vec::new();
        check_irr_coexistence(&filters, &names, &mut errors);
        assert!(
            errors.is_empty(),
            "router + IRR with a reachable bound consumer is allowed: {errors:?}"
        );
    }

    #[test]
    fn irr_with_load_balancer_errors() {
        let filters = vec![
            named_noop_filter("iterative_request_router", vec![]),
            lb_filter(&["web"]),
        ];
        let names = vec!["iterative_request_router", "load_balancer"];
        let mut errors = Vec::new();
        check_irr_coexistence(&filters, &names, &mut errors);
        assert_eq!(errors.len(), 1, "IRR + top-level LB should produce one error");
        assert!(
            errors[0].contains("load_balancer"),
            "error should mention load_balancer: {}",
            errors[0]
        );
    }

    #[test]
    fn irr_with_both_router_and_lb_errors_twice() {
        // A top-level LB (rule 10) plus a binding router with no bound consumer
        // (rule 11) each fire.
        let filters = vec![
            named_noop_filter("iterative_request_router", vec![]),
            selector_filter("router", &["web"]),
            lb_filter(&["web"]),
        ];
        let names = vec!["iterative_request_router", "router", "load_balancer"];
        let mut errors = Vec::new();
        check_irr_coexistence(&filters, &names, &mut errors);
        assert_eq!(
            errors.len(),
            2,
            "IRR + top-level LB + unconsumed router should error twice"
        );
    }

    #[test]
    fn irr_alone_no_error() {
        let filters = vec![named_noop_filter("iterative_request_router", vec![])];
        let names = vec!["iterative_request_router"];
        let mut errors = Vec::new();
        check_irr_coexistence(&filters, &names, &mut errors);
        assert!(errors.is_empty(), "IRR alone should not error");
    }

    #[test]
    fn no_irr_router_and_lb_no_error() {
        let filters = vec![selector_filter("router", &["web"]), lb_filter(&["web"])];
        let names = vec!["router", "load_balancer"];
        let mut errors = Vec::new();
        check_irr_coexistence(&filters, &names, &mut errors);
        assert!(errors.is_empty(), "no IRR means no conflict");
    }

    #[test]
    fn bound_condition_with_pre_read_body_errors() {
        let mut pf = body_filter(); // declares request_body_access = ReadOnly
        pf.conditions = vec![bound_condition(Some("openai_responses"), None)];
        let filters = vec![pf];
        let mut errors = Vec::new();
        check_bound_condition_with_pre_read_body(
            &filters,
            BodyMode::StreamBuffer { max_bytes: Some(1024) },
            &mut errors,
        );
        assert_eq!(
            errors.len(),
            1,
            "a pre-read body hook paired with a bound_upstream condition must error: {errors:?}"
        );
        assert!(
            errors[0].contains("branch_body") && errors[0].contains("pre-read request-body hook"),
            "error should name the filter and the contradiction: {}",
            errors[0]
        );
    }

    #[test]
    fn bound_condition_without_pre_read_body_no_error() {
        let filters = vec![noop_filter_with_conditions(
            "guardrails",
            vec![bound_condition(Some("openai_responses"), None)],
        )];
        let mut errors = Vec::new();
        check_bound_condition_with_pre_read_body(
            &filters,
            BodyMode::StreamBuffer { max_bytes: Some(1024) },
            &mut errors,
        );
        assert!(
            errors.is_empty(),
            "a bound condition with no pre-read body hook is fine: {errors:?}"
        );
    }

    #[test]
    fn pre_read_body_without_bound_condition_no_error() {
        let filters = vec![body_filter()];
        let mut errors = Vec::new();
        check_bound_condition_with_pre_read_body(
            &filters,
            BodyMode::StreamBuffer { max_bytes: Some(1024) },
            &mut errors,
        );
        assert!(
            errors.is_empty(),
            "an ordinary pre-read body hook without a bound condition is fine: {errors:?}"
        );
    }

    #[test]
    fn bound_condition_with_pre_read_body_in_branch_is_left_to_branch_body_check() {
        let mut inner = body_filter();
        inner.conditions = vec![bound_condition(Some("openai_responses"), None)];
        let mut host = named_noop_filter("headers", vec![]);
        host.branches = vec![make_branch_with_filters("br", vec![inner])];
        let filters = vec![host];
        let mut errors = Vec::new();
        check_bound_condition_with_pre_read_body(
            &filters,
            BodyMode::StreamBuffer { max_bytes: Some(1024) },
            &mut errors,
        );
        assert!(errors.is_empty(), "branch body hooks are diagnosed by the branch check");
    }

    #[test]
    fn bound_condition_with_body_hook_is_allowed_without_pre_read() {
        let mut pf = body_filter();
        pf.conditions = vec![bound_condition(Some("openai_responses"), None)];
        for mode in [BodyMode::Stream, BodyMode::SizeLimit { max_bytes: 1024 }] {
            let mut errors = Vec::new();
            check_bound_condition_with_pre_read_body(std::slice::from_ref(&pf), mode, &mut errors);
            assert!(
                errors.is_empty(),
                "post-request body mode can observe the binding: {errors:?}"
            );
        }
    }

    #[cfg(feature = "bound-upstream-request-body")]
    #[test]
    fn bound_upstream_body_mode_rejects_stream() {
        let filters = vec![bound_body_filter("bound_body", BodyAccess::ReadOnly, BodyMode::Stream)];
        let mut errors = Vec::new();
        check_bound_upstream_body_mode(&filters, &mut errors);
        assert_eq!(errors.len(), 1, "Stream mode must be rejected for a bound participant");
        assert!(
            errors[0].contains("bound_body") && errors[0].contains("bounded StreamBuffer"),
            "error should name the filter and require a bounded buffer: {}",
            errors[0]
        );
    }

    #[cfg(feature = "bound-upstream-request-body")]
    #[test]
    fn bound_upstream_body_mode_rejects_unbounded_stream_buffer() {
        let filters = vec![bound_body_filter(
            "bound_body",
            BodyAccess::ReadOnly,
            BodyMode::StreamBuffer { max_bytes: None },
        )];
        let mut errors = Vec::new();
        check_bound_upstream_body_mode(&filters, &mut errors);
        assert_eq!(errors.len(), 1, "an unbounded StreamBuffer must be rejected");
    }

    #[cfg(feature = "bound-upstream-request-body")]
    #[test]
    fn bound_upstream_body_mode_accepts_bounded_stream_buffer() {
        let filters = vec![bound_body_filter(
            "bound_body",
            BodyAccess::ReadWrite,
            BodyMode::StreamBuffer { max_bytes: Some(4096) },
        )];
        let mut errors = Vec::new();
        check_bound_upstream_body_mode(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "bounded StreamBuffer is the required mode: {errors:?}"
        );
    }

    #[cfg(feature = "bound-upstream-request-body")]
    #[test]
    fn bound_upstream_body_mode_rejects_selected_upstream_condition() {
        let mut filter = bound_body_filter(
            "bound_body",
            BodyAccess::ReadOnly,
            BodyMode::StreamBuffer { max_bytes: Some(4096) },
        );
        filter.conditions = vec![selected_upstream_cond(None, Some("openai"))];
        let mut errors = Vec::new();

        check_bound_upstream_body_mode(&[filter], &mut errors);

        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("endpoint metadata does not exist"));
    }

    #[cfg(feature = "bound-upstream-request-body")]
    #[test]
    fn bound_upstream_body_mode_ignores_non_participants() {
        let filters = vec![body_filter()];
        let mut errors = Vec::new();
        check_bound_upstream_body_mode(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "a filter with no bound-upstream body access must not be checked: {errors:?}"
        );
    }

    #[cfg(feature = "bound-upstream-request-body")]
    #[test]
    fn branch_bound_upstream_body_filter_errors() {
        let mut host = named_noop_filter("headers", vec![]);
        host.branches = vec![make_branch_with_filters(
            "bound_branch",
            vec![bound_body_filter(
                "bound_body",
                BodyAccess::ReadWrite,
                BodyMode::StreamBuffer { max_bytes: Some(4096) },
            )],
        )];
        let filters = vec![host];
        let mut errors = Vec::new();
        check_branch_bound_upstream_body_filters(&filters, &mut errors);
        assert_eq!(errors.len(), 1, "bound-upstream body filter in a branch must error");
        assert!(
            errors[0].contains("bound_branch") && errors[0].contains("bound_body"),
            "error should name the branch and the filter: {}",
            errors[0]
        );
    }

    #[cfg(feature = "bound-upstream-request-body")]
    #[test]
    fn nested_branch_bound_upstream_body_filter_errors() {
        let mut inner = named_noop_filter("classifier", vec![]);
        inner.branches = vec![make_branch_with_filters(
            "inner",
            vec![bound_body_filter(
                "bound_body",
                BodyAccess::ReadOnly,
                BodyMode::StreamBuffer { max_bytes: Some(4096) },
            )],
        )];
        let mut host = named_noop_filter("headers", vec![]);
        host.branches = vec![make_branch_with_filters("outer", vec![inner])];
        let filters = vec![host];
        let mut errors = Vec::new();
        check_branch_bound_upstream_body_filters(&filters, &mut errors);
        assert_eq!(errors.len(), 1, "the check must recurse into nested branches");
        assert!(
            errors[0].contains("inner"),
            "error should name the innermost branch: {}",
            errors[0]
        );
    }

    #[cfg(feature = "bound-upstream-request-body")]
    #[test]
    fn top_level_bound_upstream_body_filter_no_branch_error() {
        let filters = vec![bound_body_filter(
            "bound_body",
            BodyAccess::ReadWrite,
            BodyMode::StreamBuffer { max_bytes: Some(4096) },
        )];
        let mut errors = Vec::new();
        check_branch_bound_upstream_body_filters(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "a top-level bound-upstream body filter is legitimate: {errors:?}"
        );
    }

    #[test]
    fn bound_lb_without_binding_errors() {
        let filters = vec![bound_lb(&["inference"])];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        assert_eq!(errors.len(), 1, "a bound LB with no preceding binding must error");
        assert!(
            errors[0].contains("load_balancer") && errors[0].contains("bound_upstream load balancer"),
            "error should name the bound LB dependency: {}",
            errors[0]
        );
    }

    #[test]
    fn bound_lb_after_binding_no_error() {
        let filters = vec![binding_router(&["inference"]), bound_lb(&["inference"])];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        assert!(
            errors.is_empty(),
            "an unconditional binding router before the bound LB satisfies the requirement: {errors:?}"
        );
    }

    #[test]
    fn bound_lb_in_step_with_entry_binding_no_error() {
        // An IRR step runs as a continuation of a parent that already guarantees
        // a binding before the IRR (the parent's own reachability check enforces
        // this). With that entry binding assumed present, a step's bound LB needs
        // no step-local binding router.
        let filters = vec![bound_lb(&["inference"])];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, true, &mut errors);
        assert!(
            errors.is_empty(),
            "a step's bound LB inherits the parent's guaranteed binding: {errors:?}"
        );
    }

    #[cfg(feature = "bound-upstream-request-body")]
    #[test]
    fn bound_body_hook_without_binding_errors() {
        let filters = vec![bound_body_filter(
            "bound_body",
            BodyAccess::ReadWrite,
            BodyMode::StreamBuffer { max_bytes: Some(4096) },
        )];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        assert_eq!(errors.len(), 1, "a bound-upstream body hook with no binding must error");
        assert!(
            errors[0].contains("bound-upstream request-body hook"),
            "error should name the bound-body dependency: {}",
            errors[0]
        );
    }

    #[test]
    fn bound_coverage_without_consumer_no_error() {
        let filters = vec![binding_router(&["inference"])];
        let mut errors = Vec::new();
        check_bound_cluster_coverage(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "no bound consumer means the coverage check does not run: {errors:?}"
        );
    }

    #[test]
    fn incompatible_unconditional_bound_consumer_blocks_later_consumer() {
        let mut host_a = named_noop_filter("headers", vec![]);
        host_a.branches = vec![make_branch_with_filters("a", vec![bound_lb(&["openai-responses"])])];
        let mut host_b = named_noop_filter("headers", vec![]);
        host_b.branches = vec![make_branch_with_filters("b", vec![bound_lb(&["chat-backend"])])];
        let filters = vec![binding_router(&["openai-responses", "chat-backend"]), host_a, host_b];
        let mut errors = Vec::new();
        check_bound_cluster_coverage(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "the first unconditional bound LB rejects chat-backend before its later consumer: {errors:?}"
        );
        assert!(errors[0].contains("chat-backend"));
    }

    #[test]
    fn bound_direct_branch_and_ordinary_fallthrough_cover_distinct_clusters() {
        let mut direct = named_noop_filter("headers", vec![bound_condition(None, Some("openai"))]);
        let mut direct_branch = make_branch_with_filters("direct", vec![bound_lb(&["openai-backend"])]);
        direct_branch.rejoin = RejoinTarget::Terminal;
        direct.branches = vec![direct_branch];
        let filters = vec![
            binding_router(&["openai-backend", "chat-backend"]),
            metadata_filter("catalog", "openai-backend", None, Some("openai")),
            metadata_filter("catalog", "chat-backend", None, Some("vllm")),
            direct,
            lb_filter(&["chat-backend"]),
        ];
        let mut errors = Vec::new();

        check_bound_cluster_coverage(&filters, &mut errors);

        assert!(
            errors.is_empty(),
            "ordinary fallthrough transport completes coverage: {errors:?}"
        );
    }

    #[test]
    fn bound_coverage_missing_cluster_errors() {
        let filters = vec![
            binding_router(&["openai-responses", "chat-backend"]),
            bound_lb(&["openai-responses"]),
        ];
        let mut errors = Vec::new();
        check_bound_cluster_coverage(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a bindable cluster no bound LB resolves must error: {errors:?}"
        );
        assert!(
            errors[0].contains("chat-backend"),
            "error should name the uncovered cluster: {}",
            errors[0]
        );
    }

    #[test]
    fn conditional_branch_consumer_does_not_guarantee_coverage() {
        let mut branch = make_branch_with_filters("optional", vec![bound_lb(&["inference"])]);
        branch.condition = Some(crate::pipeline::branch::ResolvedBranchCondition {
            filter_name: Arc::from("classifier"),
            key: Arc::from("route"),
            value: Arc::from("direct"),
        });
        let mut host = named_noop_filter("classifier", vec![]);
        host.branches = vec![branch];
        let filters = vec![binding_router(&["inference"]), host];
        let mut errors = Vec::new();

        check_bound_cluster_coverage(&filters, &mut errors);

        assert_eq!(
            errors.len(),
            1,
            "a skipped branch would leave the binding without transport"
        );
    }

    #[test]
    fn skip_to_bypassing_bound_consumer_does_not_count_as_coverage() {
        let mut host = named_noop_filter("host", vec![]);
        host.branches = vec![make_skip_branch("bypass", 3)];
        let filters = vec![
            binding_router(&["inference"]),
            host,
            bound_lb(&["inference"]),
            named_noop_filter("after", vec![]),
        ];
        let mut errors = Vec::new();

        check_bound_cluster_coverage(&filters, &mut errors);

        assert_eq!(errors.len(), 1, "the bypassed consumer cannot cover the skip path");
    }

    #[test]
    fn terminal_branch_before_bound_consumer_does_not_count_as_coverage() {
        let mut host = named_noop_filter("host", vec![]);
        host.branches = vec![make_terminal_branch("stop", vec![])];
        let filters = vec![binding_router(&["inference"]), host, bound_lb(&["inference"])];
        let mut errors = Vec::new();

        check_bound_cluster_coverage(&filters, &mut errors);

        assert_eq!(errors.len(), 1, "a consumer after a terminal rejoin is unreachable");
    }

    #[test]
    fn conditional_host_terminal_path_does_not_count_later_consumer() {
        let mut host = named_noop_filter("host", vec![make_condition()]);
        host.branches = vec![make_terminal_branch("stop", vec![])];
        let filters = vec![binding_router(&["inference"]), host, bound_lb(&["inference"])];
        let mut errors = Vec::new();

        check_bound_cluster_coverage(&filters, &mut errors);

        assert_eq!(
            errors.len(),
            1,
            "both outcomes of request-dependent host conditions must be explored"
        );
    }

    #[test]
    fn single_binding_no_rebind_error() {
        // A binding followed by a consumer is the valid shape: exactly one
        // binding before the barrier.
        let filters = vec![binding_router(&["inference"]), bound_lb(&["inference"])];
        let mut errors = Vec::new();
        check_no_rebind_after_binding(&filters, false, &mut errors);
        assert!(
            errors.is_empty(),
            "the establishing binding runs with nothing bound on entry: {errors:?}"
        );
    }

    #[test]
    fn rebind_without_body_participant_errors() {
        let filters = vec![binding_router(&["a"]), binding_router(&["b"])];
        let mut errors = Vec::new();
        check_no_rebind_after_binding(&filters, false, &mut errors);
        assert_eq!(errors.len(), 1, "the first binding freezes even without a body hook");
    }

    #[test]
    fn second_top_level_binding_rebind_errors() {
        let filters = vec![binding_router(&["a"]), binding_router(&["b"]), bound_lb(&["a"])];
        let mut errors = Vec::new();
        check_no_rebind_after_binding(&filters, false, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a second binding after the barrier must error: {errors:?}"
        );
        assert!(
            errors[0].contains("already") && errors[0].contains("binding"),
            "error should explain the frozen binding: {}",
            errors[0]
        );
    }

    #[test]
    fn same_cluster_republication_is_rejected_at_validation() {
        let filters = vec![
            binding_router(&["same"]),
            binding_router(&["same"]),
            bound_lb(&["same"]),
        ];
        let mut errors = Vec::new();

        check_no_rebind_after_binding(&filters, false, &mut errors);

        assert_eq!(
            errors.len(),
            1,
            "validation keeps one publisher even though same-cluster runtime replay is idempotent"
        );
    }

    #[test]
    fn conditional_binding_before_second_router_rebind_errors() {
        let mut first = binding_router(&["a"]);
        first.conditions = vec![make_condition()];
        let filters = vec![first, binding_router(&["b"]), bound_lb(&["a", "b"])];
        let mut errors = Vec::new();

        check_no_rebind_after_binding(&filters, false, &mut errors);

        assert_eq!(
            errors.len(),
            1,
            "the second router can run after the conditional router has bound: {errors:?}"
        );
    }

    #[test]
    fn reenter_over_binding_router_rebind_errors() {
        let mut router = binding_router(&["a"]);
        router.branches = vec![ResolvedBranch {
            condition: Some(crate::pipeline::branch::ResolvedBranchCondition {
                filter_name: Arc::from("router"),
                key: Arc::from("retry"),
                value: Arc::from("yes"),
            }),
            filters: vec![],
            max_iterations: Some(1),
            name: Arc::from("reroute"),
            rejoin: RejoinTarget::ReEnter(0),
        }];
        let filters = vec![router, bound_lb(&["a"])];
        let mut errors = Vec::new();

        check_no_rebind_after_binding(&filters, false, &mut errors);

        assert_eq!(
            errors.len(),
            1,
            "the back edge can execute the binding router with a frozen binding: {errors:?}"
        );
    }

    #[test]
    fn entry_binding_rejects_step_router_even_with_bound_consumer() {
        let filters = vec![binding_router(&["a"]), bound_lb(&["a"])];
        let mut errors = Vec::new();

        check_no_rebind_after_binding(&filters, true, &mut errors);

        assert_eq!(
            errors.len(),
            1,
            "an IRR step must inherit the request binding instead of publishing another: {errors:?}"
        );
    }

    #[test]
    fn rebind_in_branch_after_binding_errors() {
        let mut host = named_noop_filter("headers", vec![]);
        host.branches = vec![make_branch_with_filters("br", vec![binding_router(&["b"])])];
        let filters = vec![binding_router(&["a"]), host, bound_lb(&["a"])];
        let mut errors = Vec::new();
        check_no_rebind_after_binding(&filters, false, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a binding filter in a branch reached after the barrier must error: {errors:?}"
        );
    }

    #[test]
    fn binding_control_flow_next_adds_only_sequential_edge() {
        let filters = vec![named_noop_filter("a", vec![]), named_noop_filter("b", vec![])];

        assert_eq!(binding_control_flow_edges(&filters), vec![(0, 1, true)]);
    }

    #[test]
    fn binding_control_flow_unconditional_skip_replaces_fallthrough() {
        let mut host = named_noop_filter("host", vec![]);
        host.branches = vec![make_skip_branch("skip", 2)];
        let filters = vec![
            host,
            named_noop_filter("skipped", vec![]),
            named_noop_filter("target", vec![]),
        ];

        assert_eq!(binding_control_flow_edges(&filters), vec![(0, 2, false), (1, 2, true)]);
    }

    #[test]
    fn binding_control_flow_conditional_skip_keeps_fallthrough() {
        let mut host = named_noop_filter("host", vec![]);
        host.branches = vec![conditional_branch("skip", vec![], RejoinTarget::SkipTo(2))];
        let filters = vec![
            host,
            named_noop_filter("fallthrough", vec![]),
            named_noop_filter("target", vec![]),
        ];

        assert_eq!(
            binding_control_flow_edges(&filters),
            vec![(0, 1, true), (0, 2, false), (1, 2, true)]
        );
    }

    #[test]
    fn binding_control_flow_skip_on_conditional_host_keeps_fallthrough() {
        let mut host = named_noop_filter("host", vec![make_condition()]);
        host.branches = vec![make_skip_branch("skip", 2)];
        let filters = vec![
            host,
            named_noop_filter("fallthrough", vec![]),
            named_noop_filter("target", vec![]),
        ];

        assert_eq!(
            binding_control_flow_edges(&filters),
            vec![(0, 1, true), (0, 2, false), (1, 2, true)]
        );
    }

    #[test]
    fn binding_control_flow_terminal_host_has_no_exit() {
        let filters = vec![
            crate::pipeline::test_filters::terminal_filter("terminal"),
            named_noop_filter("unreachable", vec![]),
        ];

        assert!(binding_control_flow_edges(&filters).is_empty());
    }

    #[test]
    fn binding_control_flow_drops_out_of_range_jump() {
        let mut host = named_noop_filter("host", vec![]);
        host.branches = vec![make_skip_branch("invalid", 99)];
        let filters = vec![host, named_noop_filter("later", vec![])];

        assert!(binding_control_flow_edges(&filters).is_empty());
    }

    #[test]
    fn untagged_bound_cluster_when_condition_errors() {
        let filters = vec![
            binding_router(&["openai"]),
            noop_filter_with_conditions("guardrails", vec![bound_condition(None, Some("openai"))]),
        ];
        let mut errors = Vec::new();
        check_untagged_bound_cluster_fields(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "an untagged bindable cluster under a when-provider gate must error: {errors:?}"
        );
        assert!(errors[0].contains("matches no bindable cluster"));
    }

    #[test]
    fn tagged_bound_cluster_when_condition_no_error() {
        let filters = vec![
            binding_router(&["openai"]),
            metadata_filter("load_balancer", "openai", None, Some("openai")),
            noop_filter_with_conditions("guardrails", vec![bound_condition(None, Some("openai"))]),
        ];
        let mut errors = Vec::new();
        check_untagged_bound_cluster_fields(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "a cluster tagged with the demanded field must not error: {errors:?}"
        );
    }

    #[test]
    fn untagged_bound_cluster_unless_condition_no_error() {
        // `unless bound_upstream` on a missing field runs rather than silently
        // skips, so it is not a dead gate and rule 12 excludes it.
        let unless = Condition::Unless(ConditionMatch {
            grpc: None,
            path: None,
            path_prefix: None,
            methods: None,
            headers: None,
            bound_upstream: Some(praxis_core::config::ApplicationMatch {
                application_protocol: None,
                application_provider: Some("openai".to_owned()),
            }),
            selected_upstream: None,
        });
        let filters = vec![
            binding_router(&["openai"]),
            noop_filter_with_conditions("guardrails", vec![unless]),
        ];
        let mut errors = Vec::new();
        check_untagged_bound_cluster_fields(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "an unless condition on a missing field is not a dead gate: {errors:?}"
        );
    }

    #[test]
    fn no_bound_condition_no_untagged_error() {
        let filters = vec![binding_router(&["openai"])];
        let mut errors = Vec::new();
        check_untagged_bound_cluster_fields(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "with no bound_upstream condition, no field is demanded: {errors:?}"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build a [`PipelineFilter`] that publishes a logical upstream binding,
    /// standing in for a `router` in reachability tests.
    fn binding_filter() -> PipelineFilter {
        /// Minimal filter that reports it binds the logical upstream.
        struct BindingFilter;

        #[async_trait::async_trait]
        impl crate::filter::HttpFilter for BindingFilter {
            fn name(&self) -> &'static str {
                "router"
            }

            async fn on_request(
                &self,
                _ctx: &mut crate::HttpFilterContext<'_>,
            ) -> Result<crate::FilterAction, crate::FilterError> {
                Ok(crate::FilterAction::Continue)
            }

            fn selects_cluster(&self) -> bool {
                true
            }

            fn binds_upstream(&self) -> bool {
                true
            }
        }

        PipelineFilter::new(0, AnyFilter::Http(Box::new(BindingFilter)), vec![], vec![])
    }

    /// Build a [`PipelineFilter`] that declares application metadata for one
    /// cluster, standing in for a `load_balancer` in catalog tests.
    fn cluster_metadata_filter(cluster: &str, protocol: Option<&str>, provider: Option<&str>) -> PipelineFilter {
        use crate::pipeline::catalog::{ClusterApplicationMetadata, ClusterMetadataDeclaration};

        /// Minimal filter declaring one cluster's application metadata.
        struct MetadataFilter {
            decl: ClusterMetadataDeclaration,
        }

        #[async_trait::async_trait]
        impl crate::filter::HttpFilter for MetadataFilter {
            fn name(&self) -> &'static str {
                "load_balancer"
            }

            async fn on_request(
                &self,
                _ctx: &mut crate::HttpFilterContext<'_>,
            ) -> Result<crate::FilterAction, crate::FilterError> {
                Ok(crate::FilterAction::Continue)
            }

            fn declared_cluster_metadata(&self) -> Vec<ClusterMetadataDeclaration> {
                vec![self.decl.clone()]
            }
        }

        let decl = ClusterMetadataDeclaration {
            name: Arc::from(cluster),
            metadata: ClusterApplicationMetadata::new(protocol.map(Arc::from), provider.map(Arc::from)),
        };
        PipelineFilter::new(0, AnyFilter::Http(Box::new(MetadataFilter { decl })), vec![], vec![])
    }
}
