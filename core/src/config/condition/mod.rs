//! Condition predicates that gate filter execution.

mod request;
mod response;

pub use request::{Condition, ConditionMatch};
pub use response::{ResponseCondition, ResponseConditionMatch};
