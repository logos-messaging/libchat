//! Storage module for persisting chat state.

mod db;
mod migrations;
pub(crate) mod types;

pub(crate) use db::ChatStorage;
