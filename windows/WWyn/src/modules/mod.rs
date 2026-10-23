//! new module: add the file + one line in ALL
use crate::ctx::Ctx;

mod menial;
mod updates;
mod users;

pub type Run = fn(&Ctx) -> anyhow::Result<()>;

pub const ALL: &[(&str, Run)] = &[("menial", menial::run), ("users", users::run), ("updates", updates::run)];
