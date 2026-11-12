use crate::{
    ctx::Ctx,
    sys::{self, Data, Hive},
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Conf {
    reg: Vec<Reg>,
    #[serde(default)]
    cmd: Vec<Cmd>,
    #[serde(default)]
    ask: Vec<Ask>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ask {
    question: String,
    // true = don't ask
    check: Option<String>,
    yes: Option<String>,
    no: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reg {
    desc: String,
    hive: Hive,
    key: String,
    name: String,
    data: Data,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cmd {
    desc: String,
    run: String,
    // true = already done
    check: Option<String>,
}

#[derive(Default)]
struct Tally {
    fixed: u32,
    ok: u32,
    failed: u32,
}

impl Tally {
    fn add(&mut self, ctx: &Ctx, desc: &str, res: anyhow::Result<bool>) {
        match res {
            Ok(true) => self.fixed += 1,
            Ok(false) => {
                self.ok += 1;
                ctx.debug(format!("ok: {desc}"));
            }
            Err(e) => {
                self.failed += 1;
                ctx.info(format!("FAILED {desc}: {e}"));
            }
        }
    }
}

pub fn run(ctx: &Ctx) -> anyhow::Result<()> {
    let conf: Conf = ctx.load("menial.toml")?;
    let mut t = Tally::default();
    for r in &conf.reg {
        let res = sys::reg_get(r.hive, &r.key, &r.name).and_then(|cur| {
            if cur.as_ref() == Some(&r.data) {
                return Ok(false);
            }
            let cur = cur.map_or("(unset)".into(), |c| c.to_string());
            ctx.info(format!("{}: {cur} -> {}", r.desc, r.data));
            sys::reg_set(ctx, r.hive, &r.key, &r.name, &r.data).map(|_| true)
        });
        t.add(ctx, &r.desc, res);
    }
    for c in &conf.cmd {
        let res = c.check.as_deref().map_or(Ok(false), sys::check).and_then(|done| {
            if done {
                return Ok(false);
            }
            ctx.info(&c.desc);
            sys::run(ctx, &c.run).map(|_| true)
        });
        t.add(ctx, &c.desc, res);
    }
    for a in &conf.ask {
        let res = a.check.as_deref().map_or(Ok(false), sys::check).and_then(|skip| {
            let cmd = if skip { None } else { ctx.ask(&a.question).and_then(|y| if y { a.yes.as_ref() } else { a.no.as_ref() }) };
            cmd.map_or(Ok(false), |c| sys::run(ctx, c).map(|_| true))
        });
        t.add(ctx, &a.question, res);
    }
    ctx.info(format!("menial: {} to fix, {} already ok, {} failed", t.fixed, t.ok, t.failed));
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/unit/menial.rs"]
mod tests;
