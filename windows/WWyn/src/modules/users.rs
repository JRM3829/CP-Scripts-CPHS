//! local accounts + Administrators group = whatever the README says
use crate::{ctx::Ctx, readme, sys};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Conf {
    password: String,
}

// by SID in case the group got renamed
const ADMIN_GROUP: &str = "$g = [ADSI](\"WinNT://$env:COMPUTERNAME/\" + (Get-LocalGroup -SID 'S-1-5-32-544').Name + ',group')";

pub fn run(ctx: &Ctx) -> anyhow::Result<()> {
    let conf: Conf = ctx.load("users.toml")?;
    let auth = readme::load(ctx)?;
    // bad parse = empty list = delete everyone
    let Some(me) = auth.me.clone() else { anyhow::bail!("README has no \"(you)\" account; not touching users") };
    anyhow::ensure!(!auth.admins.is_empty(), "README has no authorized administrators; not touching users");
    ctx.info(format!("you: {me}"));
    ctx.info(format!("admins ({}): {}", auth.admins.len(), auth.admins.join(", ")));
    ctx.info(format!("users ({}): {}", auth.users.len(), auth.users.join(", ")));

    let has = |list: &[String], n: &str| list.iter().any(|x| x.eq_ignore_ascii_case(n));
    let authorized = |n: &str| has(&auth.admins, n) || has(&auth.users, n);
    let current = std::env::var("USERNAME").unwrap_or_default();
    let protected = |n: &str| n.eq_ignore_ascii_case(&me) || n.eq_ignore_ascii_case(&current);

    // (name, rid). rid < 1000 is built-in, menial handles those
    let local: Vec<(String, u32)> = sys::query("Get-LocalUser | ForEach-Object { '{0}|{1}' -f $_.Name, $_.SID.Value }")?
        .lines()
        .filter_map(|l| {
            let (name, sid) = l.trim().split_once('|')?;
            Some((name.to_string(), sid.rsplit('-').next()?.parse().ok()?))
        })
        .collect();
    // ADSI, not Get-LocalGroupMember: that one throws on orphaned SIDs
    let in_admins: Vec<String> = sys::query(&format!(
        "{ADMIN_GROUP}\n$g.Invoke('Members') | ForEach-Object {{ $_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null) }}"
    ))?
    .lines()
    .map(str::trim)
    .filter(|l| !l.is_empty())
    .map(String::from)
    .collect();
    let exists = |n: &str| local.iter().any(|(l, _)| l.eq_ignore_ascii_case(n));
    let plain = conf.password.replace('\'', "''");
    let pw = format!("(ConvertTo-SecureString '{plain}' -AsPlainText -Force)");

    let mut failed = 0;
    let mut act = |desc: String, cmd: String| {
        ctx.info(&desc);
        if let Err(e) = sys::run(ctx, &cmd) {
            failed += 1;
            ctx.info(format!("FAILED {desc}: {e}"));
        }
    };

    for (n, rid) in &local {
        if *rid >= 1000 && !authorized(n) && !protected(n) {
            act(format!("remove unauthorized user {n}"), format!("Remove-LocalUser -Name '{n}'"));
        }
    }
    for n in auth.admins.iter().chain(&auth.users) {
        if !exists(n) {
            act(format!("create missing user {n}"), format!("New-LocalUser -Name '{n}' -Password {pw}"));
        }
    }
    for (n, rid) in &local {
        if *rid >= 1000 && authorized(n) && has(&in_admins, n) && !has(&auth.admins, n) && !protected(n) {
            act(format!("remove {n} from Administrators"), format!("{ADMIN_GROUP}\n$g.Remove(\"WinNT://$env:COMPUTERNAME/{n},user\")"));
        }
    }
    for n in &auth.admins {
        if !has(&in_admins, n) {
            act(format!("add {n} to Administrators"), format!("{ADMIN_GROUP}\n$g.Add(\"WinNT://$env:COMPUTERNAME/{n},user\")"));
        }
    }
    for n in auth.admins.iter().chain(&auth.users) {
        if !protected(n) {
            act(
                format!("set password for {n}"),
                // net user, not Set-LocalUser -Password: that throws InvalidPasswordException on some image accounts where net user works
                format!("net user '{n}' '{plain}' | Out-Null\nSet-LocalUser -Name '{n}' -PasswordNeverExpires $false\nnet user '{n}' /passwordreq:yes | Out-Null"),
            );
        }
    }
    ctx.info(format!("users: {failed} failed"));
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn shipped_conf_parses() {
        let s = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/conf/users.toml")).unwrap();
        let c: super::Conf = toml::from_str(&s).unwrap();
        assert!(c.password.len() >= 10);
    }
}
