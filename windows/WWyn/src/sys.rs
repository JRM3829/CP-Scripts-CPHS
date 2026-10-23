//! only place that touches the system. every mutation checks dry_run here so modules can't skip it
use crate::ctx::Ctx;
use serde::Deserialize;
use std::io;

#[derive(Deserialize, Clone, Copy, Debug)]
pub enum Hive {
    HKLM,
    HKCU,
}

/// toml int -> REG_DWORD, toml string -> REG_SZ
#[derive(Deserialize, Clone, PartialEq, Debug)]
#[serde(untagged)]
pub enum Data {
    Dword(u32),
    Str(String),
}

impl std::fmt::Display for Data {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Data::Dword(n) => write!(f, "{n}"),
            Data::Str(s) => write!(f, "\"{s}\""),
        }
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use winreg::{enums::*, types::FromRegValue, RegKey};

    fn root(h: Hive) -> RegKey {
        RegKey::predef(match h {
            Hive::HKLM => HKEY_LOCAL_MACHINE,
            Hive::HKCU => HKEY_CURRENT_USER,
        })
    }

    fn found<T>(r: io::Result<T>) -> anyhow::Result<Option<T>> {
        match r {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// None = missing, or a value type we don't manage
    pub fn reg_get(h: Hive, key: &str, name: &str) -> anyhow::Result<Option<Data>> {
        let Some(k) = found(root(h).open_subkey(key))? else { return Ok(None) };
        let Some(v) = found(k.get_raw_value(name))? else { return Ok(None) };
        Ok(match v.vtype {
            REG_DWORD => Some(Data::Dword(u32::from_reg_value(&v)?)),
            REG_SZ => Some(Data::Str(String::from_reg_value(&v)?)),
            _ => None,
        })
    }

    pub fn reg_write(h: Hive, key: &str, name: &str, d: &Data) -> anyhow::Result<()> {
        let (k, _) = root(h).create_subkey(key)?;
        match d {
            Data::Dword(n) => k.set_value(name, n)?,
            Data::Str(s) => k.set_value(name, s)?,
        }
        Ok(())
    }
}

// so it builds and tests on linux
#[cfg(not(windows))]
mod imp {
    use super::*;
    pub fn reg_get(_: Hive, _: &str, _: &str) -> anyhow::Result<Option<Data>> {
        anyhow::bail!("registry access requires Windows")
    }
    pub fn reg_write(_: Hive, _: &str, _: &str, _: &Data) -> anyhow::Result<()> {
        anyhow::bail!("registry access requires Windows")
    }
}

pub use imp::reg_get;

pub fn reg_set(ctx: &Ctx, h: Hive, key: &str, name: &str, d: &Data) -> anyhow::Result<()> {
    if ctx.dry_run {
        ctx.info(format!("[dry-run] would set {h:?}\\{key}\\{name} = {d}"));
        return Ok(());
    }
    imp::reg_write(h, key, name, d)?;
    ctx.info(format!("set {h:?}\\{key}\\{name} = {d}"));
    Ok(())
}

// -EncodedCommand so quotes survive as written.
// progress silenced, otherwise it leaks into stderr as CLIXML
fn ps(script: &str) -> io::Result<std::process::Output> {
    let script = format!("$ProgressPreference = 'SilentlyContinue'\n[Console]::OutputEncoding = [Text.Encoding]::UTF8\n{script}");
    let utf16: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut c = std::process::Command::new("powershell");
    // gui build has no console; without this every call flashes a window
    #[cfg(windows)]
    std::os::windows::process::CommandExt::creation_flags(&mut c, 0x0800_0000); // CREATE_NO_WINDOW
    c.args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", &base64(&utf16)])
        .output()
}

/// any unhandled error -> plain text on stderr + exit 1. errors the script silences itself don't count
fn guarded(script: &str) -> String {
    format!("$ErrorActionPreference = 'Stop'\ntry {{\n{script}\n}} catch {{ [Console]::Error.WriteLine($_); exit 1 }}")
}

fn base64(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            s.push(if i <= c.len() { T[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    s
}

/// read-only, so it runs in dry-run too
pub fn check(cond: &str) -> anyhow::Result<bool> {
    // want a marker, not just exit 0. a stub powershell (wine) exits 0 for everything
    let out = ps(&format!("if ({cond}) {{ 'WYN-CHECK-TRUE' }}"))?.stdout;
    Ok(String::from_utf8_lossy(&out).contains("WYN-CHECK-TRUE"))
}

/// read-only, so it runs in dry-run too
pub fn query(script: &str) -> anyhow::Result<String> {
    let o = ps(&guarded(script))?;
    anyhow::ensure!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr).trim());
    Ok(String::from_utf8_lossy(&o.stdout).into_owned())
}

pub fn run(ctx: &Ctx, cmd: &str) -> anyhow::Result<()> {
    if ctx.dry_run {
        ctx.info(format!("[dry-run] would run: {cmd}"));
        return Ok(());
    }
    // native tools (net, secedit...) only report failure through their exit code
    let o = ps(&format!("{}\nif ($LASTEXITCODE) {{ exit $LASTEXITCODE }}\nexit 0", guarded(cmd)))?;
    let out = String::from_utf8_lossy(&o.stdout);
    let err = String::from_utf8_lossy(&o.stderr);
    ctx.debug(out.trim());
    if !o.status.success() {
        let msg = if err.trim().is_empty() { out.trim() } else { err.trim() };
        anyhow::bail!("exit {}: {msg}", o.status.code().unwrap_or(-1));
    }
    ctx.info(format!("ran: {cmd}"));
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn base64_padding() {
        assert_eq!(super::base64(b"Man"), "TWFu");
        assert_eq!(super::base64(b"Ma"), "TWE=");
        assert_eq!(super::base64(b"M"), "TQ==");
    }
}
