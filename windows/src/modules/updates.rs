use crate::{ctx::Ctx, sys};

// objects, not winget's table
const MODULE: &str = "Import-Module Microsoft.WinGet.Client";

pub fn run(ctx: &Ctx) -> anyhow::Result<()> {
    if !sys::check("(Get-Module -ListAvailable Microsoft.WinGet.Client) -and (Get-AppxPackage -AllUsers Microsoft.DesktopAppInstaller)")? {
        ctx.info("winget missing: installing it (App Installer + Microsoft.WinGet.Client)");
        // psgallery needs tls 1.2
        sys::run(
            ctx,
            "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
Install-Module Microsoft.WinGet.Client -Repository PSGallery -Scope AllUsers -Force -AllowClobber
Import-Module Microsoft.WinGet.Client
Repair-WinGetPackageManager -AllUsers -Latest -Force",
        )?;
        if ctx.dry_run {
            ctx.info("updates: can't list updates until winget is installed");
            return Ok(());
        }
    }

    let list = sys::query(&format!(
        "{MODULE}\nGet-WinGetPackage -Source winget | Where-Object IsUpdateAvailable | ForEach-Object {{ '{{0}}|{{1}}|{{2}}|{{3}}' -f $_.Id, $_.Name, $_.InstalledVersion, $_.AvailableVersions[0] }}"
    ))?;
    let pkgs = parse(&list);
    ctx.info(format!("{} app update(s) available", pkgs.len()));

    let mut failed = 0;
    for (i, p) in pkgs.iter().enumerate() {
        let desc = format!("[{}/{}] update {} ({} -> {})", i + 1, pkgs.len(), p.name, p.from, p.to);
        ctx.set_progress(i, pkgs.len(), &p.name);
        ctx.info(&desc);
        let cmd = format!(
            "{MODULE}\n$r = Update-WinGetPackage -Id '{}' -Source winget -MatchOption Equals -Mode Silent\nif ($r.Status -ne 'Ok') {{ throw \"$($r.Status) $($r.ExtendedErrorCode)\" }}",
            p.id
        );
        if let Err(e) = sys::run(ctx, &cmd) {
            failed += 1;
            ctx.info(format!("FAILED {desc}: {e}"));
        }
    }
    ctx.info(format!("updates: {} updated, {failed} failed", pkgs.len() - failed));
    Ok(())
}

struct Pkg {
    id: String,
    name: String,
    from: String,
    to: String,
}

// ids land in ps quotes
fn parse(s: &str) -> Vec<Pkg> {
    s.lines()
        .filter_map(|l| {
            let mut f = l.trim().splitn(4, '|');
            let (id, name, from, to) = (f.next()?, f.next()?, f.next()?, f.next()?);
            id.chars().all(|c| c.is_ascii_alphanumeric() || "._-+".contains(c)).then_some(())?;
            Some(Pkg { id: id.into(), name: name.into(), from: from.into(), to: to.into() })
        })
        .collect()
}

#[cfg(test)]
#[path = "../../tests/unit/updates.rs"]
mod tests;
