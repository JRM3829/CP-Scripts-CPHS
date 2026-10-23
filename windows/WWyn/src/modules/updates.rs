//! app updates through winget. CP images often ship without it, so install it first
use crate::{ctx::Ctx, sys};

// Microsoft.WinGet.Client returns objects; winget.exe only prints a table with progress bars in it
const MODULE: &str = "Import-Module Microsoft.WinGet.Client";

pub fn run(ctx: &Ctx) -> anyhow::Result<()> {
    if !sys::check("(Get-Module -ListAvailable Microsoft.WinGet.Client) -and (Get-AppxPackage -AllUsers Microsoft.DesktopAppInstaller)")? {
        ctx.info("winget missing: installing it (App Installer + Microsoft.WinGet.Client)");
        // PSGallery needs TLS 1.2 on Windows PowerShell 5.1
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

// "Id|Name|Installed|Available" per line. ids go into powershell quotes, so only plain ones
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
mod tests {
    #[test]
    fn parse_skips_junk_and_unsafe_ids() {
        let p = super::parse("Google.Chrome|Google Chrome|155.0|156.1\n\nNotepad++.Notepad++|Notepad++|8.6|8.7\nbad'id|x|1|2\nonly|two\n");
        let ids: Vec<_> = p.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, ["Google.Chrome", "Notepad++.Notepad++"]);
        assert_eq!((p[0].from.as_str(), p[0].to.as_str()), ("155.0", "156.1"));
    }
}
