//! README parser (Lwyn: libs/readme.sh)
use crate::{ctx::Ctx, sys};
use std::path::{Path, PathBuf};

#[derive(Debug, Default)]
pub struct Readme {
    /// the "(you)" account. never delete it or touch its password
    pub me: Option<String>,
    pub admins: Vec<String>,
    pub users: Vec<String>,
}

const MARKER: &str = "authorized administrators";

fn has_list(page: &str) -> bool {
    page.to_lowercase().contains(MARKER)
}

/// README shortcut (.lnk/.url) or saved page on any desktop under C:\Users, Public included
pub fn load(ctx: &Ctx) -> anyhow::Result<Readme> {
    let (src, html) = match &ctx.readme {
        Some(t) => open(t)?,
        None => find(ctx).map_err(|e| anyhow::anyhow!("{e}; give the README URL manually (GUI box or --readme)"))?,
    };
    ctx.info(format!("README: {src}"));
    Ok(parse(&html))
}

fn find(ctx: &Ctx) -> anyhow::Result<(String, String)> {
    for desktop in files(Path::new(r"C:\Users")).into_iter().map(|u| u.join("Desktop")) {
        for f in files(&desktop) {
            let name = f.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
            if !name.contains("readme") {
                continue;
            }
            let target = if name.ends_with(".lnk") {
                // browser shortcuts put the url in Arguments
                let p = f.display().to_string().replace('\'', "''");
                sys::query(&format!("$s = (New-Object -ComObject WScript.Shell).CreateShortcut('{p}'); \"$($s.TargetPath) $($s.Arguments)\""))?
            } else if name.ends_with(".url") {
                f.display().to_string()
            } else {
                continue;
            };
            ctx.debug(format!("shortcut {} -> {}", f.display(), target.trim()));
            return open(target.trim());
        }
        if let Some(found) = html_in(&desktop) {
            return Ok(found);
        }
    }
    anyhow::bail!(r"no README found on any Desktop (C:\Users\*\Desktop)")
}

/// shortcut target: a url anywhere in it, a .url file, or a local page
fn open(target: &str) -> anyhow::Result<(String, String)> {
    if let Some(url) = urls(target).into_iter().next() {
        let html = fetch(&url)?;
        return Ok((url, html));
    }
    let path = target.trim_matches('"');
    let page = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("README shortcut target {path}: {e}"))?;
    if path.to_lowercase().ends_with(".url") {
        let url = page.lines().find_map(|l| l.trim().strip_prefix("URL=")).ok_or_else(|| anyhow::anyhow!("no URL= in {path}"))?;
        return open(url);
    }
    if has_list(&page) {
        return Ok((path.to_string(), page));
    }
    // C:\CyberPatriot\readme.html is just a redirect to the online README
    for url in urls(&page).into_iter().take(5) {
        if let Ok(html) = fetch(&url) {
            if has_list(&html) {
                return Ok((url, html));
            }
        }
    }
    anyhow::bail!("{path} has no account list and none of its links lead to one")
}

fn urls(s: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for (i, _) in s.match_indices("http") {
        let rest = &s[i..];
        if !rest.starts_with("http://") && !rest.starts_with("https://") {
            continue;
        }
        let url: String = rest.chars().take_while(|c| !c.is_whitespace() && !"\"'<>);".contains(*c)).collect();
        if !out.contains(&url) {
            out.push(url);
        }
    }
    out
}

fn files(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir).map(|rd| rd.flatten().map(|e| e.path()).collect()).unwrap_or_default()
}

fn html_in(dir: &Path) -> Option<(String, String)> {
    files(dir).into_iter().find_map(|f| {
        let ext = f.extension()?.to_string_lossy().to_lowercase();
        if ext != "html" && ext != "htm" {
            return None;
        }
        let page = std::fs::read_to_string(&f).ok()?;
        has_list(&page).then(|| (f.display().to_string(), page))
    })
}

fn fetch(url: &str) -> anyhow::Result<String> {
    anyhow::ensure!(!url.contains('\''), "bad README URL: {url}");
    sys::query(&format!("(Invoke-WebRequest -UseBasicParsing -Uri '{url}').Content"))
}

// also keeps names safe inside powershell quotes
fn valid_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 20 && s.chars().all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
}

pub fn parse(html: &str) -> Readme {
    let mut r = Readme::default();
    let mut admins_section: Option<bool> = None;
    for raw in to_text(html).lines() {
        let line = raw.trim().trim_start_matches(['-', '*', '•']).trim();
        let lower = line.to_ascii_lowercase(); // ascii so byte offsets match line
        if lower.starts_with(MARKER) {
            admins_section = Some(true);
            continue;
        }
        if lower.starts_with("authorized users") {
            admins_section = Some(false);
            continue;
        }
        let Some(is_admin) = admins_section else { continue };
        if lower.ends_with(':') || ["critical services", "competition", "forensics", "guidelines", "notes", "tasks"].iter().any(|h| lower.starts_with(h)) {
            admins_section = None;
            continue;
        }
        if lower.starts_with("password") {
            continue;
        }
        let you = lower.find("(you)");
        let name = match you {
            Some(i) => format!("{}{}", &line[..i], &line[i + 5..]).trim().to_string(),
            None => line.to_string(),
        };
        if !valid_name(&name) {
            continue; // prose
        }
        if you.is_some() {
            r.me = Some(name.clone());
        }
        let list = if is_admin { &mut r.admins } else { &mut r.users };
        if !list.contains(&name) {
            list.push(name);
        }
    }
    // listed as both -> admin
    let admins = r.admins.clone();
    r.users.retain(|u| !admins.contains(u));
    r
}

/// the <pre> with the account lists if there is one, else the whole page. tags stripped
fn to_text(html: &str) -> String {
    let lower = html.to_ascii_lowercase(); // ascii so byte offsets match html
    let mut body = html.to_string();
    let mut from = 0;
    while let Some(i) = lower[from..].find("<pre").map(|i| i + from) {
        let end = lower[i..].find("</pre>").map_or(lower.len(), |e| i + e);
        if lower[i..end].contains(MARKER) {
            body = html[i..end].to_string();
            break;
        }
        from = end;
    }
    for tag in ["script", "style"] {
        body = drop_blocks(&body, tag);
    }
    let mut out = String::new();
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        if c != '<' {
            out.push(c);
            continue;
        }
        let tag: String = chars.by_ref().take_while(|&c| c != '>').collect();
        let name = tag.trim_start_matches('/').chars().take_while(char::is_ascii_alphanumeric).collect::<String>().to_lowercase();
        if ["br", "p", "li", "div", "tr", "h1", "h2", "h3", "h4", "h5", "h6"].contains(&name.as_str()) {
            out.push('\n');
        }
    }
    decode(&out)
}

// script text would otherwise read as page text
fn drop_blocks(s: &str, tag: &str) -> String {
    let (open, close) = (format!("<{tag}"), format!("</{tag}>"));
    let mut out = String::new();
    let mut rest = s;
    loop {
        let lower = rest.to_ascii_lowercase();
        let Some(i) = lower.find(&open) else { break };
        out.push_str(&rest[..i]);
        rest = lower[i..].find(&close).map_or("", |e| &rest[i + e + close.len()..]);
    }
    out.push_str(rest);
    out
}

fn entity(e: &str) -> Option<char> {
    match e {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" => Some(' '),
        _ => e
            .strip_prefix("#x")
            .or_else(|| e.strip_prefix("#X"))
            .and_then(|h| u32::from_str_radix(h, 16).ok())
            .or_else(|| e.strip_prefix('#')?.parse().ok())
            .and_then(char::from_u32),
    }
}

fn decode(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        // unknown or unterminated entity stays as literal '&'
        match rest.find(';').filter(|&j| j < 10).and_then(|j| Some((entity(&rest[1..j])?, j))) {
            Some((c, j)) => {
                out.push(c);
                rest = &rest[j + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_links() {
        let page = r#"<meta http-equiv="refresh" content="0; url=https://example.org/scenario/abc/"><script>window.location='https://example.org/scenario/abc/';</script>"#;
        assert_eq!(urls(page), ["https://example.org/scenario/abc/"]);
    }

    #[test]
    fn no_pre_block_stops_at_next_heading() {
        let r = parse(
            "<html><body><script>var authorized = 1;</script><p>Critical Services:</p><p>None</p>\
             <h2>Authorized Administrators and Users</h2><p>Authorized Administrators:<br>alpha (you)<br>\
             &nbsp; password: x&amp;y<br>beta</p><p>Authorized Users:</p><ul><li>gamma</li><li>Some prose here.</li></ul>\
             <h2>Competition Guidelines</h2><p>Never</p></body></html>",
        );
        assert_eq!(r.me.as_deref(), Some("alpha"));
        assert_eq!(r.admins, ["alpha", "beta"]);
        assert_eq!(r.users, ["gamma"]);
    }
}
