# php2shell-guard

Defensive toolkit for **php2shell** (CVE-2026-109618 / CVE-2026-109619), the two critical PHP core vulnerabilities announced on 20 October 2026 (CVSS v4.0 9.2 each).

One bash script and one PHP file. No install, no dependencies beyond `bash` and `curl`. It answers four questions:

| Question | Command |
|---|---|
| Which PHP builds run on this box, and are they patched? | `./guard.sh scan` |
| Does my edge rule actually stop multipart POSTs before PHP? | `./guard.sh test URL` |
| What does the *web* PHP really have configured? | `./guard.sh webcheck WEBROOT` (installs `check.php`) |
| Was I already hit? | `./guard.sh hunt` |

Plus tested blocking rules for Apache/LiteSpeed, Nginx, Caddy, HAProxy and ModSecurity, an untested Cloudflare expression, and php.ini / FPM / `.user.ini` snippets.

> **Patching PHP is the fix.** Everything here is a stopgap for the hours or days before you can patch, or for end-of-life PHP that will never get a fix. Nothing here contains or links exploit code.

## Status (updated 2026-10-21 07:00 UTC)

- PHP's emergency release is scheduled for **21 October 2026, 14:00 UTC** ([php.net](https://www.php.net/archive/2026.php#2026-10-20-1)). Affected and fixed versions are not public yet.
- Leaked material credits an exploit tool claiming PHP 5.4+ ([Sansec](https://sansec.io/research/php2shell)). Not confirmed by PHP.
- Researchers point at a memory-safety bug in **session upload-progress handling while PHP parses `multipart/form-data` POST bodies**, before your application code runs ([Syhunt](https://github.com/syhunt/php2shell-protection)). Also not confirmed. The rules here target that path and will be revised once the advisory is out.
- PHP 8.1 and older are end-of-life and will not get an official fix.

## Quick start

```bash
git clone https://github.com/Blue-B/php2shell-guard && cd php2shell-guard
sudo ./guard.sh scan
```

### 1. `scan`: am I patched?

Finds `php`, `php-cgi`, `php-fpm` and `lsphp` in `PATH` and in the usual panel locations (cPanel EA-PHP, Plesk, CloudLinux alt-php, Remi, LiteSpeed, aaPanel), plus PHP inside running Docker containers. For each version it prints a verdict:

- **EOL**: branch has no official fix coming.
- **fix not released yet**: supported branch, no patched release yet.
- **below / at or above fixed release**: compared against the first fixed upstream release.

While the version table in the script is empty, `scan` asks php.net for the latest release of each branch (`--offline` skips this). It also greps Debian/Ubuntu and RPM package changelogs for the CVE IDs, because **distro packages often backport the fix without changing the PHP version** (Ubuntu's 8.3.6 stays 8.3.6). Finally it shows `session.upload_progress.enabled` for CLI/FPM and any explicit overrides in `/etc`.

### 2. `test`: does my block rule work?

```bash
./guard.sh webcheck /var/www/html      # prints a probe URL, remove the file afterwards
./guard.sh test "https://example.com/p2sg-xxxx.php?probe=1"
```

Sends one ordinary url-encoded POST (should pass) and eight harmless multipart variants that PHP still parses as multipart:

```text
multipart (curl -F)              upper case Content-Type
no space before boundary         comma separator  (HAProxy req.hdr misses this one)
trailing space                   chunked body
duplicate Content-Type (multipart first / last)
```

With the `?probe=1` endpoint it reads back what PHP itself received, so it can tell "blocked", "reached PHP but not as multipart", and "reached PHP as multipart". Without the probe it falls back to HTTP status (4xx = blocked). You can test any URL, but test the PHP entry points you actually expose.

### 3. `check.php`: what does the web server's PHP use?

CLI `php -i` reads a different ini than PHP-FPM or mod_php. `check.php` runs inside the web SAPI and reports version, verdict, `session.upload_progress.enabled`, `file_uploads`, `enable_post_data_reading` and the loaded ini. It runs on PHP 5.2+, needs a 16+ character key (refuses to run with the placeholder), sends `noindex`, and supports `&format=json`. **Delete it when done**: the key ends up in access logs.

### 4. `hunt`: was I hit?

One-shot look for common post-exploitation signs:

- shells, interpreters and download tools whose parent chain contains `php-fpm`, `php-cgi`, `lsphp`, `httpd` or `apache2` (`sh -c sendmail` from `mail()` and piped logs are shown as "review", not alerts)
- reverse-shell-looking command lines (`/dev/tcp/`, `mkfifo`, `bash -i`, `nc -e`, ...)
- **PHP worker crashes** (`SIGSEGV`, `signal 11`, `zend_mm_heap corrupted`) in FPM/Apache/LiteSpeed/Nginx logs and the journal. Memory-corruption exploits often crash workers before they succeed
- PHP files in `/tmp`, `/var/tmp`, `/dev/shm`
- PHP/`.htaccess`/`.user.ini` files changed in the last N days in your webroots, and common webshell patterns
- recently changed cron files

`./guard.sh hunt /var/www/site1 /var/www/site2 --days 7`. For continuous monitoring use [process-watcher](https://github.com/Neo23x0/process-watcher).

## Mitigation rules

Pick by what your site needs:

| Your site | Do this |
|---|---|
| No file uploads or multipart forms | Block multipart POST at the edge: `rules/` for your server |
| Uploads needed, no upload progress bars | Turn off `session.upload_progress.enabled` (`rules/php.ini`), works via `.user.ini` on shared hosting |
| Uploads and progress needed | Patch as soon as possible; restrict upload endpoints to trusted users or IPs |

| File | Server | Tested in `tests/run.sh` |
|---|---|---|
| `rules/apache.htaccess` | Apache 2.4 (.htaccess or vhost), LiteSpeed | yes (Apache) |
| `rules/nginx.conf` | Nginx | yes |
| `rules/Caddyfile` | Caddy 2 | yes |
| `rules/haproxy.cfg` | HAProxy | yes |
| `rules/modsecurity.conf` | ModSecurity v2/v3, with OWASP CRS | yes (CRS apache image) |
| `rules/cloudflare.txt` | Cloudflare WAF custom rule | **no** |
| `rules/php.ini` | php.ini, FPM pool, mod_php, `.user.ini` | `.user.ini` on FPM: yes |

Blocking multipart breaks every upload and multipart form on the site (WordPress media uploads, contact forms with attachments, admin imports). Each rule file has an allowlist example; anything you allowlist stays exposed.

**Don't block on `PHPSESSID`.** A rule like `if ($http_cookie ~* PHPSESSID) { return 403; }` breaks logins and still lets multipart bodies through.

## Tests

```bash
tests/run.sh
```

Starts real Nginx, Caddy, HAProxy, Apache (mod_php) and ModSecurity+CRS containers in front of PHP 8.3, runs `guard.sh test` against each, checks an unprotected Nginx is caught, checks `check.php` key handling and `.user.ini`, and plants fake indicators (shell under PHP, SIGSEGV log line, `/tmp` PHP file, webshell) to verify `hunt` finds them. Needs Docker and ports 18081-18086.

## Limits

- A passing `test` shows the rule filters the URLs you tested. It does not prove the CVEs are fixed, does not cover other vhosts or origins reachable directly, and assumes the reported multipart path is the right one.
- `hunt` is a quick triage, not forensics. A clean result does not mean a clean host.
- Bash 4+ and GNU-ish userland (Linux). Windows `php-cgi.exe` / IIS hosts are not covered by `guard.sh`; `check.php` still works there.

## After the release

When PHP publishes fixed versions, fill the `FIXED` table in both `guard.sh` and `check.php` (the online lookup in `scan` works without it). PRs with distro backport package versions and rule updates are welcome.

## License

MIT
