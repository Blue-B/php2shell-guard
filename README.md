# php2shell-guard

Defensive toolkit for **php2shell** (CVE-2026-109618 / CVE-2026-109619), the two critical PHP core vulnerabilities announced on 20 October 2026 and fixed on 21 October (CVSS v4.0 9.2 each).

One bash script and one PHP file. No install, no dependencies beyond `bash` and `curl`. It answers four questions:

| Question | Command |
|---|---|
| Which PHP builds run on this box, and are they patched? | `./guard.sh scan` |
| Does my edge rule actually stop multipart POSTs before PHP? | `./guard.sh test URL` |
| What does the *web* PHP really have configured? | `./guard.sh webcheck WEBROOT` (installs `check.php`) |
| Was I already hit? | `./guard.sh hunt` |

Plus tested blocking rules for Apache/LiteSpeed, Nginx, Caddy, HAProxy and ModSecurity, an untested Cloudflare expression, and PHP's interim settings for php.ini, FPM pools and Apache.

> **Patching PHP is the fix.** Everything here is a stopgap for the hours or days before you can patch, or for end-of-life PHP that will never get a fix. Nothing here contains or links exploit code.

## Status (updated 2026-10-22)

- **Fixed in PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35**, released 21 October 2026 ([php.net advisory](https://www.php.net/archive/2026.php#2026-10-21-5)). Linux distributions and LTS vendors got the patches in advance: check your vendor's packages.
- **PHP 7.4, 8.0, 8.1**: no official release. PHP published minimal source backports ([7.4](https://github.com/php/php-src/tree/PHP-7.4-CVE-2026-109618-109619), [8.0](https://github.com/php/php-src/tree/PHP-8.0-CVE-2026-109618-109619), [8.1](https://github.com/php/php-src/tree/PHP-8.1-CVE-2026-109618-109619)) or use a vendor package. **5.4 to 7.3**: no fix from PHP; the affected code goes back to 5.4.0 ([Tenable FAQ](https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote)).
- Two separate bugs:
  - **CVE-2026-109618, OOM corruption** ([GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)): an out-of-memory error while request data is half-initialized leaves it invalid, and request shutdown then uses it. Multipart body parsing can be pushed into OOM within normal limits (no usable Content-Length, many headers per part, empty file fields with nested names).
  - **CVE-2026-109619, stale global state** ([GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)): a use-after-free across two requests on the same worker. Confirmed paths: session upload progress (mod_php and FPM) and PHP 8.5 fatal error backtraces (mod_php).
- Every PHP that serves web requests is at risk. **mod_php is the worst case**: the confirmed exploit runs before any application code. FrankenPHP is likely the same; FPM and LSAPI are susceptible but need more conditions.
- **Exploited in the wild.** Amazon saw a first attempt on 17 October, four days before disclosure, and reports broad exploitation now ([AWS](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/)). Investigate from 17 October, not from the disclosure date. PHP found no working exploit among the public "PoCs" it inspected at release: don't run exploit code you can't audit, fake PoCs that drop malware are common after big disclosures.

## Quick start

```bash
git clone https://github.com/Blue-B/php2shell-guard && cd php2shell-guard
sudo ./guard.sh scan
```

### 1. `scan`: am I patched?

Finds `php`, `php-cgi`, `php-fpm` and `lsphp` in `PATH` and in the usual panel locations (cPanel EA-PHP, Plesk, CloudLinux alt-php, Remi, LiteSpeed, aaPanel), plus PHP inside running Docker containers. For each version it prints a verdict:

- **EOL**: 7.4 to 8.1 are fixed only by a vendor package or PHP's source backport; older branches have no fix.
- **below / at or above fixed release**: compared against the first fixed upstream release (8.2.35, 8.3.36, 8.4.27, 8.5.12).

It also greps Debian/Ubuntu and RPM package changelogs for the CVE IDs, because **distro packages often backport the fix without changing the PHP version** (Ubuntu's 8.3.6 stays 8.3.6). For unpatched binaries it shows the stopgap settings in their default ini (`session.upload_progress.enabled`, `memory_limit`, `fatal_error_backtraces`), lists explicit settings in `/etc`, and warns when running PHP or web workers have an address-space or data rlimit (PHP warns against those: a failed allocation reaches the bug).

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

CLI `php -i` reads a different ini than PHP-FPM or mod_php. `check.php` runs inside the web SAPI and reports version, verdict, SAPI risk, the stopgap settings (`session.upload_progress.enabled`, `memory_limit`, `fatal_error_backtraces`), request limits (`post_max_size`, `max_input_vars`, `max_input_nesting_level`, `max_file_uploads`), `file_uploads`, `enable_post_data_reading` and the loaded ini.

Settings are shown as they apply while PHP parses the request. On FPM, CGI and LSAPI that is the php.ini/pool value, because `.user.ini` and `ini_set()` apply later: when a `.user.ini` value differs, check.php reports the value that counts and says so. It runs on PHP 5.2+, needs a 16+ character key (refuses to run with the placeholder), sends `noindex`, and supports `&format=json`. **Delete it when done**: the key ends up in access logs.

### 4. `hunt`: was I hit?

One-shot look for common post-exploitation signs:

- shells, interpreters and download tools whose parent chain contains `php-fpm`, `php-cgi`, `lsphp`, `httpd` or `apache2` (`sh -c sendmail` from `mail()` and piped logs are shown as "review", not alerts)
- reverse-shell-looking command lines (`/dev/tcp/`, `mkfifo`, `bash -i`, `nc -e`, ...)
- **PHP worker crashes** (`SIGSEGV`, `signal 11`, `zend_mm_heap corrupted`) in PHP/FPM/Apache/LiteSpeed/Nginx logs and the journal. Memory-corruption exploits often crash workers before they succeed
- **out-of-memory before any script ran** (`Allowed memory size ... exhausted ... in Unknown on line 0`) and FPM children exiting with code 70 (FPM ends a child whose request startup failed). CVE-2026-109618 needs an OOM while PHP parses the request, so attempts tend to leave these
- PHP files in `/tmp`, `/var/tmp`, `/dev/shm`
- PHP/`.htaccess`/`.user.ini` files changed in the last N days in your webroots, and common webshell patterns
- recently changed cron files

`./guard.sh hunt /var/www/site1 /var/www/site2`. File, cron and journal checks look back to 17 October 2026 by default (first exploitation seen); `--days N` changes that. For continuous monitoring use [process-watcher](https://github.com/Neo23x0/process-watcher).

## Mitigation rules

Pick by what your site needs:

| Your site | Do this |
|---|---|
| No file uploads or multipart forms | Block multipart POST at the edge (`rules/` for your server; PHP recommends this too), and apply `rules/php.ini` |
| Uploads needed | Apply `rules/php.ini` in php.ini, the FPM pool or the vhost. Allowlist only the upload endpoints, refuse chunked multipart on them (`rules/apache.htaccess` does), cap the body size at the proxy, and restrict them to trusted users or IPs |
| Shared hosting on FPM/CGI without php.ini access | `.user.ini` does **not** help (it applies too late). Use the `.htaccess` edge rule if the site can live without multipart, and get the host to patch |
| None of the above is possible | Take the site off the internet until PHP is patched |

`rules/php.ini` holds PHP's interim settings: `session.upload_progress.enabled=Off`, `memory_limit=-1` (with a service-level memory cap, never `ulimit -v`), a small `post_max_size`, and `fatal_error_backtraces=Off` on 8.5. Restart every worker after changing them. PHP's advisory also says to remove invalid or deprecated per-request settings (`.htaccess` `php_value`, `PHP_VALUE` from the web server): their warnings are a CVE-2026-109619 trigger. Hiding warnings with `error_reporting` or `@` does not help.

| File | Server | Tested in `tests/run.sh` |
|---|---|---|
| `rules/apache.htaccess` | Apache 2.4 (.htaccess or vhost), LiteSpeed | yes (Apache, incl. chunked on an allowlisted endpoint) |
| `rules/nginx.conf` | Nginx | yes |
| `rules/Caddyfile` | Caddy 2 | yes |
| `rules/haproxy.cfg` | HAProxy | yes |
| `rules/modsecurity.conf` | ModSecurity v2/v3, with OWASP CRS | yes (CRS apache image) |
| `rules/cloudflare.txt` | Cloudflare WAF custom rule | **no** |
| `rules/php.ini` | php.ini, FPM pool, mod_php vhost/.htaccess | loads cleanly on 8.3; pool value seen and `.user.ini` flagged by check.php on FPM |

Blocking multipart breaks every upload and multipart form on the site (WordPress media uploads, contact forms with attachments, admin imports). Each rule file has an allowlist example; anything you allowlist stays exposed.

**Don't block on `PHPSESSID`.** A rule like `if ($http_cookie ~* PHPSESSID) { return 403; }` breaks logins and still lets multipart bodies through.

## Tests

```bash
tests/run.sh
```

Starts real Nginx, Caddy, HAProxy, Apache (mod_php) and ModSecurity+CRS containers in front of PHP 8.3.35 (the last unfixed 8.3), runs `guard.sh test` against each, checks an unprotected Nginx is caught, checks `check.php` key handling, verdicts, pool values and `.user.ini`, runs `scan` against 8.3.35 and 8.3.36, and plants fake indicators (shell under PHP, SIGSEGV and pre-script OOM log lines, `/tmp` PHP file, webshell) to verify `hunt` finds them. Needs Docker and ports 18081-18086.

## Limits

- A passing `test` shows the rule filters the URLs you tested. It does not prove the CVEs are fixed and does not cover other vhosts or origins reachable directly.
- Blocking multipart and the php.ini stopgaps cover the application-independent paths PHP describes. Out-of-memory, fatal errors and timeouts reached through your application stay exploitable until you patch.
- `hunt` is a quick triage, not forensics. A clean result does not mean a clean host.
- Bash 4+ and GNU-ish userland (Linux). Windows `php-cgi.exe` / IIS hosts are not covered by `guard.sh`; `check.php` still works there.

## Contributing

The fixed versions live in the `FIXED` table in both `guard.sh` and `check.php`. PRs with distro backport package versions and rule updates are welcome.

## License

MIT
