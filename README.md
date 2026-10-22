# php2shell-guard

Checks and stopgap rules for **php2shell** (CVE-2026-109618 / CVE-2026-109619), two critical PHP remote code execution bugs, exploited in the wild since 17 October 2026. One bash script and one PHP file, no install. No exploit code.

> **Patch PHP to 8.5.12, 8.4.27, 8.3.36, 8.2.35 or later** ([PHP advisory](https://www.php.net/archive/2026.php#2026-10-21-5)). Distro packages may carry the fix without a version bump. 7.4 to 8.1: vendor package or PHP's source backport ([7.4](https://github.com/php/php-src/tree/PHP-7.4-CVE-2026-109618-109619), [8.0](https://github.com/php/php-src/tree/PHP-8.0-CVE-2026-109618-109619), [8.1](https://github.com/php/php-src/tree/PHP-8.1-CVE-2026-109618-109619)). Older: no fix. Everything here is a stopgap until you patch.

## Use

```bash
git clone https://github.com/Blue-B/php2shell-guard && cd php2shell-guard
sudo ./guard.sh scan
```

| Command | What it does |
|---|---|
| `guard.sh scan` | Finds every PHP build (panels and containers too), says whether it is patched, checks distro backports and stopgap settings |
| `guard.sh webcheck WEBROOT` | Installs `check.php`, which shows what the web PHP really runs. Delete it afterwards |
| `guard.sh test URL` | Sends harmless multipart variants to check that your edge rule blocks them |
| `guard.sh hunt [WEBROOT...]` | Looks for signs of compromise since 17 October: shells under PHP, worker crashes, out-of-memory before scripts ran, webshells, cron |

## Stopgaps

| Your site | Do this |
|---|---|
| No uploads or multipart forms | Block multipart POST at the edge with the rule for your server in `rules/`, and apply `rules/php.ini` |
| Uploads needed | Apply `rules/php.ini` in php.ini, the FPM pool or the vhost. Allowlist only the upload endpoints and restrict them to trusted users |
| Neither possible | Take the site off the internet until PHP is patched |

- `.user.ini` and `ini_set()` do **not** work for these settings on FPM, CGI or LSAPI: they apply too late. Restart every PHP worker after a change.
- Blocking multipart breaks uploads and multipart forms. Anything you allowlist stays exposed.
- Rules for Apache/LiteSpeed, Nginx, Caddy, HAProxy and ModSecurity are tested by `tests/run.sh` (needs Docker). The Cloudflare rule is untested.

## Limits

- The stopgaps cover the paths that work against any application. Bugs reached through your application stay exploitable until you patch.
- `test` only checks the URLs you give it. `hunt` is triage, not forensics.
- Linux with Bash 4+. `check.php` also runs on Windows.

## License

MIT
