# php2shell-guard

[English](README.md) | [한국어](README.ko.md)

Find, stopgap and keep out **php2shell** (CVE-2026-109618 / CVE-2026-109619), two critical PHP remote code execution bugs, exploited in the wild since 17 October 2026. One bash script and one PHP file, no install, no dependencies beyond coreutils. No exploit code.

> **Patch PHP to 8.5.12, 8.4.27, 8.3.36, 8.2.35 or later** ([PHP advisory](https://www.php.net/archive/2026.php#2026-10-21-5)). Distro packages may carry the fix without a version bump. 7.4 to 8.1: vendor package or PHP's source backport ([7.4](https://github.com/php/php-src/tree/PHP-7.4-CVE-2026-109618-109619), [8.0](https://github.com/php/php-src/tree/PHP-8.0-CVE-2026-109618-109619), [8.1](https://github.com/php/php-src/tree/PHP-8.1-CVE-2026-109618-109619)). Older: no fix. Everything here is a stopgap until you patch.

## Use

```bash
git clone https://github.com/Blue-B/php2shell-guard && cd php2shell-guard
sudo ./guard.sh scan            # am I affected?
sudo ./guard.sh fix             # what would the stopgaps change? (dry run)
sudo ./guard.sh fix --apply     # write them, test the config, reload PHP
```

```text
== PHP binaries on this host ==
  /usr/local/sbin/php-fpm
  [!!] PHP 8.3.35: below fixed release 8.3.36 (unless a distro package backported the fix)
  [??] stopgaps not set in the default ini: session.upload_progress.enabled=On memory_limit=128M (see rules/php.ini)

== Stopgaps for unpatched PHP (CVE-2026-109618 / CVE-2026-109619) ==
  write /usr/local/etc/php/conf.d/99-php2shell-guard.ini
  write /usr/local/etc/php-fpm.d/zz-php2shell-guard.conf (pools: www)
  [??] memory_limit=-1 lets one request use all RAM: cap the service instead (systemd MemoryMax=, container memory limit)
```

| Command | What it does |
|---|---|
| `guard.sh scan` | Finds every PHP build (panels and containers too), says whether it is patched, checks distro backports and stopgap settings |
| `guard.sh fix [--apply]` | Stopgaps for unpatched builds only. Without `--apply` it only shows the plan. With it, writes new drop-in files (never edits your config), rolls back if `php -r`, `php-fpm -t` or `apachectl -t` output changes, reloads PHP under systemd |
| `guard.sh undo` | Removes those drop-in files after you patch (only files carrying its marker) |
| `guard.sh images [DIR...]` | Finds PHP image tags in Dockerfiles, compose and Kubernetes files. Exit 1 on an unfixed or end-of-life tag, so it works as a CI gate |
| `guard.sh webcheck WEBROOT` | Installs `check.php`, which shows what the web PHP really runs. Delete it afterwards |
| `guard.sh test URL` | Sends harmless multipart variants to check that your edge rule blocks them |
| `guard.sh hunt [WEBROOT...]` | Looks for signs of compromise since 17 October: shells under PHP, worker crashes, out-of-memory before scripts ran, webshells, cron |

`scan`, `test`, `hunt` and `images` take `--json` (one object on stdout, for SIEMs and scripts). Exit code 1 means something needs attention.

## Am I affected

| You run | Check | Then |
|---|---|---|
| Debian/Ubuntu or RHEL packages | `guard.sh scan` (reads the package changelog, so backports count) | Upgrade the packages |
| Official `php` Docker image or a source build | `guard.sh images .` and `guard.sh scan` | Rebuild on a fixed tag |
| cPanel, Plesk, aaPanel, CloudLinux alt-php | `guard.sh scan` (panel paths included) | The panel's PHP updater |
| Shared hosting | `guard.sh webcheck`, or ask the host | Ask the host to patch; edge rule if you have no uploads |
| Windows / IIS | `check.php` | Patch; no edge rule here for IIS yet |

## Stopgaps

| Your site | Do this |
|---|---|
| No uploads or multipart forms | Block multipart POST at the edge with the rule for your server in `rules/`, and run `guard.sh fix --apply` (or apply `rules/php.ini` by hand) |
| Uploads needed | `guard.sh fix --apply`, or `rules/php.ini` in php.ini, the FPM pool or the vhost. Allowlist only the upload endpoints and restrict them to trusted users |
| Neither possible | Take the site off the internet until PHP is patched |

- `.user.ini` and `ini_set()` do **not** work for these settings on FPM, CGI or LSAPI: they apply too late. Restart every PHP worker after a change, then confirm with `guard.sh webcheck`.
- `memory_limit=-1` is PHP's stopgap for CVE-2026-109618. Cap the service instead (systemd `MemoryMax=`, container limit), and run `guard.sh undo` after patching.
- Blocking multipart breaks uploads and multipart forms. Anything you allowlist stays exposed.

## Keep it fixed

Fail CI when someone pins an old PHP image:

```yaml
# .github/workflows/php2shell.yml
on: [push, pull_request]
jobs:
  php-image-tags:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: git clone --depth 1 --branch v0.3.0 https://github.com/Blue-B/php2shell-guard /tmp/p2sg && /tmp/p2sg/guard.sh images .
```

Rescan servers daily, so a rollback or a forgotten container shows up:

```bash
# /etc/cron.d/php2shell-guard
17 6 * * * root /opt/php2shell-guard/guard.sh scan --json >> /var/log/php2shell-guard.jsonl 2>/dev/null
```

## Tests

`tests/run.sh` (needs Docker) runs every command against real servers: the edge rules for Apache/LiteSpeed, Nginx, Caddy, HAProxy and ModSecurity, `check.php` on FPM and mod_php, `scan`/`hunt` with planted indicators, and `fix`/`undo` on the official FPM image behind Nginx and on Ubuntu packages. The Cloudflare rule is untested.

## Limits

- The stopgaps cover the paths that work against any application. Bugs reached through your application stay exploitable until you patch.
- `fix` reloads PHP only through systemd. Containers, panels and LiteSpeed need a restart from you. Panels that regenerate FPM pools can drop the pool file.
- `images` does not resolve tags set through `ARG` or environment variables.
- `test` only checks the URLs you give it. `hunt` is triage, not forensics.
- Linux with Bash 4+. `check.php` also runs on Windows.

## License

MIT
