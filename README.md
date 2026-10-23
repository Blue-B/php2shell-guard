# php2shell-guard

[English](README.md) | [한국어](README.ko.md)

Checks whether your servers are exposed to **php2shell** (CVE-2026-109618 / CVE-2026-109619), two critical PHP remote code execution bugs with exploitation attempts since 17 October 2026 ([Amazon](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/)), and blocks them until you can patch. One bash script, no install. No exploit code.

Fixed in **PHP 8.5.12, 8.4.27, 8.3.36, 8.2.35** ([PHP advisory](https://www.php.net/archive/2026.php#2026-10-21-5)). 7.4 to 8.1: vendor package or PHP's source backport ([7.4](https://github.com/php/php-src/tree/PHP-7.4-CVE-2026-109618-109619), [8.0](https://github.com/php/php-src/tree/PHP-8.0-CVE-2026-109618-109619), [8.1](https://github.com/php/php-src/tree/PHP-8.1-CVE-2026-109618-109619)). Older: no fix.

## How to use

```bash
git clone https://github.com/Blue-B/php2shell-guard && cd php2shell-guard

sudo ./guard.sh scan           # 1. Am I vulnerable?
sudo ./guard.sh fix --apply    # 2. Block it now (temporary)
                               # 3. Update PHP (fix prints the command for your system)
sudo ./guard.sh undo           # 4. After updating: remove the temporary settings
```

1. **scan** finds every PHP on the server (control panels and Docker containers too) and says whether it is patched. Distro packages that carry the fix without a new version number count as patched, but only when they name both CVEs. It also finds PHP workers still running the old code because nobody restarted them after the update.
2. **fix --apply** puts PHP's recommended temporary settings in place, checks the config still loads, and reloads PHP. It adds its own files and never edits yours. Run `fix` without `--apply` to only see what it would do. Under Docker or a control panel, restart PHP yourself.
3. **Update PHP.** This is the real fix, and you run it yourself: `fix` prints the command for your system (`apt`, `dnf`, a new Docker tag, or your panel's updater).
4. **undo** removes the temporary settings. One of them lifts PHP's memory limit, so do not leave it on after you update.

```text
$ sudo ./guard.sh scan
== PHP binaries on this host ==
  /usr/local/sbin/php-fpm
  [!!] PHP 8.3.35: below fixed release 8.3.36 (unless a distro package backported the fix)
```

## More commands

| Command | What it does |
|---|---|
| `guard.sh check URL` | From outside, no server access: reads the PHP version a site advertises. Distro builds and hidden versions are reported as unknown, not as safe or vulnerable |
| `guard.sh images [DIR]` | Finds old PHP image tags in Dockerfiles, compose and Kubernetes files. Exits 1 if one is unpatched, so it can fail CI |
| `guard.sh hunt` | Looks for signs you were already hacked: shells started by PHP, crashes, webshells, cron |
| `guard.sh webcheck WEBROOT` | Installs `check.php`, which shows the settings your website really runs with. Delete it afterwards |
| `guard.sh test URL` | Checks that your web server rule from `rules/` blocks the attack's entry point |

`scan`, `check`, `hunt`, `images` and `test` also print JSON with `--json`.

**No file uploads on your site?** Also block multipart POST in the web server with the rule for yours in `rules/` (Apache, Nginx, Caddy, HAProxy, ModSecurity, Cloudflare). It breaks uploads, so it is not applied automatically.

**Keep old images out** with one GitHub Actions step (`path` is optional, default `.`):

```yaml
- uses: actions/checkout@v4
- uses: Blue-B/php2shell-guard@v0
  with:
    path: docker k8s
```

Other CI: `git clone --depth 1 --branch v0 https://github.com/Blue-B/php2shell-guard /tmp/p2sg && /tmp/p2sg/guard.sh images .`

`v0` always points to the latest 0.x release, so new fixes reach your CI without editing it. Pin an exact tag such as `v0.4.0` if you prefer.

## Compared with openai/php2shell-checker

[php2shell-checker](https://github.com/openai/php2shell-checker) tells you from the version number whether you may be affected. php2shell-guard also blocks the attack until you patch and looks for signs you were already hit.

| | php2shell-guard | php2shell-checker |
|---|---|---|
| Check a site by URL | `check` | yes |
| Check the server | `scan`, a script: every PHP build, containers, panels, distro backports, workers not restarted | instructions for the Codex agent |
| Block until patched | `fix --apply` (PHP settings), tested rules for 6 web servers | no |
| Signs of compromise | `hunt` | no |
| Old PHP images in CI | `images`, GitHub Action | no |
| Needs | bash, curl | Node.js, or Codex |

## Limits

- The temporary settings block the attacks that work on any PHP site. Attacks through your own application's code stay possible until you update PHP.
- `hunt` is a first look, not forensics. `images` does not resolve tags set through `ARG`. `check` only sees what the site advertises in its headers.
- Linux with Bash 4+. `check.php` also runs on Windows.
- `tests/run.sh` (Docker) tests every command and rule against real servers. The Cloudflare rule is untested.

## License

MIT
