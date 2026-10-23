#!/usr/bin/env bash
# End-to-end tests: real Apache, Nginx, Caddy, HAProxy, ModSecurity in Docker, each in front of PHP.
# Usage: tests/run.sh   (needs docker; uses ports 18081-18087; cleans up after itself)
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
NET=p2sg-net
KEY=testkey0123456789abcdef
WORK=""
FAILS=0

cleanup() { docker ps -aq --filter name=p2sg- | xargs -r docker rm -f >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; [[ -n $WORK ]] && rm -rf "$WORK"; }
trap cleanup EXIT
cleanup; WORK=$(mktemp -d)

expect() { # description expected actual
    if [[ $2 == "$3" ]]; then echo "PASS  $1"; else echo "FAIL  $1 (expected $2, got $3)"; FAILS=$((FAILS+1)); fi
}
has() { # description pattern text
    if grep -qE -- "$2" <<<"$3"; then echo "PASS  $1"; else echo "FAIL  $1 (no match for: $2)"; echo "$3" | sed 's/^/      /' | head -20; FAILS=$((FAILS+1)); fi
}

# Pinned: 8.3.35 is the last unfixed 8.3 release, 8.3.36 the first fixed one.
PHP_OLD=8.3.35 PHP_NEW=8.3.36

# webroot: keyed check.php, plus a subdir with .user.ini turning upload progress off (too late on FPM)
mkdir -p "$WORK/www/ui"
sed "s/^\$KEY = 'CHANGE_ME';/\$KEY = '$KEY';/" check.php > "$WORK/www/check.php"
cp "$WORK/www/check.php" "$WORK/www/ui/check.php"
printf 'session.upload_progress.enabled = 0\n' > "$WORK/www/ui/.user.ini"
printf '[www]\nphp_admin_value[memory_limit] = -1\n' > "$WORK/zz-pool.conf"
chmod -R a+rX "$WORK"

cat > "$WORK/nginx-open.conf" <<'EOF'
server { listen 80; root /var/www/html;
  location ~ \.php$ { fastcgi_pass p2sg-fpm:9000; include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME /var/www/html$fastcgi_script_name; } }
EOF
{ grep -v '^#' rules/nginx.conf; sed 's/server { listen 80; root \/var\/www\/html;/&\n  if ($p2sg_block) { return 403; }/' "$WORK/nginx-open.conf"; } > "$WORK/nginx-guard.conf"
{ echo ':80 {'; echo 'root * /var/www/html'; cat rules/Caddyfile; echo 'php_fastcgi p2sg-fpm:9000'; echo '}'; } > "$WORK/Caddyfile"
cat > "$WORK/haproxy.cfg" <<EOF
defaults
  mode http
  timeout connect 5s
  timeout client 30s
  timeout server 30s
frontend fe
  bind :80
$(grep -v '^#' rules/haproxy.cfg | sed 's/^/  /')
  default_backend be
backend be
  server s1 p2sg-nginx-open:80
EOF
mkdir -p "$WORK/apache/up"; cp check.php "$WORK/apache/check.php"; cp rules/apache.htaccess "$WORK/apache/.htaccess"
sed -i "s/^\$KEY = 'CHANGE_ME';/\$KEY = '$KEY';/" "$WORK/apache/check.php"; cp "$WORK/apache/check.php" "$WORK/apache/up/check.php"
# /up/ has its own .htaccess with the allowlist line enabled for /up/check.php
sed 's|^# RewriteCond %{REQUEST_URI} !^/wp-admin/async-upload|RewriteCond %{REQUEST_URI} !^/up/check|' rules/apache.htaccess > "$WORK/apache/up/.htaccess"
chmod -R a+rX "$WORK/apache"

docker network create $NET >/dev/null
run() { docker run -d --network $NET "$@" >/dev/null || { echo "docker run failed: $*"; exit 2; }; }
run --name p2sg-fpm -v "$WORK/www:/var/www/html:ro" -v "$WORK/zz-pool.conf:/usr/local/etc/php-fpm.d/zz-pool.conf:ro" php:$PHP_OLD-fpm-alpine
run --name p2sg-nginx-open -p 18081:80 -v "$WORK/www:/var/www/html:ro" -v "$WORK/nginx-open.conf:/etc/nginx/conf.d/default.conf:ro" nginx:alpine
run --name p2sg-nginx-guard -p 18082:80 -v "$WORK/www:/var/www/html:ro" -v "$WORK/nginx-guard.conf:/etc/nginx/conf.d/default.conf:ro" nginx:alpine
run --name p2sg-caddy -p 18083:80 -v "$WORK/www:/var/www/html:ro" -v "$WORK/Caddyfile:/etc/caddy/Caddyfile:ro" caddy:alpine
run --name p2sg-haproxy -p 18084:80 -v "$WORK/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro" haproxy:alpine
# data rlimit set on purpose: scan must warn about it
run --name p2sg-apache -p 18085:80 --ulimit data=17179869184 -v "$WORK/apache:/var/www/html:ro" -v "$ROOT:/guard:ro" php:$PHP_OLD-apache \
    sh -c "a2enmod rewrite >/dev/null && sed -i 's/AllowOverride None/AllowOverride All/' /etc/apache2/apache2.conf && exec apache2-foreground"
run --name p2sg-modsec -p 18086:8080 -e BACKEND=http://p2sg-nginx-open:80 \
    -v "$ROOT/rules/modsecurity.conf:/etc/modsecurity.d/owasp-crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf:ro" owasp/modsecurity-crs:apache

echo "waiting for servers..."
for port in 18081 18082 18083 18084 18085 18086; do
    for _ in $(seq 60); do curl -s -o /dev/null "http://127.0.0.1:$port/check.php?probe=1" && break; sleep 1; done
done

echo; echo "== guard.sh test against each server =="
P="check.php?probe=1"
out=$(./guard.sh test "http://127.0.0.1:18081/$P"); rc=$?
expect "nginx without rule is detected as unprotected" 1 $rc
has "unprotected nginx: multipart reaches PHP" 'reached PHP as multipart' "$out"
for t in "nginx:18082" "caddy:18083" "haproxy:18084" "apache .htaccess:18085" "modsecurity+CRS:18086"; do
    out=$(./guard.sh test "http://127.0.0.1:${t##*:}/$P"); rc=$?
    expect "${t%%:*} rule blocks every multipart variant" 0 $rc
    has "${t%%:*} still allows url-encoded POST" 'url-encoded POST allowed \(200\), PHP executed' "$out"
    [[ $rc == 0 ]] || echo "$out" | grep -E '\[(!!|\?\?)\]' | sed 's/^/      /'
done
out=$(curl -s -F t=x "http://127.0.0.1:18085/up/check.php?probe=1")
has "apache allowlisted endpoint still takes multipart" 'P2SG_PHP_EXECUTED post=1' "$out"
out=$(curl -s -o /dev/null -w '%{http_code}' -H 'Transfer-Encoding: chunked' -F t=x "http://127.0.0.1:18085/up/check.php?probe=1")
expect "apache refuses chunked multipart even on an allowlisted endpoint" 403 "$out"

echo; echo "== check.php =="
out=$(curl -s -w ' %{http_code}' "http://127.0.0.1:18081/check.php")
has "check.php refuses without key" '403$' "$out"
out=$(curl -s "http://127.0.0.1:18081/check.php?key=wrong")
has "check.php refuses wrong key" 'Forbidden' "$out"
out=$(curl -s "http://127.0.0.1:18081/check.php?key=$KEY")
has "check.php reports VULNERABLE for $PHP_OLD" 'verdict +VULNERABLE' "$out"
has "check.php sees upload_progress On by default" 'session.upload_progress.enabled +On' "$out"
has "check.php sees the FPM pool php_admin_value memory_limit" 'memory_limit +-1$' "$out"
out=$(curl -s "http://127.0.0.1:18081/ui/check.php?key=$KEY&format=json")
has "check.php on FPM ignores .user.ini (applies too late)" '"session.upload_progress.enabled":"On"' "$out"
has "check.php explains the .user.ini value does not count" 'only per directory' "$out"
out=$(curl -s "http://127.0.0.1:18085/check.php?key=$KEY")
has "check.php flags mod_php as highest risk" 'apache2handler: highest risk' "$out"
has "check.php suggests memory_limit=-1 while unpatched" 'memory_limit=-1 via php_admin_value' "$out"
tmpkeyless=$(sed -n "s/^\$KEY = '\(.*\)';/\1/p" check.php)
has "shipped check.php still has the placeholder key" '^CHANGE_ME$' "$tmpkeyless"

echo; echo "== guard.sh scan / hunt / webcheck inside a Debian PHP container =="
out=$(docker exec p2sg-apache bash /guard/guard.sh scan); rc=$?
expect "scan flags unpatched PHP $PHP_OLD" 1 $rc
has "scan finds /usr/local/bin/php" '/usr/local/bin/php' "$out"
has "scan reports the fixed release" "PHP $PHP_OLD: below fixed release $PHP_NEW" "$out"
has "scan shows missing stopgaps" 'stopgaps not set in the default ini: session.upload_progress.enabled=On memory_limit=128M' "$out"
has "scan warns about the data rlimit on apache2" 'apache2: data size limited to 17179869184' "$out"
out=$(docker run --rm -v "$ROOT:/guard:ro" php:$PHP_NEW-cli bash /guard/guard.sh scan)
has "scan accepts $PHP_NEW" "PHP $PHP_NEW: at or above first fixed release $PHP_NEW" "$out"
out=$(docker exec p2sg-apache php -c /guard/rules/php.ini -r 'echo ini_get("memory_limit"), " ", ini_get("post_max_size"), " ", (int)ini_get("session.upload_progress.enabled");' 2>&1)
expect "rules/php.ini loads on PHP 8.3 without warnings" '-1 8M 0' "$out"

clean=$(docker exec p2sg-apache bash /guard/guard.sh hunt /var/www/html --days 1); rc=$?
expect "hunt on a clean container" 0 $rc
out=$(docker exec p2sg-apache bash /guard/guard.sh hunt /nonexistent)
has "hunt looks back to 2026-10-17 by default" "Cron changed in the last $(( ($(date +%s) - $(date -d 2026-10-17 +%s)) / 86400 + 1 )) day" "$out"
docker exec p2sg-apache sh -c "mkdir -p /tmp/w && echo '<?php eval(base64_decode(\$_POST[1]));' > /tmp/w/shell.php && cp /tmp/w/shell.php /tmp/x.php"
docker exec p2sg-apache sh -c "echo '<?php shell_exec(\"sh -c \\\"sleep 20\\\"\");' > /tmp/spawn.php"
docker exec -d p2sg-apache php -S 127.0.0.1:9999 -t /tmp
sleep 1; docker exec -d p2sg-apache sh -c 'curl -s --max-time 25 http://127.0.0.1:9999/spawn.php'
docker exec -d p2sg-apache sh -c 'echo "[pool www] child 99 exited on signal 11 (SIGSEGV) after 1.0 seconds from start" >> /var/log/php-fpm.log'
docker exec -d p2sg-apache sh -c 'echo "PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 65536 bytes) in Unknown on line 0" >> /var/log/php-fpm.log'
sleep 2
out=$(docker exec p2sg-apache bash /guard/guard.sh hunt /tmp/w --days 1); rc=$?
expect "hunt flags the planted indicators" 1 $rc
has "hunt: shell spawned by PHP" 'sh under php' "$out"
has "hunt: worker crash in logs" 'SIGSEGV' "$out"
has "hunt: out-of-memory before any script ran" 'out-of-memory during request startup' "$out"
has "hunt: PHP file in /tmp" '/tmp/x.php' "$out"
has "hunt: webshell pattern" 'webshell-like.*|/tmp/w/shell.php' "$out"

out=$(docker exec -u root p2sg-apache bash -c 'mkdir -p /tmp/wr && /guard/guard.sh webcheck /tmp/wr && grep -c "^.KEY = .[0-9a-f]\{48\}.;" /tmp/wr/p2sg-*.php && grep -c "CHANGE_ME" /tmp/wr/p2sg-*.php')
has "webcheck installs a random 48-hex key and keeps the placeholder guard" $'^1\n1$' "$(tail -2 <<<"$out")"

echo; echo "== --json =="
js() { docker exec -i p2sg-apache php -r '$j = json_decode(stream_get_contents(STDIN), true); if (!is_array($j)) { echo "INVALID"; exit; } echo $j["exit"], "\n"; foreach ($j["findings"] as $f) echo $f["level"], " ", str_replace("\n", " ", $f["message"]), "\n";'; }
out=$(docker exec p2sg-apache bash /guard/guard.sh scan --json | js)
has "scan --json is valid JSON with exit 1" '^1$' "$(head -1 <<<"$out")"
has "scan --json carries the verdict" "^bad PHP $PHP_OLD: below fixed release $PHP_NEW" "$out"
out=$(docker exec p2sg-apache bash /guard/guard.sh hunt /tmp/w --days 1 --json | js)
has "hunt --json keeps the evidence lines" '^bad found: .*/tmp/x.php' "$out"

echo; echo "== guard.sh images =="
mkdir -p "$WORK/img/app" "$WORK/img/k8s" "$WORK/img/node_modules/x"
printf 'FROM php:%s-fpm AS base\nFROM docker.io/library/php:%s-apache\nFROM php:8.2-fpm-alpine\nFROM php:7.4-apache\n' $PHP_OLD $PHP_NEW > "$WORK/img/app/Dockerfile"
printf 'services:\n  web:\n    image: "bitnami/php-fpm:8.4.20-debian-12-r0"\n' > "$WORK/img/compose.yaml"
printf -- '- image: myreg.io/team/php:%s\n' $PHP_NEW > "$WORK/img/k8s/dep.yml"
echo 'FROM php:5.6' > "$WORK/img/node_modules/x/Dockerfile"
out=$(./guard.sh images "$WORK/img"); rc=$?
expect "images exits 1 on an old tag" 1 $rc
has "images: pinned old tag" "PHP $PHP_OLD: below fixed release $PHP_NEW" "$out"
has "images: registry path and fixed tag" "myreg.io/team/php:$PHP_NEW" "$out"
has "images: moving tag is a warning" 'php:8.2-fpm-alpine: moving tag' "$out"
has "images: EOL branch" 'php:7.4-apache: branch 7.4 is end-of-life' "$out"
has "images: non-official php-fpm image" 'PHP 8.4.20: below fixed release 8.4.27' "$out"
expect "images skips node_modules" 0 "$(grep -c 'php:5.6' <<<"$out")"
printf 'FROM php:%s-cli\n' $PHP_NEW > "$WORK/img-ok"; mkdir -p "$WORK/img2"; mv "$WORK/img-ok" "$WORK/img2/Dockerfile"
./guard.sh images "$WORK/img2" >/dev/null; expect "images exits 0 when every tag is fixed" 0 $?
./guard.sh images "$WORK/no-such-dir" >/dev/null 2>&1; expect "images fails on a missing path" 2 $?
# Alpine: busybox grep/find, and the oldest Bash we claim
alp=$(docker run --rm -v "$ROOT:/guard:ro" -v "$WORK/img:/img:ro" bash:4.0 bash /guard/guard.sh images /img); rc=$?
expect "images on busybox + Bash 4.0 finds the same tags" "$(grep -c '\[' <<<"$out")|1" "$(grep -c '\[' <<<"$alp")|$rc"
docker run --rm -v "$ROOT:/guard:ro" bash:4.0 sh -c "mkdir -p /srv/w && echo '<?php eval(base64_decode(\$_POST[1]));' > /srv/w/s.php && bash /guard/guard.sh hunt /srv/w --days 1" > "$WORK/alp-hunt"
has "hunt on busybox finds the webshell" '/srv/w/s.php' "$(cat "$WORK/alp-hunt")"

echo; echo "== guard.sh fix / undo: official FPM image behind nginx =="
run --name p2sg-fixfpm -v "$WORK/www:/var/www/html:ro" -v "$ROOT:/guard:ro" php:$PHP_OLD-fpm
sed 's/p2sg-fpm:9000/p2sg-fixfpm:9000/' "$WORK/nginx-open.conf" > "$WORK/nginx-fix.conf"
run --name p2sg-nginx-fix -p 18087:80 -v "$WORK/www:/var/www/html:ro" -v "$WORK/nginx-fix.conf:/etc/nginx/conf.d/default.conf:ro" nginx:alpine
for _ in $(seq 60); do curl -s -o /dev/null "http://127.0.0.1:18087/check.php?probe=1" && break; sleep 1; done
web() { curl -s "http://127.0.0.1:18087/check.php?key=$KEY"; }
has "before fix: FPM serves upload_progress On" 'session.upload_progress.enabled +On' "$(web)"

out=$(docker exec p2sg-fixfpm bash /guard/guard.sh fix); rc=$?
expect "fix without --apply is a dry run (exit 1)" 1 $rc
has "fix plans the ini drop-in" 'write /usr/local/etc/php/conf.d/99-php2shell-guard.ini' "$out"
has "fix plans the pool drop-in for pool www" 'write /usr/local/etc/php-fpm.d/zz-php2shell-guard.conf \(pools: www\)' "$out"
expect "dry run writes nothing" 0 "$(docker exec p2sg-fixfpm sh -c 'ls /usr/local/etc/php/conf.d/99-* /usr/local/etc/php-fpm.d/zz-php2* 2>/dev/null | wc -l')"
out=$(docker exec -u www-data p2sg-fixfpm bash /guard/guard.sh fix --apply 2>&1); rc=$?
expect "fix --apply refuses without root" 2 $rc

# a fake apachectl that only fails once our file exists: the write must be rolled back
docker exec p2sg-fixfpm sh -c 'printf "#!/bin/sh\n[ -f /usr/local/etc/php/conf.d/99-php2shell-guard.ini ] && { echo boom; exit 1; }\necho Syntax OK\n" > /usr/local/bin/apachectl && chmod +x /usr/local/bin/apachectl'
out=$(docker exec p2sg-fixfpm bash /guard/guard.sh fix --apply); rc=$?
expect "fix --apply rolls back when a config test changes" 1 $rc
has "rollback says why" 'rolled back' "$out"
expect "rollback leaves no drop-in behind" 0 "$(docker exec p2sg-fixfpm sh -c 'ls /usr/local/etc/php/conf.d/99-* /usr/local/etc/php-fpm.d/zz-php2* 2>/dev/null | wc -l')"
docker exec p2sg-fixfpm rm /usr/local/bin/apachectl

out=$(docker exec p2sg-fixfpm bash /guard/guard.sh fix --apply); rc=$?
expect "fix --apply succeeds" 0 $rc
has "fix --apply checks the config" 'config tests unchanged' "$out"
has "fix --apply asks for a restart without systemd" 'restart every PHP worker' "$out"
expect "CLI sees the stopgaps" '-1 0' "$(docker exec p2sg-fixfpm php -r 'echo ini_get("memory_limit"), " ", (int)ini_get("session.upload_progress.enabled");')"
docker kill -s USR2 p2sg-fixfpm >/dev/null; sleep 2
out=$(web)
has "after fix + reload: FPM serves upload_progress Off" 'session.upload_progress.enabled +Off' "$out"
has "after fix + reload: FPM serves memory_limit -1" 'memory_limit +-1$' "$out"
expect "after fix: the memory_limit note is gone" 0 "$(grep -c 'memory_limit=-1 via' <<<"$out")"
first=$(docker exec p2sg-fixfpm cat /usr/local/etc/php-fpm.d/zz-php2shell-guard.conf)
docker exec p2sg-fixfpm bash /guard/guard.sh fix --apply >/dev/null; rc=$?
expect "fix --apply twice is fine" 0 $rc
expect "second run does not stack pool sections" "$first" "$(docker exec p2sg-fixfpm cat /usr/local/etc/php-fpm.d/zz-php2shell-guard.conf)"

docker exec p2sg-fixfpm sh -c 'echo "memory_limit = 64M" > /usr/local/etc/php/conf.d/99-php2shell-guard.ini.keep'
out=$(docker exec p2sg-fixfpm bash /guard/guard.sh undo); rc=$?
expect "undo succeeds" 0 $rc
has "undo removes the ini drop-in" 'removed /usr/local/etc/php/conf.d/99-php2shell-guard.ini' "$out"
has "undo removes the pool drop-in" 'removed /usr/local/etc/php-fpm.d/zz-php2shell-guard.conf' "$out"
expect "undo leaves other files alone" 1 "$(docker exec p2sg-fixfpm sh -c 'ls /usr/local/etc/php/conf.d/*.keep | wc -l')"
docker exec p2sg-fixfpm sh -c 'printf "memory_limit = 64M\n" > /usr/local/etc/php/conf.d/99-php2shell-guard.ini'
out=$(docker exec p2sg-fixfpm bash /guard/guard.sh undo)
has "undo keeps a same-named file it did not write" 'nothing to remove' "$out"
docker exec p2sg-fixfpm sh -c 'rm /usr/local/etc/php/conf.d/99-php2shell-guard.ini*'
docker kill -s USR2 p2sg-fixfpm >/dev/null; sleep 2
has "after undo + reload: FPM back to upload_progress On" 'session.upload_progress.enabled +On' "$(web)"

out=$(docker run --rm -v "$ROOT:/guard:ro" php:$PHP_NEW-cli bash /guard/guard.sh fix --apply); rc=$?
expect "fix on patched PHP $PHP_NEW does nothing" 0 $rc
has "fix on patched PHP says so" 'no unpatched PHP binary found' "$out"

echo; echo "== guard.sh fix / undo: Ubuntu packages (one conf.d per SAPI, distro backports) =="
run --name p2sg-ubuntu -v "$ROOT:/guard:ro" ubuntu:24.04 sleep 600
if docker exec -e DEBIAN_FRONTEND=noninteractive p2sg-ubuntu sh -c 'apt-get update -qq && apt-get install -y -qq php8.3-fpm libapache2-mod-php8.3' >/dev/null 2>&1; then
    CL=/usr/share/doc/php8.3-common/changelog.Debian.gz
    # pretend the package carries the fix, then that it does not
    docker exec p2sg-ubuntu sh -c "{ echo '  * Fix CVE-2026-109618 and CVE-2026-109619'; zcat $CL; } | gzip > /tmp/cl && mv /tmp/cl $CL"
    out=$(docker exec p2sg-ubuntu bash /guard/guard.sh fix --apply); rc=$?
    expect "fix: a distro backport counts as patched" 0 $rc
    has "fix: nothing to do on a backported package" 'no unpatched PHP binary found' "$out"
    docker exec p2sg-ubuntu sh -c "zcat $CL | grep -v 'CVE-2026-10961[89]' | gzip > /tmp/cl && mv /tmp/cl $CL"
    out=$(docker exec p2sg-ubuntu bash /guard/guard.sh fix --apply); rc=$?
    expect "fix --apply on Ubuntu packages" 0 $rc
    for s in cli fpm apache2; do has "fix writes the $s conf.d" "wrote /etc/php/8.3/$s/conf.d/99-php2shell-guard.ini" "$out"; done
    has "fix writes the Ubuntu pool drop-in" 'wrote /etc/php/8.3/fpm/pool.d/zz-php2shell-guard.conf' "$out"
    has "php-fpm8.3 accepts the pool drop-in" 'memory_limit.*-1' "$(docker exec p2sg-ubuntu php-fpm8.3 -tt 2>&1 | grep -i 'memory_limit')"
    out=$(docker exec p2sg-ubuntu bash /guard/guard.sh undo)
    expect "undo removes all four Ubuntu drop-ins" 4 "$(grep -c 'removed ' <<<"$out")"
else
    echo "FAIL  apt-get install php8.3-fpm in ubuntu:24.04 (network?)"; FAILS=$((FAILS+1))
fi

echo; [[ $FAILS == 0 ]] && echo "ALL PASSED" || echo "$FAILS FAILED"
exit $((FAILS > 0))
