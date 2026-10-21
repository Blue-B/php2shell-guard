#!/usr/bin/env bash
# End-to-end tests: real Apache, Nginx, Caddy, HAProxy, ModSecurity in Docker, each in front of PHP.
# Usage: tests/run.sh   (needs docker; uses ports 18081-18086; cleans up after itself)
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

expect() { # description expected-exit actual-exit
    if [[ $2 == "$3" ]]; then echo "PASS  $1"; else echo "FAIL  $1 (expected exit $2, got $3)"; FAILS=$((FAILS+1)); fi
}
has() { # description pattern text
    if grep -qE -- "$2" <<<"$3"; then echo "PASS  $1"; else echo "FAIL  $1 (no match for: $2)"; echo "$3" | sed 's/^/      /' | head -20; FAILS=$((FAILS+1)); fi
}

# webroot: keyed check.php, plus a subdir with .user.ini turning upload progress off
mkdir -p "$WORK/www/ui"
sed "s/^\$KEY = 'CHANGE_ME';/\$KEY = '$KEY';/" check.php > "$WORK/www/check.php"
cp "$WORK/www/check.php" "$WORK/www/ui/check.php"
printf 'session.upload_progress.enabled = 0\n' > "$WORK/www/ui/.user.ini"
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
mkdir -p "$WORK/apache"; cp check.php "$WORK/apache/check.php"; cp rules/apache.htaccess "$WORK/apache/.htaccess"
sed -i "s/^\$KEY = 'CHANGE_ME';/\$KEY = '$KEY';/" "$WORK/apache/check.php"; chmod -R a+rX "$WORK/apache"

docker network create $NET >/dev/null
run() { docker run -d --network $NET "$@" >/dev/null || { echo "docker run failed: $*"; exit 2; }; }
run --name p2sg-fpm -v "$WORK/www:/var/www/html:ro" php:8.3-fpm-alpine
run --name p2sg-nginx-open -p 18081:80 -v "$WORK/www:/var/www/html:ro" -v "$WORK/nginx-open.conf:/etc/nginx/conf.d/default.conf:ro" nginx:alpine
run --name p2sg-nginx-guard -p 18082:80 -v "$WORK/www:/var/www/html:ro" -v "$WORK/nginx-guard.conf:/etc/nginx/conf.d/default.conf:ro" nginx:alpine
run --name p2sg-caddy -p 18083:80 -v "$WORK/www:/var/www/html:ro" -v "$WORK/Caddyfile:/etc/caddy/Caddyfile:ro" caddy:alpine
run --name p2sg-haproxy -p 18084:80 -v "$WORK/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro" haproxy:alpine
run --name p2sg-apache -p 18085:80 -v "$WORK/apache:/var/www/html:ro" -v "$ROOT:/guard:ro" php:8.3-apache \
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

echo; echo "== check.php =="
out=$(curl -s -w ' %{http_code}' "http://127.0.0.1:18081/check.php")
has "check.php refuses without key" '403$' "$out"
out=$(curl -s "http://127.0.0.1:18081/check.php?key=wrong")
has "check.php refuses wrong key" 'Forbidden' "$out"
out=$(curl -s "http://127.0.0.1:18081/check.php?key=$KEY")
has "check.php reports version and PENDING verdict" 'verdict +PENDING' "$out"
has "check.php sees upload_progress On by default" 'session.upload_progress.enabled +On' "$out"
out=$(curl -s "http://127.0.0.1:18081/ui/check.php?key=$KEY&format=json")
has "check.php sees .user.ini turning upload_progress Off (FPM)" '"session.upload_progress.enabled":"Off"' "$out"
tmpkeyless=$(sed -n "s/^\$KEY = '\(.*\)';/\1/p" check.php)
has "shipped check.php still has the placeholder key" '^CHANGE_ME$' "$tmpkeyless"

echo; echo "== guard.sh scan / hunt / webcheck inside a Debian PHP container =="
out=$(docker exec p2sg-apache bash /guard/guard.sh scan --offline); rc=$?
expect "scan flags unpatched PHP 8.3 (offline)" 1 $rc
has "scan finds /usr/local/bin/php" '/usr/local/bin/php' "$out"
has "scan reports pending fix" 'fix not released yet for 8.3' "$out"
out=$(docker exec p2sg-apache bash /guard/guard.sh scan)
has "scan online lookup gives a verdict" '(fix not released yet|below fixed release|at or above first fixed)' "$out"

clean=$(docker exec p2sg-apache bash /guard/guard.sh hunt /var/www/html --days 1); rc=$?
expect "hunt on a clean container" 0 $rc
docker exec p2sg-apache sh -c "mkdir -p /tmp/w && echo '<?php eval(base64_decode(\$_POST[1]));' > /tmp/w/shell.php && cp /tmp/w/shell.php /tmp/x.php"
docker exec p2sg-apache sh -c "echo '<?php shell_exec(\"sh -c \\\"sleep 20\\\"\");' > /tmp/spawn.php"
docker exec -d p2sg-apache php -S 127.0.0.1:9999 -t /tmp
sleep 1; docker exec -d p2sg-apache sh -c 'curl -s --max-time 25 http://127.0.0.1:9999/spawn.php'
docker exec -d p2sg-apache sh -c 'echo "[pool www] child 99 exited on signal 11 (SIGSEGV) after 1.0 seconds from start" >> /var/log/php-fpm.log'
sleep 2
out=$(docker exec p2sg-apache bash /guard/guard.sh hunt /tmp/w --days 1); rc=$?
expect "hunt flags the planted indicators" 1 $rc
has "hunt: shell spawned by PHP" 'sh under php' "$out"
has "hunt: worker crash in logs" 'SIGSEGV' "$out"
has "hunt: PHP file in /tmp" '/tmp/x.php' "$out"
has "hunt: webshell pattern" 'webshell-like.*|/tmp/w/shell.php' "$out"

out=$(docker exec -u root p2sg-apache bash -c 'mkdir -p /tmp/wr && /guard/guard.sh webcheck /tmp/wr && grep -c "^.KEY = .[0-9a-f]\{48\}.;" /tmp/wr/p2sg-*.php && grep -c "CHANGE_ME" /tmp/wr/p2sg-*.php')
has "webcheck installs a random 48-hex key and keeps the placeholder guard" $'^1\n1$' "$(tail -2 <<<"$out")"

echo; [[ $FAILS == 0 ]] && echo "ALL PASSED" || echo "$FAILS FAILED"
exit $((FAILS > 0))
