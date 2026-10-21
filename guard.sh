#!/usr/bin/env bash
# php2shell-guard: defensive checks for CVE-2026-109618 / CVE-2026-109619 ("php2shell").
# Read-only except `webcheck`, which copies check.php into a webroot you name.
set -uo pipefail

VERSION=0.1.0
CVES="CVE-2026-109618|CVE-2026-109619"
RELEASE_DATE="2026-10-21"   # PHP emergency release day; any later upstream release in a branch includes the fix

# First upstream release of each branch with the fix. Empty = not published yet,
# then `scan` asks php.net (skip with --offline). Keep in sync with check.php.
declare -A FIXED=([8.2]="" [8.3]="" [8.4]="" [8.5]="")

if [[ -t 1 ]]; then R=$'\e[31m' G=$'\e[32m' Y=$'\e[33m' B=$'\e[1m' N=$'\e[0m'; else R="" G="" Y="" B="" N=""; fi
bad()  { echo "  ${R}[!!]${N} $*"; FOUND=1; }
warn() { echo "  ${Y}[??]${N} $*"; }
ok()   { echo "  ${G}[ok]${N} $*"; }
hdr()  { echo; echo "${B}== $* ==${N}"; }
FOUND=0

usage() {
cat <<EOF
php2shell-guard $VERSION  -  checks for CVE-2026-109618 / CVE-2026-109619

  guard.sh scan [--offline]          find every PHP binary/container, verdict per version,
                                     distro backport check, upload_progress settings
  guard.sh test URL [URL...]         send harmless POST variants, verify your edge rule
                                     blocks multipart before PHP (best with check.php?probe=1)
  guard.sh hunt [WEBROOT...] [--days N]
                                     look for signs of compromise: shells spawned by PHP,
                                     worker crashes, new PHP files, webshell patterns, cron
  guard.sh webcheck WEBROOT          copy check.php with a random key, print the URL

Exit code 1 when something needs attention.
EOF
}

# ---------- versions ----------

declare -A ONLINE=()
online_fixed() { # branch -> prints fixed version if php.net has a release on/after RELEASE_DATE
    local br=$1 json ver date d m y pre months=JanFebMarAprMayJunJulAugSepOctNovDec
    json=$(curl -fsS --max-time 10 "https://www.php.net/releases/index.php?json&version=$br" 2>/dev/null) || return 1
    ver=$(grep -oE '"version":"[0-9.]+"' <<<"$json" | tail -1 | cut -d'"' -f4)
    date=$(grep -oE '"date":"[^"]+"' <<<"$json" | head -1 | cut -d'"' -f4)   # "21 Oct 2026"
    read -r d m y <<<"$date"; pre=${months%%"$m"*}
    [[ -n $ver && -n $y && ${#pre} -lt 36 ]] || return 1
    printf -v date '%04d-%02d-%02d' "$y" $(( ${#pre} / 3 + 1 )) "$((10#$d))"
    # shortcut: uses the latest release, so a later bugfix release raises the bar; that only errs on the safe side.
    [[ $date < $RELEASE_DATE ]] || echo "$ver"
}

verdict() { # version -> one line verdict, sets FOUND on bad
    local v=$1 br=${1%.*} fx
    fx=${FIXED[$br]-}
    if [[ -z ${FIXED[$br]+x} ]]; then
        bad "PHP $v: branch $br is end-of-life, no official fix expected. Upgrade or take it off the internet."; return
    fi
    if [[ -z $fx && $OFFLINE == 0 ]]; then
        [[ -n ${ONLINE[$br]+x} ]] || ONLINE[$br]=$(online_fixed "$br" || echo "?")
        fx=${ONLINE[$br]}
        [[ $fx == "?" ]] && { warn "PHP $v: could not reach php.net; fixed version unknown. Treat as vulnerable."; FOUND=1; return; }
    fi
    if [[ -z $fx ]]; then
        bad "PHP $v: fix not released yet for $br. Use the edge rules in rules/ until it is."
    elif [[ $(printf '%s\n%s\n' "$fx" "$v" | sort -V | head -1) == "$fx" ]]; then
        ok "PHP $v: at or above first fixed release $fx"
    else
        bad "PHP $v: below fixed release $fx (unless your distro backported it, see below)"
    fi
}

php_bins() {
    local p d
    {
        IFS=: read -ra d <<<"$PATH"
        for p in "${d[@]}"; do
            [[ $p == /mnt/* ]] && continue   # WSL Windows drives: slow, and php.exe is out of scope
            printf '%s\n' "$p"/php "$p"/php[0-9]* "$p"/php-cgi* "$p"/php-fpm* "$p"/lsphp*
        done
        for p in /usr/bin/php* /usr/sbin/php-fpm* /usr/local/bin/php* /usr/local/sbin/php-fpm* \
                 /opt/cpanel/ea-php*/root/usr/{bin/php,bin/php-cgi,sbin/php-fpm} \
                 /opt/plesk/php/*/{bin/php,bin/php-cgi,sbin/php-fpm} /opt/remi/php*/root/usr/{bin/php,sbin/php-fpm} \
                 /opt/alt/php*/usr/bin/{php,php-cgi} /usr/local/lsws/lsphp*/bin/lsphp /usr/local/php*/bin/php \
                 /www/server/php/*/bin/php /www/server/php/*/sbin/php-fpm; do
            echo "$p"
        done
    } | while read -r p; do [[ -f $p && -x $p ]] && echo "$p"; done | grep -vE '(config|ize|dbg)[0-9.]*$' | while read -r p; do readlink -f "$p"; done | sort -u
}

bin_version() { "$1" -v 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1; }

cmd_scan() {
    OFFLINE=0; [[ ${1:-} == --offline ]] && OFFLINE=1
    hdr "PHP binaries on this host"
    local b v any=0
    while read -r b; do
        [[ -n $b ]] || continue
        v=$(bin_version "$b"); [[ -n $v ]] || continue
        any=1; echo "  $b"; verdict "$v"
    done < <(php_bins)
    [[ $any == 1 ]] || warn "no PHP binary found in PATH or common panel paths (mod_php only? use check.php)"

    if command -v docker >/dev/null && docker ps -q 2>/dev/null | grep -q .; then
        hdr "Running containers"
        local id name c=0
        while read -r id name; do
            v=$(docker exec "$id" php -r 'echo PHP_VERSION;' 2>/dev/null) || continue
            c=1; echo "  container $name"; verdict "$v"
        done < <(docker ps --format '{{.ID}} {{.Names}}')
        [[ $c == 1 ]] || echo "  no running container has php in PATH"
    fi

    hdr "Distro backports (fix without a version bump)"
    local f pkg hit=0
    for f in /usr/share/doc/php[0-9]*-common/changelog.Debian.gz; do   # other php8.x-* doc dirs symlink here
        [[ -f $f ]] || continue
        if zgrep -qE "$CVES" "$f"; then ok "$(basename "$(dirname "$f")"): changelog mentions the CVEs"; else warn "$(basename "$(dirname "$f")"): no CVE in changelog yet"; fi
        hit=1
    done
    if command -v rpm >/dev/null; then
        while read -r pkg; do
            if rpm -q --changelog "$pkg" 2>/dev/null | grep -qE "$CVES"; then ok "$pkg: changelog mentions the CVEs"; else warn "$pkg: no CVE in changelog yet"; fi
            hit=1
        done < <(rpm -qa --qf '%{NAME}\n' 2>/dev/null | grep -E '^(ea-|alt-)?php[0-9]*(-php)?-common$' | sort -u)
    fi
    [[ $hit == 1 ]] || echo "  no Debian/RPM PHP packages found (source build, panel or container: version check above applies)"

    hdr "session.upload_progress.enabled (reported attack path, not an official root cause)"
    while read -r b; do
        [[ -n $b ]] || continue
        v=$("$b" -i 2>/dev/null | grep -m1 '^session.upload_progress.enabled' | awk -F'=> ' '{print $NF}')
        [[ -n $v ]] || continue
        if [[ ${v,,} == on ]]; then warn "$b: On (CLI/FPM default ini; web pools may override)"; else ok "$b: $v"; fi
    done < <(php_bins | grep -v cgi)
    local overrides
    overrides=$(grep -rsniE 'session\.upload_progress\.enabled' /etc/php* /etc/opt /usr/local/etc /opt/cpanel/ea-php*/root/etc /etc/apache2 /etc/httpd 2>/dev/null | grep -v ':[[:space:]]*;' | head -20)
    [[ -n $overrides ]] && { echo "  explicit settings found:"; sed 's/^/    /' <<<"$overrides"; }
    echo "  The web SAPI value is the one that counts: check it with check.php (guard.sh webcheck)."

    [[ $FOUND == 0 ]] && { echo; ok "nothing flagged"; }
    return $FOUND
}

# ---------- test ----------

probe() { # url curl-args... -> prints "status|body"
    local out
    out=$(curl -sS -o - -w '\n%{http_code}' --max-time 15 -H 'Expect:' "${@:2}" "$1" 2>/dev/null)
    printf '%s|%s' "${out##*$'\n'}" "${out%$'\n'*}"
}

reached_parser() { # body -> 0 if PHP saw a multipart content type (PHP lowercases up to ; , or space)
    local ct
    ct=$(grep -o 'P2SG_PHP_EXECUTED.*' <<<"$1" | sed 's/.* ct=//')
    ct=${ct,,}; ct=${ct%%[;, ]*}
    [[ $ct == multipart/form-data ]]
}

cmd_test() {
    [[ $# -gt 0 ]] || { usage; return 2; }
    local url bd=p2sgBoundary
    local body=$'--'$bd$'\r\nContent-Disposition: form-data; name="t"\r\n\r\nx\r\n--'$bd$'--\r\n'
    for url in "$@"; do
        hdr "$url"
        local r st b
        r=$(probe "$url" --data 't=x'); st=${r%%|*}; b=${r#*|}
        if [[ $st =~ ^2 ]]; then ok "url-encoded POST allowed ($st)$(grep -q P2SG_PHP_EXECUTED <<<"$b" && echo ', PHP executed')"
        else warn "url-encoded POST got $st: rule may be too broad, or the URL is wrong"; fi

        local name ct
        local -a variants=(
            "multipart (curl -F)|"
            "upper case|MULTIPART/FORM-DATA; boundary=$bd"
            "no space before boundary|multipart/form-data;boundary=$bd"
            "comma separator|multipart/form-data, boundary=$bd"
            "trailing space|multipart/form-data ; boundary=$bd"
            "chunked body|multipart/form-data; boundary=$bd"
            "duplicate header (multipart first)|multipart/form-data; boundary=$bd"
            "duplicate header (multipart last)|multipart/form-data; boundary=$bd"
        )
        local i
        for i in "${variants[@]}"; do
            name=${i%%|*}; ct=${i#*|}
            case $name in
                "multipart (curl -F)") r=$(probe "$url" -F 't=x') ;;
                "chunked body") r=$(probe "$url" -H "Content-Type: $ct" -H 'Transfer-Encoding: chunked' --data-binary "$body") ;;
                "duplicate header (multipart first)") r=$(probe "$url" -H "Content-Type: $ct" -H "Content-Type: text/plain" --data-binary "$body") ;;
                "duplicate header (multipart last)") r=$(probe "$url" -H "Content-Type: text/plain" -H "Content-Type: $ct" --data-binary "$body") ;;
                *) r=$(probe "$url" -H "Content-Type: $ct" --data-binary "$body") ;;
            esac
            st=${r%%|*}; b=${r#*|}
            if grep -q P2SG_PHP_EXECUTED <<<"$b"; then
                if reached_parser "$b"; then bad "$name: reached PHP as multipart ($st)"; else ok "$name: reached PHP but not as multipart ($st)"; fi
            elif [[ $st =~ ^4 ]]; then ok "$name: blocked ($st)"
            elif [[ $st == 000 ]]; then warn "$name: connection failed/reset (blocked or broken?)"
            else bad "$name: not blocked ($st)"; fi
        done
    done
    echo
    echo "  Passing means the multipart entry path is filtered for these URLs only. It is not proof the CVEs are fixed: patch PHP."
    return $FOUND
}

# ---------- hunt ----------

cmd_hunt() {
    local days=3 roots=() a
    while [[ $# -gt 0 ]]; do
        case $1 in --days) days=$2; shift 2 ;; *) roots+=("$1"); shift ;; esac
    done
    if [[ ${#roots[@]} -eq 0 ]]; then
        for a in /var/www /srv/www /usr/share/nginx/html /home/*/public_html /home/*/www /www/wwwroot; do [[ -d $a ]] && roots+=("$a"); done
    fi
    [[ $EUID -ne 0 ]] && warn "not root: some processes, logs and webroots may be hidden"

    hdr "Processes spawned by PHP / web server"
    local web='^(php|php-fpm.*|php-cgi.*|lsphp.*|httpd|apache2|litespeed|lshttpd)$'
    local sus='^(sh|bash|dash|zsh|ash|ksh|csh|tcsh|busybox|python[0-9.]*|perl|ruby|lua|nc|ncat|netcat|socat|telnet|curl|wget|whoami|id|uname|base64|xmrig|kinsing)$'
    declare -A pp cm ar
    local pid ppid comm args
    while read -r pid ppid comm args; do pp[$pid]=$ppid; cm[$pid]=$comm; ar[$pid]=$args; done < <(ps -eo pid=,ppid=,comm=,args= 2>/dev/null)
    local n=0 p depth
    for pid in "${!cm[@]}"; do
        [[ ${cm[$pid]} =~ $sus ]] || continue
        p=${pp[$pid]}; depth=0
        while [[ -n $p && $p != 0 && $p != 1 && $depth -lt 8 ]]; do
            if [[ ${cm[$p]:-} =~ $web ]]; then
                # mail() and piped logs legitimately run `sh -c sendmail|rotatelogs`; still shown, just not as an alert
                if [[ ${ar[$pid]} =~ (sendmail|rotatelogs|cronolog) ]]; then warn "pid $pid ${cm[$pid]} under ${cm[$p]}($p): ${ar[$pid]:0:160}"
                else bad "pid $pid ${cm[$pid]} under ${cm[$p]}($p): ${ar[$pid]:0:160}"; fi
                n=1; break
            fi
            p=${pp[$p]:-}; depth=$((depth+1))
        done
    done
    for pid in "${!ar[@]}"; do
        [[ ${ar[$pid]} =~ (/dev/tcp/|/dev/udp/|mkfifo|fsockopen|(^|[ /])(ba|da|z)?sh\ -i( |$)|nc\ .*-e\ |socat\ .*exec) ]] && { bad "pid $pid reverse-shell-like command: ${ar[$pid]:0:160}"; n=1; }
    done
    [[ $n == 0 ]] && ok "none right now (one-shot view; for live monitoring see Neo23x0/process-watcher)"

    hdr "PHP worker crashes (memory-corruption exploits often crash workers first)"
    local logs=() l
    for l in /var/log/php*fpm*.log /var/log/php-fpm/*.log /var/log/apache2/error.log* /var/log/httpd/error_log* /usr/local/apache/logs/error_log /usr/local/lsws/logs/error.log /var/log/nginx/error.log*; do
        [[ -f $l ]] && logs+=("$l")
    done
    local crashes=""
    [[ ${#logs[@]} -gt 0 ]] && crashes=$(zgrep -hE 'SIGSEGV|SIGBUS|SIGABRT|signal 11|signal 6|signal 7|Segmentation fault|zend_mm_heap corrupted' "${logs[@]}" 2>/dev/null | tail -10)
    command -v journalctl >/dev/null && crashes+=$(journalctl -q --no-pager --since "-${days} days" 2>/dev/null | grep -E '(php|httpd|apache2).*(SIGSEGV|signal 11|segfault|Segmentation fault)' | tail -10)
    if [[ -n $crashes ]]; then bad "crash lines found (last 10 per source):"; sed 's/^/      /' <<<"$crashes"
    else ok "no crash lines in ${#logs[@]} log file(s)$(command -v journalctl >/dev/null && echo ' or journal')"; fi

    hdr "PHP files in temp dirs"
    local tmpphp
    tmpphp=$(find /tmp /var/tmp /dev/shm -xdev -type f \( -iname '*.php*' -o -iname '*.phtml' -o -iname '.*.php' \) 2>/dev/null | head -20)
    if [[ -n $tmpphp ]]; then bad "found:"; sed 's/^/      /' <<<"$tmpphp"; else ok "none"; fi

    hdr "Webroots: ${roots[*]:-(none found, pass a path)}"
    if [[ ${#roots[@]} -gt 0 ]]; then
        local recent shells
        recent=$(find "${roots[@]}" -xdev -type f \( -iname '*.php*' -o -iname '*.phtml' -o -iname '*.phar' -o -name '.user.ini' -o -name '.htaccess' \) -mtime "-$days" 2>/dev/null | head -50)
        if [[ -n $recent ]]; then warn "changed in the last $days day(s) (review; deploys also show up here):"; sed 's/^/      /' <<<"$recent"; else ok "no PHP/.htaccess/.user.ini changes in the last $days day(s)"; fi
        shells=$(grep -rlsE --include='*.php*' --include='*.phtml' --include='*.inc' \
            -e 'eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin|\$_(GET|POST|REQUEST|COOKIE|SERVER))' \
            -e '(system|passthru|shell_exec|exec|popen|proc_open|assert|create_function)[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE|SERVER)' \
            -e '\$_(GET|POST|REQUEST|COOKIE)\[[^]]*\][[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE)' \
            "${roots[@]}" 2>/dev/null | head -30)
        if [[ -n $shells ]]; then bad "webshell-like patterns:"; sed 's/^/      /' <<<"$shells"; else ok "no common webshell patterns"; fi
    fi

    hdr "Cron changed in the last $days day(s)"
    local cr
    cr=$(find /etc/crontab /etc/cron.* /var/spool/cron /var/spool/cron/crontabs -type f -mtime "-$days" 2>/dev/null | head -20)
    if [[ -n $cr ]]; then warn "review:"; sed 's/^/      /' <<<"$cr"; else ok "none"; fi

    echo
    [[ $FOUND == 1 ]] && echo "  If anything above is real: isolate the host, keep web/PHP logs, then patch and rebuild."
    return $FOUND
}

# ---------- webcheck ----------

cmd_webcheck() {
    local root=${1:-} here key name
    [[ -d $root ]] || { echo "usage: guard.sh webcheck WEBROOT" >&2; return 2; }
    here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
    [[ -f $here/check.php ]] || { echo "check.php not found next to guard.sh" >&2; return 2; }
    key=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
    name="p2sg-$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n').php"
    sed "s/^\$KEY = 'CHANGE_ME';/\$KEY = '$key';/" "$here/check.php" > "$root/$name"
    chmod 644 "$root/$name"
    echo "Installed $root/$name"
    echo "Open:   https://YOUR-SITE/$name?key=$key"
    echo "Probe:  guard.sh test https://YOUR-SITE/$name?probe=1"
    echo "Remove when done:  rm '$root/$name'"
}

case ${1:-} in
    scan) shift; cmd_scan "$@" ;;
    test) shift; cmd_test "$@" ;;
    hunt) shift; cmd_hunt "$@" ;;
    webcheck) shift; cmd_webcheck "$@" ;;
    -v|--version) echo "$VERSION" ;;
    *) usage; [[ -z ${1:-} || $1 == -h || $1 == --help ]] && exit 0 || exit 2 ;;
esac
