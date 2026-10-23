#!/usr/bin/env bash
# php2shell-guard: defensive checks for CVE-2026-109618 / CVE-2026-109619 ("php2shell").
# Read-only except `webcheck` (copies check.php into a webroot you name) and `fix --apply` / `undo`
# (add or remove our own drop-in config files; existing files are never edited).
set -uo pipefail

VERSION=0.3.0
CVES="CVE-2026-109618|CVE-2026-109619"

# First upstream release of each branch with the fix (PHP, 21 Oct 2026). Keep in sync with check.php.
declare -A FIXED=([8.2]=8.2.35 [8.3]=8.3.36 [8.4]=8.4.27 [8.5]=8.5.12)

if [[ -t 1 ]]; then R=$'\e[31m' G=$'\e[32m' Y=$'\e[33m' B=$'\e[1m' N=$'\e[0m'; else R="" G="" Y="" B="" N=""; fi
FOUND=0 SECTION="" FINDINGS=()   # FINDINGS: "level|section|message", printed by --json
bad()  { echo "  ${R}[!!]${N} $*"; FOUND=1; FINDINGS+=("bad|$SECTION|$*"); }
warn() { echo "  ${Y}[??]${N} $*"; FINDINGS+=("warn|$SECTION|$*"); }
ok()   { echo "  ${G}[ok]${N} $*"; FINDINGS+=("ok|$SECTION|$*"); }
hdr()  { SECTION=$*; echo; echo "${B}== $* ==${N}"; }
detail() { # text -> indented lines; in JSON they join the last finding of this section
    sed 's/^/      /' <<<"$1"
    local n=$((${#FINDINGS[@]} - 1))
    if [[ $n -ge 0 && ${FINDINGS[n]#*|} == "$SECTION|"* ]]; then FINDINGS[n]+=$'\n'"$1"; else FINDINGS+=("info|$SECTION|$1"); fi
}

json_str() {
    local s=$1
    s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\n'/\\n}; s=${s//$'\r'/\\r}; s=${s//$'\t'/\\t}
    printf '"%s"' "$(printf '%s' "$s" | LC_ALL=C tr -d '\001-\037')"   # other control characters (ps output can carry them)
}

print_json() { # command exit-code -> one JSON object with every finding
    local f sep="" lvl sec
    printf '{"tool":"php2shell-guard","version":"%s","command":%s,"host":%s,"exit":%s,"findings":[' \
        "$VERSION" "$(json_str "$1")" "$(json_str "$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null)")" "$2"
    for f in "${FINDINGS[@]+"${FINDINGS[@]}"}"; do
        lvl=${f%%|*}; f=${f#*|}; sec=${f%%|*}
        printf '%s{"level":"%s","section":%s,"message":%s}' "$sep" "$lvl" "$(json_str "$sec")" "$(json_str "${f#*|}")"; sep=,
    done
    printf ']}\n'
}

usage() {
cat <<EOF
php2shell-guard $VERSION  -  checks for CVE-2026-109618 / CVE-2026-109619

  guard.sh scan                      find every PHP binary/container, verdict per version,
                                     distro backport check, stopgap settings, rlimits
  guard.sh test URL [URL...]         send harmless POST variants, verify your edge rule
                                     blocks multipart before PHP (best with check.php?probe=1)
  guard.sh hunt [WEBROOT...] [--days N]
                                     look for signs of compromise: shells spawned by PHP,
                                     worker crashes, pre-script OOM, new PHP files, webshell
                                     patterns, cron (default: back to 2026-10-17)
  guard.sh webcheck WEBROOT          copy check.php with a random key, print the URL
  guard.sh fix [--apply]             stopgaps for unpatched PHP: shows the plan, --apply writes
                                     drop-in files (existing config untouched), tests, reloads
  guard.sh undo                      remove those drop-in files again (after patching)
  guard.sh images [DIR...]           PHP image tags in Dockerfiles/compose/Kubernetes files (CI gate)

  --json                             scan, test, hunt, images: one JSON object on stdout

Exit code 1 when something needs attention.
EOF
}

# ---------- versions ----------

verdict() { # version -> one line verdict, sets FOUND and returns 1 unless patched
    local v=$1 br=${1%.*} fx
    fx=${FIXED[$br]-}
    if [[ -z $fx ]]; then
        case $br in
            7.4|8.0|8.1) bad "PHP $v: branch $br is end-of-life, no official release. Fixed only by a vendor/LTS package (see below) or PHP's source backport. Upgrade if you can." ;;
            *) bad "PHP $v: branch $br is end-of-life, no fix from PHP. Upgrade or take it off the internet." ;;
        esac
        return 1
    fi
    if [[ $(printf '%s\n%s\n' "$fx" "$v" | sort -V | head -1) == "$fx" ]]; then
        ok "PHP $v: at or above first fixed release $fx"
    else
        bad "PHP $v: below fixed release $fx (unless a distro package backported the fix)"; return 1
    fi
}

stopgaps() { # binary -> PHP's interim settings as its default ini has them (pools and vhosts can override)
    [[ $1 == *cgi* ]] && return   # php-cgi -i prints HTML
    local info k val msg="" risky=0
    info=$("$1" -i 2>/dev/null)
    for k in session.upload_progress.enabled memory_limit fatal_error_backtraces; do
        val=$(awk -F' => ' -v k="$k" '$1 == k {print $NF; exit}' <<<"$info")
        [[ -n $val ]] || continue
        msg+=" $k=$val"
        case $k=${val,,} in memory_limit=-1|*=off|*=0) ;; *) risky=1 ;; esac
    done
    [[ -n $msg ]] || return
    if [[ $risky == 1 ]]; then warn "stopgaps not set in the default ini:$msg (see rules/php.ini)"; else ok "default ini has the stopgaps:$msg"; fi
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
    hdr "PHP binaries on this host"
    local b v any=0
    while read -r b; do
        [[ -n $b ]] || continue
        v=$(bin_version "$b"); [[ -n $v ]] || continue
        any=1; echo "  $b"; verdict "$v" || stopgaps "$b"
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

    hdr "Stopgap settings in config files (until patched: upload_progress Off, memory_limit -1, 8.5 fatal_error_backtraces Off)"
    local overrides
    overrides=$(grep -rsniE 'session\.upload_progress\.enabled|memory_limit|fatal_error_backtraces' /etc/php* /etc/opt /usr/local/etc /opt/cpanel/ea-php*/root/etc /etc/apache2 /etc/httpd 2>/dev/null | grep -v ':[[:space:]]*;' | head -30)
    [[ -n $overrides ]] && { echo "  explicit settings found:"; detail "$overrides"; }
    echo "  The web SAPI value is the one that counts: check it with check.php (guard.sh webcheck)."
    echo "  On FPM/CGI/LSAPI, .user.ini and ini_set() apply too late to help; use php.ini, the pool or the vhost."

    hdr "Address-space/data rlimits on PHP workers (PHP: do not use them, allocation failure hits the bug)"
    local lims
    lims=$(ps -eo pid=,comm= 2>/dev/null | while read -r pid comm; do
        [[ $comm =~ ^(php-fpm.*|php-cgi.*|lsphp.*|httpd|apache2|frankenphp)$ ]] || continue
        awk -v c="$comm" '/^Max (address space|data size)/ && $4 != "unlimited" {print c ": " $2 " " $3 " limited to " $4 " bytes"}' "/proc/$pid/limits" 2>/dev/null
    done | sort -u)
    if [[ -n $lims ]]; then warn "set (use a cgroup/MemoryMax= cap instead of ulimit -v / RLIMIT_AS / RLIMIT_DATA):"; detail "$lims"
    else ok "none on running PHP/web workers"; fi

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
    # Amazon saw exploitation from 2026-10-17, four days before disclosure: look back at least that far.
    local days=$(( ($(date +%s) - $(date -d 2026-10-17 +%s)) / 86400 + 1 )) roots=() a
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

    hdr "PHP worker crashes and out-of-memory before any script ran (how exploit attempts show up)"
    local logs=() l
    for l in /var/log/php*.log /var/log/php/*.log /var/log/php-fpm/*.log /var/log/apache2/error.log* /var/log/httpd/error_log* /usr/local/apache/logs/error_log /usr/local/lsws/logs/error.log /var/log/nginx/error.log*; do
        [[ -f $l ]] && logs+=("$l")
    done
    # CVE-2026-109618 needs an OOM while PHP parses the request: logged "in Unknown on line 0", and FPM then
    # ends the child with exit code 70 (FPM_EXIT_SOFTWARE after a failed request startup).
    local crash_re='SIGSEGV|SIGBUS|SIGABRT|signal 11|signal 6|signal 7|Segmentation fault|zend_mm_heap corrupted' oom_re='exhausted.* in Unknown on line 0|exited with code 70 after'
    local crashes="" oom=""
    if [[ ${#logs[@]} -gt 0 ]]; then
        crashes=$(zgrep -hE "$crash_re" "${logs[@]}" 2>/dev/null | tail -10)
        oom=$(zgrep -hE "$oom_re" "${logs[@]}" 2>/dev/null | tail -10)
    fi
    if command -v journalctl >/dev/null; then
        local journal
        journal=$(journalctl -q --no-pager --since "-${days} days" 2>/dev/null | grep -E 'php|httpd|apache2')
        crashes+=$(grep -E 'SIGSEGV|signal 11|segfault|Segmentation fault' <<<"$journal" | tail -10)
        oom+=$(grep -E "$oom_re" <<<"$journal" | tail -10)
    fi
    local where="${#logs[@]} log file(s)$(command -v journalctl >/dev/null && echo ' or journal')"
    if [[ -n $crashes ]]; then bad "crash lines found (last 10 per source):"; detail "$crashes"
    else ok "no crash lines in $where"; fi
    if [[ -n $oom ]]; then bad "out-of-memory during request startup (last 10 per source):"; detail "$oom"
    else ok "no pre-script out-of-memory lines in $where"; fi

    hdr "PHP files in temp dirs"
    local tmpphp
    tmpphp=$(find /tmp /var/tmp /dev/shm -xdev -type f \( -iname '*.php*' -o -iname '*.phtml' -o -iname '.*.php' \) 2>/dev/null | head -20)
    if [[ -n $tmpphp ]]; then bad "found:"; detail "$tmpphp"; else ok "none"; fi

    hdr "Webroots: ${roots[*]:-(none found, pass a path)}"
    if [[ ${#roots[@]} -gt 0 ]]; then
        local recent shells
        recent=$(find "${roots[@]}" -xdev -type f \( -iname '*.php*' -o -iname '*.phtml' -o -iname '*.phar' -o -name '.user.ini' -o -name '.htaccess' \) -mtime "-$days" 2>/dev/null | head -50)
        if [[ -n $recent ]]; then warn "changed in the last $days day(s) (review; deploys also show up here):"; detail "$recent"; else ok "no PHP/.htaccess/.user.ini changes in the last $days day(s)"; fi
        # find picks the files: busybox grep (Alpine) has no --include and would silently find nothing
        shells=$(find "${roots[@]}" -xdev -type f \( -iname '*.php*' -o -iname '*.phtml' -o -iname '*.inc' \) -exec grep -lsE \
            -e 'eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin|\$_(GET|POST|REQUEST|COOKIE|SERVER))' \
            -e '(system|passthru|shell_exec|exec|popen|proc_open|assert|create_function)[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE|SERVER)' \
            -e '\$_(GET|POST|REQUEST|COOKIE)\[[^]]*\][[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE)' \
            {} + 2>/dev/null | head -30)
        if [[ -n $shells ]]; then bad "webshell-like patterns:"; detail "$shells"; else ok "no common webshell patterns"; fi
    fi

    hdr "Cron changed in the last $days day(s)"
    local cr
    cr=$(find /etc/crontab /etc/cron.* /var/spool/cron /var/spool/cron/crontabs -type f -mtime "-$days" 2>/dev/null | head -20)
    if [[ -n $cr ]]; then warn "review:"; detail "$cr"; else ok "none"; fi

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

# ---------- fix / undo ----------

INI_DROPIN=99-php2shell-guard.ini POOL_DROPIN=zz-php2shell-guard.conf MARK='; php2shell-guard drop-in'

backported() { # binary -> 0 if its distro package's changelog names the CVEs (fixed without a version bump)
    local p
    if p=$(dpkg-query -S "$1" 2>/dev/null | head -1) && [[ -n $p ]]; then zgrep -qE "$CVES" "/usr/share/doc/${p%%:*}/changelog.Debian.gz" 2>/dev/null
    elif p=$(rpm -qf "$1" 2>/dev/null) && [[ -n $p ]]; then rpm -q --changelog "$p" 2>/dev/null | grep -qE "$CVES"
    else return 1; fi
}

fix_targets() { # [unpatched] -> "ini DIR" and "pool INCLUDE-GLOB" lines (all PHP builds, or unpatched only)
    local b v d s conf inc dirs
    while read -r b; do
        [[ -n $b && $b != *cgi* ]] || continue   # php-cgi -i prints HTML; Debian's cgi conf.d is picked up as a sibling below
        v=$(bin_version "$b"); [[ -n $v ]] || continue
        [[ ${1-} == unpatched ]] && { (verdict "$v" >/dev/null) || backported "$b"; } && continue
        IFS=: read -ra dirs <<<"$("$b" -i 2>/dev/null | awk -F' => ' '$1 == "Scan this dir for additional .ini files" {print $2; exit}')"
        for d in "${dirs[@]+"${dirs[@]}"}"; do
            [[ -d $d ]] || continue
            echo "ini $d"
            # Debian/Ubuntu keep one conf.d per SAPI (cli, fpm, apache2, cgi), and mod_php has no binary to ask
            if [[ $d =~ ^/etc/php/[0-9.]+/[^/]+/conf\.d$ ]]; then for s in "${d%/*/conf.d}"/*/conf.d; do echo "ini $s"; done; fi
        done
        [[ $b == *fpm* ]] || continue
        conf=$("$b" -t 2>&1 | grep -oE 'configuration file [^ ]+' | head -1); conf=${conf#configuration file }
        [[ -f $conf ]] || continue
        while read -r inc; do
            # shortcut: a relative include is taken as relative to the conf file's grandparent (FPM's usual prefix)
            [[ $inc == /* ]] || inc=$(dirname "$(dirname "$conf")")/$inc
            # only where FPM will actually load a file with our name (glob match on purpose)
            # shellcheck disable=SC2053
            [[ -d ${inc%/*} && $POOL_DROPIN == ${inc##*/} ]] && echo "pool $inc"
        done < <(sed -nE 's/^[[:space:]]*include[[:space:]]*=[[:space:]]*(.*[^[:space:]])[[:space:]]*$/\1/p' "$conf")
    done < <(php_bins)
}

pool_names() { # include glob -> pool names defined by the files it loads, except our own
    local f
    for f in ${1%/*}/${1##*/}; do
        [[ -f $f && ${f##*/} != "$POOL_DROPIN" ]] && sed -nE 's/^[[:space:]]*\[([^]]+)\].*/\1/p' "$f"
    done | grep -vx global | sort -u
}

reload_php() {
    local u
    if [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null; then
        for u in $(systemctl list-units --type=service --state=active --no-legend --plain 'php*fpm*' 'apache2*' 'httpd*' 'lsws*' 'lshttpd*' 2>/dev/null | awk '{print $1}'); do
            if systemctl reload "$u" 2>/dev/null; then ok "reloaded $u"; else warn "could not reload $u: restart it"; fi
        done
    fi
    warn "restart every PHP worker not reloaded above (containers, panels, LiteSpeed), then check through the web server: guard.sh webcheck WEBROOT"
}

config_state() { # -> output of every config test we can run, compared before and after writing
    local b
    while read -r b; do
        case $b in
            *cgi*|*lsphp*) ;;   # no quiet config test (lsphp without a mode may start serving)
            *fpm*) "$b" -t 2>&1 | grep -v 'test is successful' | sed 's/^\[[^]]*\] //'; echo "$b -t exit ${PIPESTATUS[0]}" ;;
            *) "$b" -r '' 2>&1 ;;
        esac
    done < <(php_bins)
    for b in apache2ctl apachectl; do command -v $b >/dev/null && { $b -t 2>&1 | grep -v 'Syntax OK'; echo "$b -t exit ${PIPESTATUS[0]}"; break; }; done
}

cmd_fix() {
    local apply=0 t f names before after targets=() written=()
    [[ ${1-} == --apply ]] && apply=1
    [[ $apply == 1 && $EUID -ne 0 ]] && { echo "fix --apply needs root" >&2; return 2; }

    hdr "Stopgaps for unpatched PHP (CVE-2026-109618 / CVE-2026-109619)"
    mapfile -t targets < <(fix_targets unpatched | sort -u)
    if [[ ${#targets[@]} -eq 0 ]]; then
        ok "no unpatched PHP binary found (distro backports count as patched), nothing to do (mod_php only? use check.php). After patching, \`guard.sh undo\` removes earlier stopgaps"
        return 0
    fi
    echo "  Settings: session.upload_progress.enabled=Off, fatal_error_backtraces=Off, memory_limit=-1 (php_admin_value in FPM pools)"
    for t in "${targets[@]}"; do
        case $t in
            ini\ *) echo "  write ${t#ini }/$INI_DROPIN" ;;
            pool\ *) names=$(pool_names "${t#pool }"); [[ -n $names ]] && echo "  write $(dirname "${t#pool }")/$POOL_DROPIN (pools: $(echo $names))" ;;
        esac
    done
    warn "memory_limit=-1 lets one request use all RAM: cap the service instead (systemd MemoryMax=, container memory limit)"
    if command -v apache2 >/dev/null || command -v httpd >/dev/null; then
        warn "mod_php: applications can lower memory_limit again with ini_set(); put php_admin_value memory_limit -1 in the vhost"
    fi

    hdr "Patch (the real fix)"
    if compgen -G '/usr/share/doc/php[0-9]*-common' >/dev/null; then echo "  Debian/Ubuntu packages: apt-get update && apt-get install --only-upgrade 'php*'"
    elif command -v rpm >/dev/null && rpm -qa 2>/dev/null | grep -qE '^(ea-|alt-)?php[0-9]*(-php)?-common'; then
        echo "  RPM packages: $(command -v dnf >/dev/null && echo dnf upgrade || echo yum update) 'php*'"
    fi
    echo "  Docker official images and source builds: rebuild on a fixed tag (guard.sh images DIR finds old tags)."
    echo "  Control panels (cPanel EA, Plesk, aaPanel, CloudLinux alt-php): use the panel's PHP updater."

    if [[ $apply == 0 ]]; then
        echo; echo "  Dry run: nothing written. As root: guard.sh fix --apply"
        return 1
    fi

    hdr "Applying"
    before=$(config_state)
    for t in "${targets[@]}"; do
        case $t in
            ini\ *)
                f=${t#ini }/$INI_DROPIN
                printf '%s: stopgaps for CVE-2026-109618 / CVE-2026-109619 until PHP is patched.\n; Written by `guard.sh fix --apply`, removed by `guard.sh undo`. Reasons: rules/php.ini.\nsession.upload_progress.enabled = Off\nfatal_error_backtraces = Off\nmemory_limit = -1\n' "$MARK" > "$f" ;;
            pool\ *)
                names=$(pool_names "${t#pool }"); [[ -n $names ]] || continue
                f=$(dirname "${t#pool }")/$POOL_DROPIN
                { printf '%s: memory_limit=-1 that applications cannot lower. Removed by `guard.sh undo`.\n' "$MARK"
                  printf '[%s]\nphp_admin_value[memory_limit] = -1\n' $names; } > "$f" ;;
            *) continue ;;
        esac
        chmod 644 "$f"; written+=("$f"); ok "wrote $f"
    done
    after=$(config_state)
    if [[ $after != "$before" ]]; then
        rm -f "${written[@]}"
        bad "config tests changed after writing, rolled back:"; detail "$(diff <(echo "$before") <(echo "$after") | grep '^[<>]')"
        return 1
    fi
    ok "config tests unchanged (php -r, php-fpm -t, apachectl -t)"
    reload_php
    return 0
}

cmd_undo() {
    [[ $EUID -ne 0 ]] && { echo "undo needs root" >&2; return 2; }
    hdr "Removing php2shell-guard drop-ins"
    local t f n=0
    while read -r t; do
        case $t in ini\ *) f=${t#ini }/$INI_DROPIN ;; pool\ *) f=$(dirname "${t#pool }")/$POOL_DROPIN ;; *) continue ;; esac
        # only files we wrote: same name and our marker line
        if [[ -f $f ]] && grep -qF "$MARK" "$f"; then rm -f "$f" && ok "removed $f" && n=1; fi
    done < <(fix_targets | sort -u)
    if [[ $n == 1 ]]; then reload_php; else ok "nothing to remove"; fi
    return 0
}

# ---------- images ----------

cmd_images() {
    [[ $# -gt 0 ]] || set -- .
    local hit file ln img tag v any=0
    for file in "$@"; do [[ -e $file ]] || { echo "not found: $file" >&2; return 2; }; done   # a typo must not pass a CI gate
    hdr "PHP image tags under $*"
    # official php image and */php, */php-fpm, */php-apache images; shortcut: tags set through ARG/env variables are not resolved
    while IFS= read -r hit; do
        file=${hit%%:*}; hit=${hit#*:}; ln=${hit%%:*}; img=${hit#*:}; img=${img#[[:space:]\"\'=]}
        tag=${img##*:}; v=$(grep -oE '^[0-9]+\.[0-9]+(\.[0-9]+)?' <<<"$tag")
        any=1; echo "  $file:$ln  $img"
        if [[ $v =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then verdict "$v"
        elif [[ -n $v && -z ${FIXED[$v]-} ]]; then bad "$img: branch $v is end-of-life, no fix from PHP"
        else warn "$img: moving tag, fixed only if pulled after 21 Oct 2026: rebuild with --pull, or pin a fixed version"; fi
    done < <(find "$@" \( -name .git -o -name node_modules -o -name vendor \) -prune -o -type f \
                 \( -name '*Dockerfile*' -o -name '*.dockerfile' -o -name 'Containerfile*' -o -name '*.yml' -o -name '*.yaml' \) \
                 -exec grep -HnoE "(^|[[:space:]\"'=])([[:alnum:]._-]+/)*php(-fpm|-apache)?:[[:alnum:]][[:alnum:]._-]*" {} + 2>/dev/null)
    [[ $any == 1 ]] || ok "no PHP image tags found"
    return $FOUND
}

JSON=0 args=()
for a in "$@"; do if [[ $a == --json ]]; then JSON=1; else args+=("$a"); fi; done
set -- "${args[@]+"${args[@]}"}"
cmd=${1:-}
case $cmd in
    scan|test|hunt|webcheck|fix|undo|images) shift ;;
    -v|--version) echo "$VERSION"; exit 0 ;;
    *) usage; [[ -z $cmd || $cmd == -h || $cmd == --help ]] && exit 0 || exit 2 ;;
esac
if [[ $JSON == 1 && $cmd =~ ^(scan|test|hunt|images)$ ]]; then
    "cmd_$cmd" "$@" >/dev/null; rc=$?
    print_json "$cmd" "$rc"
    exit $rc
fi
"cmd_$cmd" "$@"
