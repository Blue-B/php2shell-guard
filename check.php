<?php
// php2shell-guard web check. Runs on PHP 5.2+ (no short arrays, no closures).
// Reports what the *web* SAPI really uses; CLI `php -i` can differ.
// Delete this file when you are done.

// Set a long random key, then open: check.php?key=YOUR_KEY  (add &format=json for JSON)
// `guard.sh webcheck <webroot>` copies this file with a random key for you.
$KEY = 'CHANGE_ME';

// First upstream release of each branch that fixes CVE-2026-109618/109619 (PHP, 21 Oct 2026).
$FIXED = array('8.2' => '8.2.35', '8.3' => '8.3.36', '8.4' => '8.4.27', '8.5' => '8.5.12');

header('Content-Type: text/plain; charset=utf-8');
header('Cache-Control: no-store');
header('X-Robots-Tag: noindex');

// Probe mode for `guard.sh test`: no key needed, reveals only what the request itself sent.
if (isset($_GET['probe'])) {
    $ct = isset($_SERVER['CONTENT_TYPE']) ? $_SERVER['CONTENT_TYPE'] : '';
    echo 'P2SG_PHP_EXECUTED post=' . count($_POST) . ' files=' . count($_FILES) . ' ct=' . str_replace(array("\r", "\n"), ' ', $ct) . "\n";
    exit;
}

if ($KEY === 'CHANGE_ME' || strlen($KEY) < 16 || !isset($_GET['key']) || (string)$_GET['key'] !== $KEY) {
    header('HTTP/1.1 403 Forbidden');
    echo "Forbidden. Set \$KEY in this file (16+ chars) and pass ?key=...\n";
    exit;
}

$v = PHP_VERSION;
$branch = implode('.', array_slice(explode('.', $v), 0, 2));

if (isset($FIXED[$branch])) {
    $verdict = version_compare($v, $FIXED[$branch], '>=') ? 'PATCHED' : 'VULNERABLE';
    $why = 'first fixed upstream release for ' . $branch . ' is ' . $FIXED[$branch];
} else {
    $verdict = 'EOL';
    $why = in_array($branch, array('7.4', '8.0', '8.1'), true)
        ? 'branch ' . $branch . ' is end-of-life; no official release. Only a vendor/LTS package or PHP\'s source backport fixes it. Upgrade if you can'
        : 'branch ' . $branch . ' is end-of-life; no fix from PHP. Upgrade to a supported branch';
}

function p2sg_fmt($r) {
    return in_array(strtolower((string)$r), array('1', 'on', 'true', 'yes'), true) ? 'On' : ((string)$r === '' || $r === '0' || strtolower((string)$r) === 'off' ? 'Off' : (string)$r);
}

function p2sg_ini($name) {
    $r = ini_get($name);
    return $r === false ? 'n/a' : p2sg_fmt($r);
}

$notes = array();
$sapi = php_sapi_name();
$p2sg_all = function_exists('ini_get_all') ? ini_get_all() : array();

// Value in effect while PHP parses the request body. FPM/CGI/LSAPI apply .user.ini and ini_set() later,
// so there the php.ini/pool value (global_value) counts. mod_php applies vhost/.htaccess values early.
function p2sg_early($name) {
    global $p2sg_all, $notes, $sapi;
    $now = p2sg_ini($name);
    if ($sapi === 'apache2handler' || !isset($p2sg_all[$name]['global_value'])) return $now;
    $early = p2sg_fmt($p2sg_all[$name]['global_value']);
    if ($early !== $now) $notes[] = $name . ' is ' . $now . ' only per directory (.user.ini or ini_set()). On ' . $sapi . ' that applies too late: the php.ini/pool value ' . $early . ' is what counts. Set it in php.ini or the FPM pool (php_admin_value).';
    return $early;
}

$progress = extension_loaded('session') ? p2sg_early('session.upload_progress.enabled') : 'n/a (session extension not loaded)';

$checks = array(
    'php_version' => $v,
    'sapi' => $sapi,
    'verdict' => $verdict,
    'verdict_reason' => $why,
    'session.upload_progress.enabled' => $progress,
    'memory_limit' => p2sg_early('memory_limit'),
    'fatal_error_backtraces' => p2sg_early('fatal_error_backtraces'),
    'post_max_size' => p2sg_early('post_max_size'),
    'max_input_vars' => p2sg_early('max_input_vars'),
    'max_input_nesting_level' => p2sg_early('max_input_nesting_level'),
    'max_file_uploads' => p2sg_early('max_file_uploads'),
    'file_uploads' => p2sg_ini('file_uploads'),
    'enable_post_data_reading' => p2sg_ini('enable_post_data_reading'),
    'disable_functions' => (string)ini_get('disable_functions'),
    'loaded_php_ini' => function_exists('php_ini_loaded_file') ? (string)php_ini_loaded_file() : 'n/a',
);

if ($verdict !== 'PATCHED') {
    $notes[] = 'Patch PHP. Distro packages (Debian/Ubuntu/RHEL) may backport the fix without changing the version number: run `guard.sh scan` on the server.';
    if ($sapi === 'apache2handler' || $sapi === 'frankenphp') $notes[] = $sapi . ': highest risk. PHP confirms (mod_php) or expects (FrankenPHP) exploitation before any application code runs.';
    if ($checks['memory_limit'] !== '-1') $notes[] = 'CVE-2026-109618 stopgap until you patch: memory_limit=-1 via php_admin_value (pool or vhost), with a cgroup/container memory cap. Restore the normal limit after patching.';
    if ($checks['fatal_error_backtraces'] === 'On') $notes[] = 'CVE-2026-109619 stopgap until you patch: fatal_error_backtraces=0 (the confirmed PHP 8.5 exploit path).';
}
if ($progress === 'On') $notes[] = 'session.upload_progress.enabled is On. Turn it Off in php.ini, the pool or the vhost (CVE-2026-109619 stopgap; PHP suggests keeping it off after patching if you have no upload progress bars).';
if ($checks['file_uploads'] === 'On') $notes[] = 'file_uploads is On. Turning it Off does not guarantee PHP skips multipart parsing; use an edge rule if you do not need multipart.';
if ($verdict !== 'PATCHED') $notes[] = 'disable_functions does not stop memory-corruption RCE; do not rely on it.';

if (isset($_GET['format']) && $_GET['format'] === 'json' && function_exists('json_encode')) {
    header('Content-Type: application/json; charset=utf-8');
    $checks['notes'] = $notes;
    echo json_encode($checks);
    exit;
}

echo "php2shell-guard web check (CVE-2026-109618 / CVE-2026-109619)\n\n";
foreach ($checks as $k => $val) echo str_pad($k, 34) . $val . "\n";
echo "\n";
foreach ($notes as $n) echo "- " . $n . "\n";
echo "\nDelete this file when done.\n";
