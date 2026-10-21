<?php
// php2shell-guard web check. Runs on PHP 5.2+ (no short arrays, no closures).
// Reports what the *web* SAPI really uses; CLI `php -i` can differ.
// Delete this file when you are done.

// Set a long random key, then open: check.php?key=YOUR_KEY  (add &format=json for JSON)
// `guard.sh webcheck <webroot>` copies this file with a random key for you.
$KEY = 'CHANGE_ME';

// First upstream release of each branch that fixes CVE-2026-109618/109619.
// Empty = not published yet. Update after the 2026-10-21 14:00 UTC release.
$FIXED = array('8.2' => '', '8.3' => '', '8.4' => '', '8.5' => '');

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

if (isset($FIXED[$branch]) && $FIXED[$branch] !== '') {
    $verdict = version_compare($v, $FIXED[$branch], '>=') ? 'PATCHED' : 'VULNERABLE';
    $why = 'first fixed upstream release for ' . $branch . ' is ' . $FIXED[$branch];
} elseif (isset($FIXED[$branch])) {
    $verdict = 'PENDING';
    $why = 'fixed versions not in this file yet; treat as vulnerable until updated';
} else {
    $verdict = 'EOL';
    $why = 'branch ' . $branch . ' is end-of-life; no official fix expected. Upgrade to a supported branch';
}

function p2sg_ini($name) {
    $r = ini_get($name);
    if ($r === false) return 'n/a';
    return in_array(strtolower((string)$r), array('1', 'on', 'true', 'yes'), true) ? 'On' : ((string)$r === '' || $r === '0' || strtolower((string)$r) === 'off' ? 'Off' : (string)$r);
}

$session = extension_loaded('session');
$progress = $session ? p2sg_ini('session.upload_progress.enabled') : 'n/a (session extension not loaded)';

$checks = array(
    'php_version' => $v,
    'sapi' => php_sapi_name(),
    'verdict' => $verdict,
    'verdict_reason' => $why,
    'session.upload_progress.enabled' => $progress,
    'file_uploads' => p2sg_ini('file_uploads'),
    'enable_post_data_reading' => p2sg_ini('enable_post_data_reading'),
    'disable_functions' => (string)ini_get('disable_functions'),
    'loaded_php_ini' => function_exists('php_ini_loaded_file') ? (string)php_ini_loaded_file() : 'n/a',
);

$notes = array();
if ($verdict !== 'PATCHED') $notes[] = 'Patch PHP. Distro packages (Debian/Ubuntu/RHEL) may backport the fix without changing the version number: run `guard.sh scan` on the server.';
if ($progress === 'On') $notes[] = 'session.upload_progress.enabled is On. If you do not use upload progress bars, turn it Off (see rules/php.ini). Reported attack path, not an official root cause.';
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
