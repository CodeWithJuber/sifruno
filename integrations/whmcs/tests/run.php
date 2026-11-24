<?php
/**
 * Runs every function of the Sifruno WHMCS module against the mock panel,
 * over HTTPS, with WHMCS's own functions replaced by stubs.php:
 *   php integrations/whmcs/tests/run.php
 * Needs the php CLI with curl, json and openssl, and the openssl command. It
 * starts php -S and two TLS proxies on free loopback ports, works in a new
 * temporary folder, prints PASS or FAIL per check and exits with the number
 * of failures. The token and passwords it makes are never printed.
 */

declare(strict_types=1);

require __DIR__ . '/stubs.php';
require __DIR__ . '/../modules/servers/sifruno/sifruno.php';

$work = sys_get_temp_dir() . '/sifruno-whmcs-' . bin2hex(random_bytes(6));
mkdir($work, 0700);
$processes = [];
register_shutdown_function(static function () use (&$processes, $work): void {
    foreach ($processes as $process) {
        proc_terminate($process);
        proc_close($process);
    }
    foreach (glob($work . '/*') ?: [] as $file) {
        unlink($file);
    }
    rmdir($work);
});

$failures = 0;
function check(string $name, bool $ok, string $detail = ''): void
{
    global $failures;
    echo ($ok ? 'PASS' : 'FAIL') . '  ' . $name . (!$ok && $detail !== '' ? ' (' . $detail . ')' : '') . "\n";
    if (!$ok) {
        $failures++;
    }
}

function newToken(): string
{
    return 'sfr_' . rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
}

function freePort(): int
{
    $socket = stream_socket_server('tcp://127.0.0.1:0');
    $name = stream_socket_get_name($socket, false);
    fclose($socket);
    return (int) substr($name, strrpos($name, ':') + 1);
}

function start(array $command, array $env, string $log): mixed
{
    $process = proc_open($command, [0 => ['file', '/dev/null', 'r'], 1 => ['file', $log, 'a'], 2 => ['file', $log, 'a']], $pipes, null, $env);
    if (!is_resource($process)) {
        fwrite(STDERR, 'cannot start ' . $command[0] . "\n");
        exit(1);
    }
    return $process;
}

function waitFor(int $port): void
{
    for ($i = 0; $i < 100; $i++) {
        $socket = @fsockopen('127.0.0.1', $port, $errno, $error, 0.2);
        if ($socket !== false) {
            fclose($socket);
            return;
        }
        usleep(50000);
    }
    fwrite(STDERR, "nothing listens on port $port\n");
    exit(1);
}

/** Makes a self-signed certificate like the panel's own: not a CA, for the given names. */
function certificate(string $work, string $name, string $altNames): array
{
    $cert = "$work/$name-cert.pem";
    $key = "$work/$name-key.pem";
    $process = proc_open(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-days', '1',
        '-subj', '/CN=sifruno-test', '-addext', 'subjectAltName=' . $altNames, '-addext', 'basicConstraints=critical,CA:FALSE',
        '-addext', 'keyUsage=digitalSignature', '-addext', 'extendedKeyUsage=serverAuth', '-keyout', $key, '-out', $cert],
        [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
    if (!is_resource($process) || proc_close($process) !== 0) {
        fwrite(STDERR, "openssl could not make a certificate\n");
        exit(1);
    }
    return [$cert, $key];
}

/** Reads or edits the mock panel's state under its lock. */
function mockState(?callable $edit = null): array
{
    global $work;
    $lock = fopen("$work/state.json", 'c+');
    flock($lock, LOCK_EX);
    $state = json_decode((string) stream_get_contents($lock), true) ?: [];
    $state += ['sites' => [], 'jobs' => [], 'requests' => [], 'bump' => []];
    if ($edit !== null) {
        $state = $edit($state);
        ftruncate($lock, 0);
        rewind($lock);
        fwrite($lock, json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        fflush($lock);
    }
    flock($lock, LOCK_UN);
    fclose($lock);
    return $state;
}

/** The requests the mock received from index $from on. */
function received(int $from): array
{
    return array_slice(mockState()['requests'], $from);
}

function siteFor(string $domain): ?array
{
    foreach (mockState()['sites'] as $site) {
        if ($site['domain'] === $domain) {
            return $site;
        }
    }
    return null;
}

/** Sends one raw request straight to php -S, to check what the mock enforces. */
function raw(int $port, string $token, string $path, string $contentType, string $body): array
{
    $handle = curl_init('http://127.0.0.1:' . $port . $path);
    curl_setopt_array($handle, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => $body, CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => ['Authorization: Bearer ' . $token, 'Content-Type: ' . $contentType]]);
    $out = (string) curl_exec($handle);
    $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
    curl_close($handle);
    return [$status, json_decode($out, true) ?: []];
}

$token = newToken();
$wrongToken = newToken();
[$goodCert, $goodKey] = certificate($work, 'panel', 'IP:127.0.0.1,DNS:localhost');
[$otherCert, $otherKey] = certificate($work, 'other', 'DNS:other.test');
$httpPort = freePort();
$env = ['PATH' => (string) getenv('PATH'), 'SIFRUNO_MOCK_STATE' => "$work/state.json", 'SIFRUNO_MOCK_TOKEN' => $token];
touch("$work/state.json");
$processes[] = start([PHP_BINARY, '-S', '127.0.0.1:' . $httpPort, __DIR__ . '/mock-panel.php'], $env, "$work/mock.log");
$tlsPort = freePort();
$processes[] = start([PHP_BINARY, __DIR__ . '/tls-proxy.php', (string) $tlsPort, $goodCert, $goodKey, (string) $httpPort], ['PATH' => (string) getenv('PATH')], "$work/proxy.log");
$otherPort = freePort();
$processes[] = start([PHP_BINARY, __DIR__ . '/tls-proxy.php', (string) $otherPort, $otherCert, $otherKey, (string) $httpPort], ['PATH' => (string) getenv('PATH')], "$work/proxy.log");
waitFor($httpPort);
waitFor($tlsPort);
waitFor($otherPort);

$server = ['host' => '127.0.0.1', 'port' => $tlsPort, 'token' => $token, 'ca' => $goodCert];
$messages = [];
$params = static fn (int $id, string $domain, array $over = []): array => array_replace(
    SifrunoTestWHMCS::params(SifrunoTestWHMCS::service($id), array_replace($server, $over), $domain, 'owner@example.com'),
    array_intersect_key($over, ['configoption1' => 1, 'clientsdetails' => 1]),
);

echo "## Module description\n";
$meta = sifruno_MetaData();
check('MetaData names the module and needs a server, on the panel\'s HTTPS port', $meta['DisplayName'] === 'Sifruno' && $meta['RequiresServer'] === true && $meta['DefaultSSLPort'] === '8443');
$options = sifruno_ConfigOptions();
check('ConfigOptions offers the PHP versions the wizard takes, 8.3 by default', ($options['PHP version']['Options'] ?? '') === '8.1,8.2,8.3,8.4' && $options['PHP version']['Default'] === '8.3');

echo "## TestConnection, the token and TLS\n";
$r = sifruno_TestConnection($params(1, 'shop.example.com'));
check('TestConnection passes with the token, verifying the panel\'s self-signed certificate from the Access Hash path', $r === ['success' => true, 'error' => ''], json_encode($r));
$last = mockState()['requests'];
check('it was an authenticated GET of /api/v1/websites/sites', end($last)['method'] === 'GET' && end($last)['path'] === '/api/v1/websites/sites' && end($last)['status'] === 200);

$r = sifruno_TestConnection($params(1, 'shop.example.com', ['token' => $wrongToken]));
$messages[] = $r['error'];
check('a wrong token fails with a plain message', $r['success'] === false && str_contains($r['error'], 'The panel refused the API token') && str_contains($r['error'], 'HTTP 401 invalid_token'), $r['error']);

$before = count(mockState()['requests']);
$r = sifruno_TestConnection($params(1, 'shop.example.com', ['token' => 'not-a-token']));
$messages[] = $r['error'];
check('a value that is not a token is refused before anything is sent', $r['success'] === false && str_contains($r['error'], 'does not hold a Sifruno API token') && count(mockState()['requests']) === $before, $r['error']);

$r = sifruno_TestConnection($params(1, 'shop.example.com', ['ca' => '']));
$messages[] = $r['error'];
check('without the CA file the self-signed certificate is refused: verification is on', $r['success'] === false && str_contains($r['error'], 'certificate could not be verified') && str_contains($r['error'], 'curl error 60'), $r['error']);

$r = sifruno_TestConnection($params(1, 'shop.example.com', ['port' => $otherPort, 'ca' => $otherCert]));
$messages[] = $r['error'];
check('a trusted certificate for another name is refused: the host name is checked', $r['success'] === false && str_contains($r['error'], 'certificate could not be verified'), $r['error']);

$r = sifruno_TestConnection($params(1, 'shop.example.com', ['ca' => 'panel-cert.pem']));
$messages[] = $r['error'];
check('an Access Hash that is not a full path to a readable file is refused', $r['success'] === false && str_contains($r['error'], 'Access Hash field is not the full path'), $r['error']);

echo "## CreateAccount\n";
$mark = count(mockState()['requests']);
$service = SifrunoTestWHMCS::service(1);
$r = sifruno_CreateAccount($params(1, 'shop.example.com'));
$messages[] = $r;
check('CreateAccount starts the wizard and returns success', $r === 'success', $r);
$sent = null;
foreach (received($mark) as $request) {
    if ($request['path'] === '/api/v1/websites/wordpress') {
        $sent = $request;
    }
}
check('it POSTed exactly the wizard\'s six keys', $sent !== null && array_keys($sent['body']) === ['domain', 'title', 'admin_user', 'admin_email', 'admin_password', 'php_version'] && $sent['status'] === 202);
check('with the domain, the client\'s email and the product\'s PHP version', $sent['body']['domain'] === 'shop.example.com' && $sent['body']['admin_email'] === 'owner@example.com' && $sent['body']['php_version'] === '8.3');
check('the generated password is 32 characters and is the service\'s Password in WHMCS', strlen($sent['body']['admin_password']) === 32 && $service->password === $sent['body']['admin_password']);
check('the WordPress admin username is the service\'s Username', $service->username !== '' && $service->username === $sent['body']['admin_user']);
$site = siteFor('shop.example.com');
check('the job ID and, once the job finished, the account ID are saved on the service', SifrunoSite::validId($service->serviceProperties->get(SifrunoPanel::JOB_FIELD)) && $site !== null && $service->serviceProperties->get(SifrunoPanel::ACCOUNT_FIELD) === $site['account_id']);
$logged = array_filter(SifrunoTestWHMCS::$logs, static fn (array $l): bool => str_starts_with((string) $l['request'], 'POST /api/v1/websites/wordpress'));
$entry = end($logged);
check('the module log shows the request with the password masked and lists the token and password to replace',
    $entry !== false && str_contains($entry['request'], '"admin_password":"********"') && in_array($token, $entry['replace'], true) && in_array($service->password, $entry['replace'], true));

$fields = sifruno_AdminServicesTabFields($params(1, 'shop.example.com'));
$messages[] = implode("\n", $fields);
check('AdminServicesTabFields shows the live website and its address', ($fields['Sifruno website'] ?? '') === 'Live: shop.example.com' && str_contains($fields['Website address'] ?? '', 'href="http://shop.example.com/"'), json_encode($fields));

$r = sifruno_CreateAccount($params(1, 'bad domain', []));
$messages[] = $r;
check('a service without a plain domain is refused before anything is sent', str_contains($r, 'not a plain domain name'), $r);
$r = sifruno_CreateAccount($params(7, 'php.example.com', ['configoption1' => '7.4']));
$messages[] = $r;
check('a PHP version the wizard does not offer is refused before anything is sent', str_contains($r, 'PHP version setting is not 8.1, 8.2, 8.3 or 8.4'), $r);

echo "## SuspendAccount and UnsuspendAccount\n";
$r = sifruno_SuspendAccount($params(1, 'shop.example.com'));
$messages[] = $r;
$site = siteFor('shop.example.com');
check('SuspendAccount suspends the website', $r === 'success' && $site['state'] === 'suspended' && $site['revision'] === 2, $r);

$mark = count(mockState()['requests']);
mockState(static function (array $s) use ($site): array {
    $s['bump'][$site['account_id']] = 1;
    return $s;
});
$r = sifruno_UnsuspendAccount($params(1, 'shop.example.com'));
$messages[] = $r;
$posts = array_values(array_filter(received($mark), static fn (array $q): bool => $q['method'] === 'POST'));
$site = siteFor('shop.example.com');
check('a change that lands between the read and the POST gets 409, and the retry with the new revision succeeds',
    $r === 'success' && array_column($posts, 'status') === [409, 200] && $site['state'] === 'active', $r . ' ' . json_encode(array_column($posts, 'status')));
check('the retry sent the revision the panel showed after the other change', ($posts[1]['body']['expected_revision'] ?? 0) === ($posts[0]['body']['expected_revision'] ?? 0) + 1);

$mark = count(mockState()['requests']);
mockState(static function (array $s) use ($site): array {
    $s['bump'][$site['account_id']] = 3;
    return $s;
});
$r = sifruno_SuspendAccount($params(1, 'shop.example.com'));
$messages[] = $r;
$posts = array_filter(received($mark), static fn (array $q): bool => $q['method'] === 'POST');
check('a website that keeps changing stops after three tries with the panel\'s reason', count($posts) === 3 && str_contains($r, 'This website changed after the page loaded it') && str_contains($r, 'HTTP 409') && siteFor('shop.example.com')['state'] === 'active', $r);

echo "## TerminateAccount\n";
$mark = count(mockState()['requests']);
$site = siteFor('shop.example.com');
$r = sifruno_TerminateAccount($params(1, 'shop.example.com'));
$messages[] = $r;
$delete = array_values(array_filter(received($mark), static fn (array $q): bool => str_ends_with($q['path'], '/delete')));
check('TerminateAccount deletes the website', $r === 'success' && siteFor('shop.example.com') === null, $r);
check('with confirm_domain and the current expected_revision', ($delete[0]['body'] ?? []) === ['confirm_domain' => 'shop.example.com', 'expected_revision' => $site['revision']]);
$r = sifruno_TerminateAccount($params(1, 'shop.example.com'));
$messages[] = $r;
check('a second terminate says the panel has no website for the domain', str_contains($r, 'The panel has no website for shop.example.com, so nothing changed'), $r);

echo "## A domain the panel does not have\n";
$r = sifruno_SuspendAccount($params(9, 'missing.example.com'));
$messages[] = $r;
check('Suspend for an unknown domain says so and changes nothing', str_contains($r, 'Could not suspend the website for missing.example.com. The panel has no website for missing.example.com'), $r);

echo "## A job that fails\n";
$r = sifruno_CreateAccount($params(2, 'fail-blog.example.com'));
$messages[] = $r;
check('CreateAccount reports a job that failed early, with what, why and what next', str_contains($r, 'Creating the website failed on the panel. The hosting account was not created.') && str_contains($r, 'Remove hosting accounts you no longer use') && str_contains($r, 'Technical details: job '), $r);
$r = sifruno_SuspendAccount($params(2, 'fail-blog.example.com'));
$messages[] = $r;
check('a later Suspend explains the failed job', str_contains($r, 'Creating the website failed on the panel'), $r);
$fields = sifruno_AdminServicesTabFields($params(2, 'fail-blog.example.com'));
$messages[] = implode("\n", $fields);
check('so does the admin tab', str_contains($fields['Sifruno website'], 'The hosting account was not created.'), json_encode($fields));

echo "## A job that outlasts CreateAccount's wait\n";
$started = microtime(true);
$r = sifruno_CreateAccount($params(3, 'slow-news.example.com'));
$messages[] = $r;
$took = microtime(true) - $started;
check('CreateAccount returns success while the job still runs, after at most its wait', $r === 'success' && $took >= SifrunoPanel::CREATE_WAIT && $took < SifrunoPanel::CREATE_WAIT + SifrunoPanel::POLL_EVERY + 5, $r . ' after ' . round($took, 1) . ' s');
check('the job ID is saved, the account ID not yet', SifrunoSite::validId(SifrunoTestWHMCS::service(3)->serviceProperties->get(SifrunoPanel::JOB_FIELD)) && SifrunoTestWHMCS::service(3)->serviceProperties->get(SifrunoPanel::ACCOUNT_FIELD) === null);
$fields = sifruno_AdminServicesTabFields($params(3, 'slow-news.example.com'));
$messages[] = implode("\n", $fields);
check('the admin tab shows the step it is on', ($fields['Sifruno website'] ?? '') === 'Being created (now: Create the hosting account)', json_encode($fields));
$r = sifruno_SuspendAccount($params(3, 'slow-news.example.com'));
$messages[] = $r;
check('Suspend meanwhile says the website is still being created', str_contains($r, 'The website is still being created on the panel'), $r);
$r = sifruno_CreateAccount($params(4, 'second.example.com'));
$messages[] = $r;
check('a second order meanwhile gets the panel\'s one-job-at-a-time answer', str_contains($r, 'Another website is being created right now') && str_contains($r, 'HTTP 409') && SifrunoTestWHMCS::service(4)->password === '', $r);
mockState(static function (array $s): array {
    foreach ($s['jobs'] as $id => $job) {
        if ($job['domain'] === 'slow-news.example.com') {
            $s['jobs'][$id]['release'] = true;
        }
    }
    return $s;
});
$r = sifruno_SuspendAccount($params(3, 'slow-news.example.com'));
$messages[] = $r;
$site = siteFor('slow-news.example.com');
check('once the job is done, Suspend finds the website through the job and saves its account ID', $r === 'success' && $site !== null && $site['state'] === 'suspended' && SifrunoTestWHMCS::service(3)->serviceProperties->get(SifrunoPanel::ACCOUNT_FIELD) === $site['account_id'], $r);

echo "## Panel refusals and WHMCS failures\n";
$r = sifruno_CreateAccount($params(5, 'slow-news.example.com'));
$messages[] = $r;
check('a domain that already has a website gets the panel\'s reason, and the service keeps no new password', str_contains($r, 'slow-news.example.com already belongs to the hosting account') && SifrunoTestWHMCS::service(5)->password === '', $r);
SifrunoTestWHMCS::$apiFails = true;
$r = sifruno_CreateAccount($params(6, 'saved.example.com'));
SifrunoTestWHMCS::$apiFails = false;
$messages[] = $r;
check('when WHMCS cannot save the login, the message says the website exists and what to do', str_contains($r, 'is being created, but WHMCS did not save its WordPress login') && str_contains($r, 'Do not run Create again'), $r);

echo "## The mock enforces the panel's strict JSON\n";
$account = siteFor('slow-news.example.com')['account_id'];
[$status, $problem] = raw($httpPort, $token, "/api/v1/websites/sites/$account/state", 'application/json', '{"state":"active","expected_revision":1,"extra":"x"}');
check('an unknown key is refused (422)', $status === 422 && str_contains($problem['detail'] ?? '', 'Send only state and expected_revision'));
[$status, $problem] = raw($httpPort, $token, "/api/v1/websites/sites/$account/state", 'application/json', '{"state":"active","state":"active","expected_revision":1}');
check('a repeated key is refused (422)', $status === 422 && str_contains($problem['detail'] ?? '', 'more than once'));
[$status, $problem] = raw($httpPort, $token, "/api/v1/websites/sites/$account/state", 'application/json', '{"state":"active","expected_revision":"1"}');
check('a revision sent as text is refused (422)', $status === 422 && ($problem['detail'] ?? '') === 'expected_revision must be a whole number.');
[$status, $problem] = raw($httpPort, $token, "/api/v1/websites/sites/$account/state", 'text/plain', '{"state":"active","expected_revision":1}');
check('a body that is not JSON by its content type is refused (415)', $status === 415 && ($problem['error'] ?? '') === 'invalid_request');
[$status, $problem] = raw($httpPort, $wrongToken, "/api/v1/websites/sites/$account/state", 'application/json', '{"state":"active","expected_revision":1}');
check('a wrong token is refused (401 invalid_token)', $status === 401 && ($problem['error'] ?? '') === 'invalid_token');

echo "## Secrets\n";
$secrets = ['the API token' => $token, 'the wrong token' => $wrongToken];
foreach (SifrunoTestWHMCS::$services as $id => $s) {
    if ($s->password !== '') {
        $secrets["service $id's password"] = $s->password;
    }
}
foreach (mockState()['requests'] as $request) {
    if (isset($request['body']['admin_password'])) {
        $secrets['a WordPress password the panel received'] = $request['body']['admin_password'];
    }
}
$captured = json_encode(['logs' => array_map(static function (array $l): array {
    unset($l['replace']);
    return $l;
}, SifrunoTestWHMCS::$logs), 'messages' => $messages], JSON_UNESCAPED_SLASHES);
$leaks = array_keys(array_filter($secrets, static fn (string $secret): bool => str_contains($captured, $secret)));
check('no token or password is in anything logModuleCall received (' . count(SifrunoTestWHMCS::$logs) . ' entries) or in any message (' . count($messages) . ')', $leaks === [], implode(', ', $leaks));
check('every log entry of a panel call lists the token to replace', array_filter(SifrunoTestWHMCS::$logs, static fn (array $l): bool => $l['request'] !== '' && !in_array($token, $l['replace'], true) && !in_array($wrongToken, $l['replace'], true)) === []);

echo $failures === 0 ? "All checks passed.\n" : "$failures check(s) failed.\n";
exit($failures);
