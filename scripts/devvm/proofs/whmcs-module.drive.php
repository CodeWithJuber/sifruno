<?php
/**
 * Runs the Sifruno WHMCS module's functions on the dev VM against the real
 * panel and broker. `proof.sh whmcs-module` runs it through
 * whmcs-module.guest.sh with the VM's lsphp CLI; WHMCS itself is replaced by
 * integrations/whmcs/tests/stubs.php. The token comes from a file and the
 * WordPress password lives only in this process; neither is printed.
 *   php whmcs-module.drive.php DIR PORT CA_FILE TOKEN_FILE DOMAIN
 * DIR holds modules/ and tests/stubs.php; the panel serves HTTPS on
 * 127.0.0.1:PORT. Exits with the number of failed checks.
 */

declare(strict_types=1);

[, $dir, $port, $ca, $tokenFile, $domain] = $argv + array_fill(0, 6, '');
require $dir . '/tests/stubs.php';
require $dir . '/modules/servers/sifruno/sifruno.php';

$fails = 0;
function check(string $name, bool $ok, string $detail = ''): void
{
    global $fails;
    echo ($ok ? 'PASS' : 'FAIL') . '  ' . $name . (!$ok && $detail !== '' ? ' (' . $detail . ')' : '') . "\n";
    if (!$ok) {
        $fails++;
    }
}

/**
 * Asks OpenLiteSpeed on this VM for the site: [status, headers, body].
 */
function site(string $domain, string $path = '/', ?array $form = null): array
{
    $handle = curl_init('http://127.0.0.1' . $path);
    $options = [CURLOPT_HTTPHEADER => ['Host: ' . $domain], CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true, CURLOPT_TIMEOUT => 60];
    if ($form !== null) {
        $options[CURLOPT_POSTFIELDS] = http_build_query($form);
        $options[CURLOPT_COOKIE] = 'wordpress_test_cookie=WP%20Cookie%20check';
    }
    curl_setopt_array($handle, $options);
    $out = (string) curl_exec($handle);
    $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
    $split = (int) curl_getinfo($handle, CURLINFO_HEADER_SIZE);
    curl_close($handle);
    return [$status, substr($out, 0, $split), substr($out, $split)];
}

/** The site's answer settles after a web server reload; ask a few times. */
function siteAnswers(string $domain, callable $expected): bool
{
    for ($i = 0; $i < 30; $i++) {
        if ($expected(site($domain))) {
            return true;
        }
        sleep(2);
    }
    return false;
}

$token = trim((string) file_get_contents($tokenFile));
$server = ['host' => '127.0.0.1', 'port' => (int) $port, 'token' => $token, 'ca' => $ca];
$service = SifrunoTestWHMCS::service(1);
$params = static fn (array $over = []): array => SifrunoTestWHMCS::params($service, array_replace($server, $over), $domain, 'owner@proof.test');
$wrongToken = 'sfr_' . rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
$messages = [];
$wordpress = static fn (array $answer): bool => $answer[0] === 200 && str_contains($answer[2], $domain) && str_contains($answer[2], 'wp-content');

echo "## TestConnection over HTTPS\n";
$r = sifruno_TestConnection($params());
$messages[] = $r['error'];
check('TestConnection passes with the API token, verifying the panel\'s self-signed certificate', $r['success'] === true, $r['error']);
$r = sifruno_TestConnection($params(['token' => $wrongToken]));
$messages[] = $r['error'];
check('a wrong token gets the panel\'s 401 invalid_token, explained', $r['success'] === false && str_contains($r['error'], 'HTTP 401 invalid_token'), $r['error']);
$r = sifruno_TestConnection($params(['ca' => '']));
$messages[] = $r['error'];
check('without the certificate file the panel\'s self-signed certificate is refused', $r['success'] === false && str_contains($r['error'], 'certificate could not be verified'), $r['error']);

echo "## CreateAccount\n";
$r = sifruno_CreateAccount($params());
$messages[] = $r;
check('CreateAccount starts the New website wizard for ' . $domain, $r === 'success', $r);
$shown = '';
$until = time() + 20 * 60;
do {
    $fields = sifruno_AdminServicesTabFields($params());
    $messages[] = implode("\n", $fields);
    $status = html_entity_decode($fields['Sifruno website'] ?? '', ENT_QUOTES, 'UTF-8');
    if ($status !== $shown) {
        echo '  admin tab: ' . $status . "\n";
        $shown = $status;
    }
    if (!str_starts_with($status, 'Being created')) {
        break;
    }
    sleep(10);
} while (time() < $until);
check('the job finished and the admin tab shows the website live', $status === 'Live: ' . $domain, $status);
check('the account ID is saved on the service', SifrunoSite::validId($service->serviceProperties->get(SifrunoPanel::ACCOUNT_FIELD)));
check('the service holds the WordPress username and a 32-character password', $service->username !== '' && strlen($service->password) === 32);
check('the site serves WordPress', siteAnswers($domain, $wordpress));
[$code, $headers] = site($domain, '/wp-login.php', ['log' => $service->username, 'pwd' => $service->password, 'wp-submit' => 'Log In', 'testcookie' => '1', 'redirect_to' => 'http://' . $domain . '/wp-admin/']);
check('the service\'s username and password sign in to WordPress', $code === 302 && preg_match('/^Set-Cookie: wordpress_logged_in_/mi', $headers) === 1, 'HTTP ' . $code);

echo "## SuspendAccount and UnsuspendAccount\n";
$r = sifruno_SuspendAccount($params());
$messages[] = $r;
check('SuspendAccount succeeds', $r === 'success', $r);
check('the suspended site answers 403', siteAnswers($domain, static fn (array $answer): bool => $answer[0] === 403));
$r = sifruno_UnsuspendAccount($params());
$messages[] = $r;
check('UnsuspendAccount succeeds', $r === 'success', $r);
check('the site serves WordPress again', siteAnswers($domain, $wordpress));

echo "## TerminateAccount\n";
$r = sifruno_TerminateAccount($params());
$messages[] = $r;
check('TerminateAccount deletes the website', $r === 'success', $r);
check('the domain no longer serves WordPress', siteAnswers($domain, static fn (array $answer): bool => !str_contains($answer[2], 'wp-content')));
$fields = sifruno_AdminServicesTabFields($params());
$messages[] = implode("\n", $fields);
check('the admin tab says the panel has no website for it', ($fields['Sifruno website'] ?? '') === SifrunoSite::html('The panel has no website for ' . $domain . '.'), $fields['Sifruno website'] ?? '');

echo "## Secrets\n";
$captured = json_encode(['logs' => array_map(static function (array $l): array {
    unset($l['replace']);
    return $l;
}, SifrunoTestWHMCS::$logs), 'messages' => $messages], JSON_UNESCAPED_SLASHES);
$secrets = array_filter(['the API token' => $token, 'the wrong token' => $wrongToken, 'the WordPress password' => $service->password], static fn (string $s): bool => $s !== '');
$leaks = array_keys(array_filter($secrets, static fn (string $s): bool => str_contains($captured, $s)));
check('no token or password is in what logModuleCall received (' . count(SifrunoTestWHMCS::$logs) . ' entries) or in any message', $leaks === [], implode(', ', $leaks));
exit($fails);
