<?php
/**
 * A stand-in for the Sifruno panel's API, for the module's tests only:
 *   SIFRUNO_MOCK_STATE=state.json SIFRUNO_MOCK_TOKEN=sfr_... php -S 127.0.0.1:PORT mock-panel.php
 *
 * It answers the routes the module uses and enforces what the real API
 * enforces there (internal/api, internal/operator): a bearer token, the
 * strict JSON body rules of prepareStrictJSON, expected_revision conflicts,
 * one running wizard job at a time, and problem JSON in both of the panel's
 * shapes. Its state is a JSON file the test runner reads and edits under the
 * same lock.
 *
 * A wizard job ends on the first read of it: a domain starting "fail-" fails
 * at the account step, one starting "slow-" keeps running until the runner
 * sets its "release" flag, and any other succeeds and becomes a website.
 */

declare(strict_types=1);

const WEBSITE_STALE = 'This website changed after the page loaded it, so nothing changed. Reload the page, check the website, then try again.';
const WEBSITE_NOT_FOUND = 'That website was not found. It may have been removed, or it was not made with New website.';
const NO_REVISION = "expected_revision must be the revision the website's entry had.";

/** The keys each POST takes, as wizardFields spells them: true for a whole number. */
const FIELDS = [
    'wordpress' => ['domain' => false, 'title' => false, 'admin_user' => false, 'admin_email' => false, 'admin_password' => false, 'php_version' => false],
    'state' => ['state' => false, 'expected_revision' => true],
    'delete' => ['confirm_domain' => false, 'expected_revision' => true],
];

$stateFile = (string) getenv('SIFRUNO_MOCK_STATE');
$token = (string) getenv('SIFRUNO_MOCK_TOKEN');
$method = $_SERVER['REQUEST_METHOD'];
$path = (string) parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

$lock = fopen($stateFile, 'c+');
flock($lock, LOCK_EX);
$state = json_decode((string) stream_get_contents($lock), true);
if (!is_array($state)) {
    $state = [];
}
$state += ['sites' => [], 'jobs' => [], 'requests' => [], 'bump' => []];

[$status, $headers, $body] = handle($state, $method, $path, $token);

$state['requests'][] = ['method' => $method, 'path' => $path, 'status' => $status, 'body' => json_decode((string) file_get_contents('php://input'), true)];
ftruncate($lock, 0);
rewind($lock);
fwrite($lock, json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
fflush($lock);
flock($lock, LOCK_UN);
fclose($lock);

http_response_code($status);
foreach ($headers as $header) {
    header($header);
}
header('Cache-Control: no-store');
echo $body;

/** @return array{0: int, 1: list<string>, 2: string} */
function handle(array &$state, string $method, string $path, string $token): array
{
    if (!str_starts_with($path, '/api/v1/websites')) {
        return [404, ['Content-Type: text/plain'], "404 page not found\n"];
    }
    $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if ($auth === '') {
        return operatorError(401, 'unauthorized', 'Operator session required');
    }
    if (!hash_equals('Bearer ' . $token, $auth)) {
        $refused = operatorError(401, 'invalid_token', 'The API token was not accepted. It may be mistyped, expired or revoked. Create a new token under Security, API tokens, and put it in the API client.');
        $refused[1][] = 'WWW-Authenticate: Bearer error="invalid_token"';
        return $refused;
    }

    if ($method === 'GET' && $path === '/api/v1/websites/sites') {
        $sites = array_values(array_map('website', $state['sites']));
        return json200(['sites' => $sites]);
    }
    if ($method === 'GET' && preg_match('#^/api/v1/websites/sites/([^/]+)$#', $path, $m) === 1) {
        $site = $state['sites'][$m[1]] ?? null;
        if ($site === null) {
            return humaError(404, WEBSITE_NOT_FOUND);
        }
        return json200(website($site) + ['php_versions' => ['8.1', '8.2', '8.3', '8.4']]);
    }
    if ($method === 'GET' && preg_match('#^/api/v1/websites/jobs/([^/]+)$#', $path, $m) === 1) {
        $job = $state['jobs'][$m[1]] ?? null;
        if ($job === null) {
            return humaError(404, 'That website job was not found. The panel keeps the newest 50 jobs.');
        }
        $state['jobs'][$m[1]] = advance($state, $job);
        return json200(['job' => $state['jobs'][$m[1]]]);
    }
    if ($method !== 'POST') {
        return [405, ['Allow: GET, HEAD'], ''];
    }
    if ($path === '/api/v1/websites/wordpress') {
        $route = 'wordpress';
    } elseif (preg_match('#^/api/v1/websites/sites/[a-f0-9]{32}/(state|delete)$#', $path, $m) === 1) {
        $route = $m[1];
    } else {
        return [405, ['Allow: GET, HEAD'], ''];
    }
    $in = strictJSON(FIELDS[$route], $refusal);
    if ($in === null) {
        return $refusal;
    }
    return match ($route) {
        'wordpress' => startWordPress($state, $in),
        'state' => setState($state, $path, $in),
        'delete' => deleteSite($state, $path, $in),
    };
}

/**
 * prepareStrictJSON: JSON content type, at most 4 KiB, one object holding
 * only the route's keys, each once, text as text and a revision as a whole
 * number. A missing key is the zero value, as Go decodes it.
 */
function strictJSON(array $fields, ?array &$refusal): ?array
{
    $type = strtolower(trim(explode(';', $_SERVER['CONTENT_TYPE'] ?? $_SERVER['HTTP_CONTENT_TYPE'] ?? '')[0]));
    if ($type !== 'application/json') {
        $refusal = operatorError(415, 'invalid_request', 'Send the request as JSON.');
        return null;
    }
    $raw = (string) file_get_contents('php://input');
    if (strlen($raw) > 4096) {
        $refusal = operatorError(413, 'invalid_request', 'The request is larger than 4 KiB.');
        return null;
    }
    $decoded = json_decode($raw, true);
    if (!str_starts_with(ltrim($raw), '{') || !is_array($decoded)) {
        $refusal = operatorError(400, 'invalid_request', 'The request must be one JSON object.');
        return null;
    }
    $names = array_keys($fields);
    foreach (topLevelKeys($raw) as $i => $key) {
        if (!in_array($key, $names, true)) {
            $last = array_pop($names);
            $refusal = operatorError(422, 'invalid_request', 'The request has a field this form does not use. Send only ' . ($names === [] ? $last : implode(', ', $names) . ' and ' . $last) . '.');
            return null;
        }
        if (in_array($key, array_slice(topLevelKeys($raw), 0, $i), true)) {
            $refusal = operatorError(422, 'invalid_request', 'The request has the field ' . $key . ' more than once.');
            return null;
        }
    }
    $in = [];
    foreach ($fields as $name => $whole) {
        $value = $decoded[$name] ?? null;
        if ($whole && $value !== null && !(is_int($value) && $value >= 0)) {
            $refusal = operatorError(422, 'invalid_request', $name . ' must be a whole number.');
            return null;
        }
        if (!$whole && $value !== null && !is_string($value)) {
            $refusal = operatorError(422, 'invalid_request', $name . ' must be text.');
            return null;
        }
        $in[$name] = $value ?? ($whole ? 0 : '');
    }
    return $in;
}

/**
 * The keys of a JSON object's top level, in order, repeats included. The
 * text is already known to be valid JSON.
 *
 * @return list<string>
 */
function topLevelKeys(string $raw): array
{
    $keys = [];
    $depth = 0;
    $n = strlen($raw);
    for ($i = 0; $i < $n; $i++) {
        $c = $raw[$i];
        if ($c === '"') {
            $start = $i;
            for ($i++; $i < $n && $raw[$i] !== '"'; $i++) {
                if ($raw[$i] === '\\') {
                    $i++;
                }
            }
            $j = $i + 1;
            while ($j < $n && ctype_space($raw[$j])) {
                $j++;
            }
            if ($depth === 1 && $j < $n && $raw[$j] === ':') {
                $keys[] = (string) json_decode(substr($raw, $start, $i - $start + 1));
            }
        } elseif ($c === '{' || $c === '[') {
            $depth++;
        } elseif ($c === '}' || $c === ']') {
            $depth--;
        }
    }
    return $keys;
}

function startWordPress(array &$state, array $in): array
{
    $domain = $in['domain'];
    if (preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/', $domain) !== 1) {
        return humaError(422, 'domain must be a lowercase domain name with at least one dot, such as example.com.');
    }
    if (strlen($in['admin_password']) < 12 || strlen($in['admin_password']) > 128) {
        return humaError(422, 'admin_password must be 12 to 128 characters, with no control characters and no space at the start or end.');
    }
    if (!in_array($in['php_version'], ['8.1', '8.2', '8.3', '8.4'], true)) {
        return humaError(422, 'php_version must be 8.1, 8.2, 8.3 or 8.4.');
    }
    foreach ($state['jobs'] as $job) {
        if ($job['state'] === 'running') {
            return humaError(409, $job['domain'] === $domain
                ? 'A website for ' . $domain . ' is being created right now. Wait for that job to finish.'
                : 'Another website is being created right now. Wait for it to finish, then try again.');
        }
    }
    foreach ($state['sites'] as $site) {
        if ($site['domain'] === $domain) {
            return humaError(409, $domain . ' already belongs to the hosting account ' . $site['username'] . '. Use another domain, or remove that account first.');
        }
    }
    $id = bin2hex(random_bytes(16));
    $now = gmdate('Y-m-d\TH:i:s\Z');
    $steps = [];
    foreach (['account' => 'Create the hosting account', 'web' => 'Put the site live with PHP', 'ssl' => 'Turn on https', 'database' => 'Create the database', 'wordpress' => 'Install WordPress'] as $name => $title) {
        $steps[] = ['name' => $name, 'title' => $title, 'state' => $name === 'account' ? 'running' : 'pending', 'message' => '', 'started_at' => '', 'finished_at' => ''];
    }
    $state['jobs'][$id] = [
        'id' => $id, 'kind' => 'wordpress', 'domain' => $domain, 'username' => '', 'php_version' => $in['php_version'],
        'state' => 'running', 'steps' => $steps, 'error' => null, 'result' => null, 'actor' => 'local-operator',
        'created_at' => $now, 'updated_at' => $now,
        'admin_user' => $in['admin_user'],
    ];
    $job = $state['jobs'][$id];
    unset($job['admin_user']);
    return [202, ['Content-Type: application/json'], json_encode(['job' => $job], JSON_UNESCAPED_SLASHES)];
}

/** Ends a running job on its first read, as the domain says. */
function advance(array &$state, array $job): array
{
    if ($job['state'] !== 'running' || (str_starts_with($job['domain'], 'slow-') && empty($job['release']))) {
        return publicJob($job);
    }
    $job['updated_at'] = gmdate('Y-m-d\TH:i:s\Z');
    if (str_starts_with($job['domain'], 'fail-')) {
        $job['state'] = 'failed';
        $job['steps'][0]['state'] = 'failed';
        foreach ($job['steps'] as $i => $step) {
            if ($i > 0) {
                $job['steps'][$i]['state'] = 'skipped';
            }
        }
        $job['error'] = [
            'step' => 'account',
            'what' => 'The hosting account was not created.',
            'why' => 'The account service refused the request: the server has no free user IDs.',
            'next' => 'Remove hosting accounts you no longer use, then create the website again.',
            'technical' => 'broker: create account: invalid',
        ];
        $state['jobs'][$job['id']] = $job;
        return publicJob($job);
    }
    $account = bin2hex(random_bytes(16));
    $username = substr((string) preg_replace('/[^a-z0-9]/', '', explode('.', $job['domain'])[0]), 0, 12);
    $job['state'] = 'succeeded';
    $job['username'] = $username;
    foreach ($job['steps'] as $i => $step) {
        $job['steps'][$i]['state'] = $step['name'] === 'ssl' ? 'skipped' : 'done';
    }
    $job['result'] = ['url' => 'http://' . $job['domain'] . '/', 'admin_url' => 'http://' . $job['domain'] . '/wp-admin/', 'wordpress_version' => '6.8.3', 'account_id' => $account];
    $state['sites'][$account] = [
        'account_id' => $account, 'username' => $username, 'domain' => $job['domain'], 'state' => 'active',
        'php_version' => $job['php_version'], 'created_at' => $job['created_at'], 'revision' => 1,
    ];
    $state['jobs'][$job['id']] = $job;
    return publicJob($job);
}

function publicJob(array $job): array
{
    unset($job['admin_user'], $job['release']);
    return $job;
}

function setState(array &$state, string $path, array $in): array
{
    $id = explode('/', $path)[5];
    if (!isset($state['sites'][$id])) {
        return humaError(404, WEBSITE_NOT_FOUND);
    }
    bumpIfAsked($state, $id);
    $site = $state['sites'][$id];
    if (!in_array($in['state'], ['active', 'suspended'], true)) {
        return humaError(422, 'state must be active or suspended.');
    }
    if ($in['expected_revision'] === 0) {
        return humaError(422, NO_REVISION);
    }
    if ($in['expected_revision'] !== $site['revision']) {
        return humaError(409, WEBSITE_STALE);
    }
    $site['state'] = $in['state'];
    $site['revision']++;
    $state['sites'][$id] = $site;
    return json200(website($site) + ['php_versions' => ['8.1', '8.2', '8.3', '8.4']]);
}

function deleteSite(array &$state, string $path, array $in): array
{
    $id = explode('/', $path)[5];
    if (!isset($state['sites'][$id])) {
        return humaError(404, WEBSITE_NOT_FOUND);
    }
    bumpIfAsked($state, $id);
    $site = $state['sites'][$id];
    if ($in['confirm_domain'] === '') {
        return humaError(422, "confirm_domain must be the website's domain.");
    }
    if ($in['expected_revision'] === 0) {
        return humaError(422, NO_REVISION);
    }
    if ($in['confirm_domain'] !== $site['domain']) {
        return humaError(422, 'The domain you typed is not this website\'s domain, ' . $site['domain'] . '. Nothing was removed.');
    }
    if ($in['expected_revision'] !== $site['revision']) {
        return humaError(409, 'This website changed after the page loaded it. Nothing was removed.');
    }
    unset($state['sites'][$id]);
    return json200(['domain' => $site['domain'], 'removed' => ['website', 'database', 'database user', 'hosting account'], 'kept' => []]);
}

/** Another change lands just before this one, when the runner asked for it. */
function bumpIfAsked(array &$state, string $id): void
{
    if (($state['bump'][$id] ?? 0) > 0) {
        $state['bump'][$id]--;
        $state['sites'][$id]['revision']++;
    }
}

function website(array $site): array
{
    return [
        'account_id' => $site['account_id'], 'username' => $site['username'], 'domain' => $site['domain'], 'state' => $site['state'],
        'https' => ['on' => false, 'not_after' => ''], 'php_version' => $site['php_version'], 'wordpress_version' => '6.8.3',
        'url' => 'http://' . $site['domain'] . '/', 'admin_url' => 'http://' . $site['domain'] . '/wp-admin/',
        'created_at' => $site['created_at'], 'revision' => $site['revision'], 'site_folder_changed' => false,
    ];
}

function json200(array $value): array
{
    return [200, ['Content-Type: application/json'], json_encode($value, JSON_UNESCAPED_SLASHES)];
}

/** operator.WriteError's shape. */
function operatorError(int $status, string $code, string $detail): array
{
    $body = ['type' => 'about:blank', 'title' => statusText($status), 'status' => $status, 'detail' => $detail, 'error' => $code, 'authenticated' => false];
    return [$status, ['Content-Type: application/problem+json'], json_encode($body, JSON_UNESCAPED_SLASHES)];
}

/** Huma's error model, as the API's handlers return it. */
function humaError(int $status, string $detail): array
{
    $body = ['title' => statusText($status), 'status' => $status, 'detail' => $detail];
    return [$status, ['Content-Type: application/problem+json'], json_encode($body, JSON_UNESCAPED_SLASHES)];
}

function statusText(int $status): string
{
    return [400 => 'Bad Request', 401 => 'Unauthorized', 404 => 'Not Found', 409 => 'Conflict', 413 => 'Request Entity Too Large', 415 => 'Unsupported Media Type', 422 => 'Unprocessable Entity'][$status] ?? 'Error';
}
