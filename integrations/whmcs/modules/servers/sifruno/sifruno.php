<?php
/**
 * Sifruno server module for WHMCS.
 *
 * Each WHMCS service is one WordPress website on a Sifruno panel. The module
 * creates it with the panel's New website wizard, and suspends, unsuspends and
 * terminates it. It calls the panel's own API over HTTPS with an admin API
 * token, using PHP's curl and json extensions only.
 *
 * Server settings in WHMCS (System Settings > Servers):
 *   Hostname     a name the panel serves over HTTPS (its --panel-host)
 *   Password     the API token, sfr_..., from Security > API tokens
 *   Access Hash  empty, or the full path of the panel's certificate file on
 *                this WHMCS server when the panel uses a self-signed one
 *   Port         the panel's HTTPS port; 8443 when not overridden
 *
 * Certificates are always verified. The token and the WordPress password are
 * never put into what logModuleCall receives, and are also on its replace
 * list.
 *
 * Creating a website is a panel job that takes minutes: the account, the web
 * server, the database and the WordPress install. CreateAccount does not wait
 * for it. WHMCS runs CreateAccount inside a payment gateway's callback, an
 * admin's browser request or the cron, and the first two give up long before
 * the job ends; a gateway that times out sends its callback again. So
 * CreateAccount starts the job, saves the login and the job ID, follows the
 * job for at most CREATE_WAIT seconds to catch an early failure, and returns.
 * The later functions find the website by its account ID, or by the domain
 * once the job has finished, and say so plainly while the job still runs or
 * after it failed.
 */

declare(strict_types=1);

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

/**
 * A message for the WHMCS admin: what happened, why, and what to do next.
 */
final class SifrunoError extends RuntimeException
{
}

/**
 * One panel as a WHMCS server's settings describe it, and the calls the module
 * makes to its API.
 */
final class SifrunoPanel
{
    /** Service custom fields the module keeps its IDs in. */
    public const ACCOUNT_FIELD = 'Sifruno account ID';
    public const JOB_FIELD = 'Sifruno job ID';

    public const PHP_VERSIONS = ['8.1', '8.2', '8.3', '8.4'];

    /** Seconds CreateAccount follows the job, and how often it asks. */
    public const CREATE_WAIT = 15;
    public const POLL_EVERY = 3;

    /** Seconds each kind of request may take. */
    public const READ_TIMEOUT = 30;
    // The panel gives starting a job 60 seconds: it lists the accounts and
    // probes the database first.
    public const START_TIMEOUT = 60;
    // The panel gives a website change 11 minutes; a delete may take 10.
    public const CHANGE_TIMEOUT = 660;

    private const DEFAULT_PORT = 8443;
    private const CONNECT_TIMEOUT = 10;
    private const MAX_RESPONSE = 8 << 20;
    private const LOGGED_RESPONSE = 20000;
    private const MASK = '********';

    /** @var string[] values that must never reach a log or a message */
    private array $secrets;

    private function __construct(
        private string $base,
        private string $host,
        private string $token,
        private ?string $caFile,
        private string $action,
    ) {
        $this->secrets = [$token];
    }

    /**
     * Reads the server's settings. Nothing is sent when they are wrong.
     */
    public static function fromParams(array $params, string $action): self
    {
        $token = trim((string) ($params['serverpassword'] ?? ''));
        if (preg_match('/^sfr_[A-Za-z0-9_-]{43}$/', $token) !== 1) {
            throw new SifrunoError("The server's Password field does not hold a Sifruno API token, so nothing was sent to the panel. Create a token in the panel under Security > API tokens and paste it into the Password field of this server in WHMCS.");
        }
        $host = strtolower(trim((string) ($params['serverhostname'] ?? '')));
        if ($host === '') {
            $host = strtolower(trim((string) ($params['serverip'] ?? '')));
        }
        if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
            $authority = '[' . $host . ']';
        } elseif (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false
            || preg_match('/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/', $host) === 1) {
            $authority = $host;
        } else {
            throw new SifrunoError("The server's Hostname is empty or is not a host name, so nothing was sent to the panel. Put the name from the panel's https address in the Hostname field of this server in WHMCS.");
        }
        $port = (int) ($params['serverport'] ?? 0);
        if ($port < 1 || $port > 65535) {
            $port = self::DEFAULT_PORT;
        }
        $ca = trim((string) ($params['serveraccesshash'] ?? ''));
        if ($ca !== '' && (!str_starts_with($ca, '/') || !is_file($ca) || !is_readable($ca))) {
            throw new SifrunoError("The server's Access Hash field is not the full path of a certificate file WHMCS can read, so nothing was sent to the panel. Leave it empty when the panel has a certificate from a public authority, or put the full path of the panel's certificate file on this WHMCS server there.");
        }
        return new self('https://' . $authority . ':' . $port, $host, $token, $ca === '' ? null : $ca, $action);
    }

    /**
     * Adds a value, such as a WordPress password, that must be masked.
     */
    public function secret(string $value): void
    {
        if ($value !== '') {
            $this->secrets[] = $value;
        }
    }

    /**
     * Sends one request. Returns the HTTP status and the decoded JSON body
     * (null when the body is not a JSON object or list). A request that got no
     * answer throws. Each call goes to the module log without the token and
     * with the WordPress password masked.
     *
     * @return array{status: int, data: ?array}
     */
    public function call(string $what, string $method, string $path, ?array $body, int $timeout): array
    {
        $headers = ['Authorization: Bearer ' . $this->token, 'Accept: application/json'];
        $logged = $method . ' ' . $path;
        $json = null;
        if ($body !== null) {
            $json = json_encode($body, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            $headers[] = 'Content-Type: application/json';
            if (array_key_exists('admin_password', $body)) {
                $body['admin_password'] = self::MASK;
            }
            $logged .= "\n" . json_encode($body, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        }
        $raw = '';
        $tooLarge = false;
        $options = [
            CURLOPT_URL => $this->base . $path,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_SSLVERSION => CURL_SSLVERSION_TLSv1_2,
            CURLOPT_CONNECTTIMEOUT => self::CONNECT_TIMEOUT,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use (&$raw, &$tooLarge): int {
                if (strlen($raw) + strlen($chunk) > self::MAX_RESPONSE) {
                    $tooLarge = true;
                    return 0;
                }
                $raw .= $chunk;
                return strlen($chunk);
            },
        ];
        if ($this->caFile !== null) {
            $options[CURLOPT_CAINFO] = $this->caFile;
        }
        if ($json !== null) {
            $options[CURLOPT_POSTFIELDS] = $json;
        }
        $handle = curl_init();
        curl_setopt_array($handle, $options);
        $answered = curl_exec($handle) !== false;
        $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        $errno = curl_errno($handle);
        $error = curl_error($handle);
        curl_close($handle);
        if (!$answered) {
            $message = $this->scrub($this->transportError($what, $errno, $error, $tooLarge, $method !== 'GET', $timeout));
            $this->log($logged, 'no answer: curl error ' . $errno . ': ' . $error, $message);
            throw new SifrunoError($message);
        }
        $data = json_decode($raw, true);
        $data = is_array($data) ? $data : null;
        $shown = strlen($raw) > self::LOGGED_RESPONSE ? substr($raw, 0, self::LOGGED_RESPONSE) . "\n(cut at " . self::LOGGED_RESPONSE . ' bytes)' : $raw;
        $this->log($logged, 'HTTP ' . $status . "\n" . $shown, $data === null ? 'not JSON' : 'JSON');
        return ['status' => $status, 'data' => $data];
    }

    /**
     * Explains an answer the module did not expect, from the panel's problem
     * JSON: its detail says why and what to do; its status, code and first
     * error go under "Technical details".
     *
     * @param array{status: int, data: ?array} $res
     */
    public function fail(string $what, array $res): SifrunoError
    {
        $status = $res['status'];
        $data = $res['data'] ?? [];
        $detail = self::text($data['detail'] ?? '');
        $code = self::text($data['error'] ?? '');
        $first = '';
        if (isset($data['errors'][0]) && is_array($data['errors'][0])) {
            $first = self::text($data['errors'][0]['message'] ?? '');
        }
        $why = match (true) {
            $status === 401 => 'The panel refused the API token: it is wrong, expired or revoked. Create a new token in the panel under Security > API tokens and paste it into the Password field of this server in WHMCS.',
            $status === 421 => 'The panel does not answer for the host name ' . $this->host . '. Put a name the panel serves (its --panel-host) in the Hostname field of this server in WHMCS.',
            $status === 429 => 'The panel is refusing API tokens for a while because too many wrong ones were sent. Wait a minute, check the token, then try again.',
            $detail !== '' => $detail,
            $res['data'] === null => 'The panel answered with something that is not the Sifruno API. Check that the Hostname and Port of this server in WHMCS point at the Sifruno panel.',
            $status >= 200 && $status < 300 => 'The panel answered in a form this module does not expect. Check that the panel and this module are both up to date.',
            default => 'The panel refused the request without saying why.',
        };
        $technical = 'HTTP ' . $status . ($code !== '' ? ' ' . $code : '') . ($first !== '' ? '; ' . $first : '');
        return new SifrunoError($this->scrub($what . '. ' . $why . ' Technical details: ' . $technical . '.'));
    }

    /**
     * Writes a module function's final error to the module log.
     */
    public function note(string $message): void
    {
        $this->log('', '', $message);
    }

    /**
     * Masks every secret in a text.
     */
    public function scrub(string $text): string
    {
        foreach ($this->secrets as $secret) {
            $text = str_replace($secret, self::MASK, $text);
        }
        return $text;
    }

    /**
     * Logs an error from outside the panel calls. Only the class and the line
     * are shown: an exception's message can hold values.
     */
    public static function unexpected(string $action, Throwable $e, array $params): string
    {
        $message = 'The Sifruno module stopped on an unexpected error, so it is not known whether the panel made the change. Check the website in the panel before trying again. Technical details: ' . get_class($e) . ' in ' . basename($e->getFile()) . ' line ' . $e->getLine() . '.';
        $secrets = array_values(array_filter([trim((string) ($params['serverpassword'] ?? '')), (string) ($params['password'] ?? '')], static fn (string $s): bool => $s !== ''));
        logModuleCall('sifruno', $action, '', '', $message, $secrets);
        return $message;
    }

    /**
     * Server text made safe to show: no control characters, one line, at
     * most 600 characters.
     */
    public static function text(mixed $value): string
    {
        if (!is_string($value)) {
            return '';
        }
        // preg_replace with /u returns null for text that is not UTF-8.
        $value = trim((string) preg_replace('/[\x00-\x1f\x7f]+/u', ' ', $value));
        if (strlen($value) > 600 && preg_match('/^.{600}/su', $value, $cut) === 1) {
            return $cut[0] . '...';
        }
        return $value;
    }

    private function transportError(string $what, int $errno, string $error, bool $tooLarge, bool $change, int $timeout): string
    {
        $technical = ' Technical details: curl error ' . $errno . ': ' . self::text($error) . '.';
        $unknown = $change ? ' The change may still finish on the panel, so check the website there before trying again.' : '';
        if ($tooLarge) {
            return $what . '. The panel\'s answer was larger than 8 MiB, so the module stopped reading it.' . $unknown . $technical;
        }
        switch ($errno) {
            case 51: // CURLE_PEER_FAILED_VERIFICATION, before curl 7.62
            case 60: // CURLE_PEER_FAILED_VERIFICATION
            case 77: // CURLE_SSL_CACERT_BADFILE
            case 83: // CURLE_SSL_ISSUER_ERROR
                return $what . '. The panel\'s HTTPS certificate could not be verified, so nothing was sent. If the panel uses its own self-signed certificate, copy panel-cert.pem from the tls folder of the panel\'s state directory to this WHMCS server and put its full path in the Access Hash field of this server in WHMCS. The Hostname must be a name the certificate is for.' . $technical;
            case 35: // CURLE_SSL_CONNECT_ERROR
                return $what . '. HTTPS could not be set up with ' . $this->host . ', so nothing was sent. Check that the Port is the panel\'s HTTPS port (8443 unless it was changed) and that the panel runs with --https-listen.' . $technical;
            case 6: // CURLE_COULDNT_RESOLVE_HOST
                return $what . '. The host name ' . $this->host . ' could not be found, so nothing was sent. Check the Hostname of this server in WHMCS.' . $technical;
            case 7: // CURLE_COULDNT_CONNECT
                return $what . '. Nothing answered at ' . $this->host . ', so nothing was sent. Check that the panel runs with --https-listen, that the Port is right, and that the panel\'s firewall lets this WHMCS server in.' . $technical;
            case 28: // CURLE_OPERATION_TIMEDOUT
                return $what . '. The panel did not answer within ' . $timeout . ' seconds.' . ($change ? $unknown : ' Try again in a few minutes.') . $technical;
        }
        return $what . '. The request to the panel failed.' . $unknown . $technical;
    }

    private function log(string $request, string $response, string $processed): void
    {
        logModuleCall('sifruno', $this->action, $request, $response, $processed, $this->secrets);
    }
}

/**
 * The website behind one WHMCS service.
 */
final class SifrunoSite
{
    /**
     * Runs a module function's work: "success", or the message WHMCS shows.
     */
    public static function run(string $action, array $params, callable $work): string
    {
        $panel = null;
        try {
            $panel = SifrunoPanel::fromParams($params, $action);
            $work($panel);
            return 'success';
        } catch (SifrunoError $e) {
            if ($panel === null) {
                logModuleCall('sifruno', $action, '', '', $e->getMessage(), array_values(array_filter([trim((string) ($params['serverpassword'] ?? ''))])));
                return $e->getMessage();
            }
            $message = $panel->scrub($e->getMessage());
            $panel->note($message);
            return $message;
        } catch (Throwable $e) {
            return SifrunoPanel::unexpected($action, $e, $params);
        }
    }

    /**
     * The service's domain as the panel wants it.
     */
    public static function domain(array $params): string
    {
        $domain = strtolower(trim((string) ($params['domain'] ?? '')));
        if (strlen($domain) > 253 || filter_var($domain, FILTER_VALIDATE_IP) !== false
            || preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/', $domain) !== 1) {
            throw new SifrunoError('This service has no domain, or its domain is not a plain domain name such as example.com, so nothing was sent to the panel. Set the domain on the service, then try again.');
        }
        return $domain;
    }

    /**
     * The WordPress admin username: the service's username when WordPress
     * accepts it, otherwise the domain's first label.
     */
    public static function adminUser(array $params, string $domain): string
    {
        $user = trim((string) ($params['username'] ?? ''));
        if (preg_match('/^[A-Za-z0-9_.@][A-Za-z0-9_.@-]{0,59}$/', $user) === 1) {
            return $user;
        }
        $label = substr((string) preg_replace('/[^a-z0-9]/', '', explode('.', $domain)[0]), 0, 20);
        return $label !== '' ? $label : 'wpadmin';
    }

    /**
     * A new WordPress admin password: 32 characters from 24 random bytes.
     */
    public static function newPassword(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(24)), '+/', '-_'), '=');
    }

    public static function validId(mixed $id): bool
    {
        return is_string($id) && preg_match('/^[a-f0-9]{32}$/', $id) === 1;
    }

    /**
     * A value the module saved on the service.
     */
    public static function stored(array $params, string $field): string
    {
        $model = $params['model'] ?? null;
        if (is_object($model)) {
            return trim((string) ($model->serviceProperties->get($field) ?? ''));
        }
        return trim((string) ($params['customfields'][$field] ?? ''));
    }

    /**
     * Saves values on the service as its custom fields (Service Properties,
     * WHMCS 7.2 and later). WHMCS creates a field that does not exist yet.
     */
    public static function store(array $params, array $values): void
    {
        $model = $params['model'] ?? null;
        if (!is_object($model)) {
            throw new SifrunoError('WHMCS did not pass the service to the module, so it could not save the website\'s IDs. This module needs WHMCS 7.2 or later.');
        }
        $model->serviceProperties->save($values);
    }

    /**
     * Finds the service's website: by the saved account ID, else by domain.
     * Without a website, the wizard job the service started, if the panel
     * still has it.
     *
     * @return array{site: ?array, job: ?array}
     */
    public static function locate(SifrunoPanel $panel, array $params, string $domain, string $what): array
    {
        $id = self::stored($params, SifrunoPanel::ACCOUNT_FIELD);
        if (self::validId($id)) {
            $res = $panel->call($what, 'GET', '/api/v1/websites/sites/' . $id, null, SifrunoPanel::READ_TIMEOUT);
            if ($res['status'] === 200 && self::isSite($res['data'])) {
                return ['site' => $res['data'], 'job' => null];
            }
            if ($res['status'] !== 404) {
                throw $panel->fail($what, $res);
            }
        }
        $res = $panel->call($what, 'GET', '/api/v1/websites/sites', null, SifrunoPanel::READ_TIMEOUT);
        if ($res['status'] !== 200 || !is_array($res['data']['sites'] ?? null)) {
            throw $panel->fail($what, $res);
        }
        foreach ($res['data']['sites'] as $site) {
            if (self::isSite($site) && $site['domain'] === $domain) {
                if ($site['account_id'] !== $id) {
                    self::store($params, [SifrunoPanel::ACCOUNT_FIELD => $site['account_id']]);
                }
                return ['site' => $site, 'job' => null];
            }
        }
        $job = null;
        $jobId = self::stored($params, SifrunoPanel::JOB_FIELD);
        if (self::validId($jobId)) {
            $res = $panel->call($what, 'GET', '/api/v1/websites/jobs/' . $jobId, null, SifrunoPanel::READ_TIMEOUT);
            if ($res['status'] === 200 && is_array($res['data']['job'] ?? null)) {
                $job = $res['data']['job'];
            } elseif ($res['status'] !== 404) {
                throw $panel->fail($what, $res);
            }
        }
        // The job may have finished after the list was read.
        $account = $job['result']['account_id'] ?? null;
        if (($job['state'] ?? '') === 'succeeded' && self::validId($account) && $account !== $id) {
            $res = $panel->call($what, 'GET', '/api/v1/websites/sites/' . $account, null, SifrunoPanel::READ_TIMEOUT);
            if ($res['status'] === 200 && self::isSite($res['data'])) {
                self::store($params, [SifrunoPanel::ACCOUNT_FIELD => $account]);
                return ['site' => $res['data'], 'job' => null];
            }
            if ($res['status'] !== 404) {
                throw $panel->fail($what, $res);
            }
        }
        return ['site' => null, 'job' => $job];
    }

    /**
     * The service's website, or an error that says why there is none.
     */
    public static function find(SifrunoPanel $panel, array $params, string $domain, string $what): array
    {
        $found = self::locate($panel, $params, $domain, $what);
        if ($found['site'] !== null) {
            return $found['site'];
        }
        $job = $found['job'];
        $state = is_array($job) ? ($job['state'] ?? '') : '';
        if ($state === 'running') {
            throw new SifrunoError($what . '. The website is still being created on the panel (' . self::currentStep($job) . '). Wait until it is finished, then try again; creating a website can take up to 15 minutes.');
        }
        if ($state === 'failed') {
            throw new SifrunoError($what . '. ' . self::jobFailure($job));
        }
        throw new SifrunoError($what . '. The panel has no website for ' . $domain . ', so nothing changed. Check Websites in the panel. If the website was deleted there, set this service\'s status in WHMCS by hand.');
    }

    /**
     * Sends one change to the website with the revision the panel last showed.
     * When someone else changed the website in between, the panel answers
     * 409 and nothing changed; the module reads the website again and retries,
     * three tries in all.
     *
     * @param callable(array): array{0: string, 1: array} $request the path and body for the website
     */
    public static function change(SifrunoPanel $panel, array $params, string $domain, string $what, callable $request): array
    {
        for ($try = 1; ; $try++) {
            $site = self::find($panel, $params, $domain, $what);
            [$path, $body] = $request($site);
            $res = $panel->call($what, 'POST', $path, $body, SifrunoPanel::CHANGE_TIMEOUT);
            if ($res['status'] === 200) {
                return $res['data'] ?? [];
            }
            if ($res['status'] !== 409 || $try === 3) {
                throw $panel->fail($what, $res);
            }
        }
    }

    /**
     * Suspends or resumes the website.
     */
    public static function setState(SifrunoPanel $panel, array $params, string $state): void
    {
        $domain = self::domain($params);
        $what = ($state === 'suspended' ? 'Could not suspend' : 'Could not unsuspend') . ' the website for ' . $domain;
        self::change($panel, $params, $domain, $what, static fn (array $site): array => [
            '/api/v1/websites/sites/' . $site['account_id'] . '/state',
            ['state' => $state, 'expected_revision' => $site['revision']],
        ]);
    }

    /**
     * Follows a wizard job until it ends or the time is up. A failed read is
     * logged and ends the wait: the job was accepted and runs on.
     */
    public static function follow(SifrunoPanel $panel, string $what, array $job, int $seconds): array
    {
        $until = microtime(true) + $seconds;
        while (($job['state'] ?? '') === 'running' && microtime(true) < $until) {
            sleep(SifrunoPanel::POLL_EVERY);
            try {
                $res = $panel->call($what, 'GET', '/api/v1/websites/jobs/' . $job['id'], null, SifrunoPanel::READ_TIMEOUT);
            } catch (SifrunoError $e) {
                break;
            }
            if ($res['status'] !== 200 || !is_array($res['data']['job'] ?? null) || ($res['data']['job']['id'] ?? '') !== $job['id']) {
                break;
            }
            $job = $res['data']['job'];
        }
        return $job;
    }

    /**
     * What a failed job says: what, why, what next, then its details.
     */
    public static function jobFailure(array $job): string
    {
        $error = is_array($job['error'] ?? null) ? $job['error'] : [];
        $parts = array_filter([
            SifrunoPanel::text($error['what'] ?? ''),
            SifrunoPanel::text($error['why'] ?? ''),
            SifrunoPanel::text($error['next'] ?? ''),
        ], static fn (string $s): bool => $s !== '');
        $text = 'Creating the website failed on the panel.' . ($parts === [] ? '' : ' ' . implode(' ', $parts));
        $technical = 'job ' . SifrunoPanel::text($job['id'] ?? '');
        $step = SifrunoPanel::text($error['step'] ?? '');
        if ($step !== '') {
            $technical .= ', step ' . $step;
        }
        $detail = SifrunoPanel::text($error['technical'] ?? '');
        if ($detail !== '') {
            $technical .= '; ' . $detail;
        }
        return $text . ' Technical details: ' . $technical . '.';
    }

    /**
     * The step a running job is on, as the panel names it.
     */
    public static function currentStep(array $job): string
    {
        foreach (is_array($job['steps'] ?? null) ? $job['steps'] : [] as $step) {
            if (is_array($step) && ($step['state'] ?? '') === 'running') {
                $title = SifrunoPanel::text($step['title'] ?? '');
                if ($title !== '') {
                    return 'now: ' . $title;
                }
            }
        }
        return 'starting';
    }

    public static function html(string $text): string
    {
        return htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    private static function isSite(mixed $site): bool
    {
        return is_array($site) && self::validId($site['account_id'] ?? null) && is_string($site['domain'] ?? null)
            && is_string($site['state'] ?? null) && is_int($site['revision'] ?? null);
    }
}

function sifruno_MetaData(): array
{
    return [
        'DisplayName' => 'Sifruno',
        'APIVersion' => '1.1',
        'RequiresServer' => true,
        // The module always uses HTTPS, so both are the panel's HTTPS port.
        'DefaultSSLPort' => '8443',
        'DefaultNonSSLPort' => '8443',
    ];
}

function sifruno_ConfigOptions(): array
{
    return [
        'PHP version' => [
            'Type' => 'dropdown',
            'Options' => implode(',', SifrunoPanel::PHP_VERSIONS),
            'Default' => '8.3',
            'Description' => 'PHP version for the WordPress website',
        ],
    ];
}

/**
 * Proves the token works: an authenticated read of the panel's websites.
 */
function sifruno_TestConnection(array $params): array
{
    $result = SifrunoSite::run('TestConnection', $params, static function (SifrunoPanel $panel): void {
        $what = 'The connection test failed';
        $res = $panel->call($what, 'GET', '/api/v1/websites/sites', null, SifrunoPanel::READ_TIMEOUT);
        if ($res['status'] !== 200 || !is_array($res['data']['sites'] ?? null)) {
            throw $panel->fail($what, $res);
        }
    });
    return $result === 'success' ? ['success' => true, 'error' => ''] : ['success' => false, 'error' => $result];
}

/**
 * Starts the panel's New website wizard for the service's domain, saves the
 * WordPress login as the service's username and password and the job ID on
 * the service, and follows the job for CREATE_WAIT seconds.
 */
function sifruno_CreateAccount(array $params): string
{
    return SifrunoSite::run('CreateAccount', $params, static function (SifrunoPanel $panel) use ($params): void {
        $domain = SifrunoSite::domain($params);
        $what = 'Could not create the website for ' . $domain;
        $php = trim((string) ($params['configoption1'] ?? ''));
        if (!in_array($php, SifrunoPanel::PHP_VERSIONS, true)) {
            throw new SifrunoError($what . '. The product\'s PHP version setting is not 8.1, 8.2, 8.3 or 8.4, so nothing was sent to the panel. Choose one on the product\'s Module Settings tab, then try again.');
        }
        $email = trim((string) ($params['clientsdetails']['email'] ?? ''));
        if ($email === '' || strlen($email) > 100 || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            throw new SifrunoError($what . '. The client\'s email address is missing or is not a plain address, and WordPress needs one for its admin, so nothing was sent to the panel. Correct it on the client\'s profile, then try again.');
        }
        $user = SifrunoSite::adminUser($params, $domain);
        $password = SifrunoSite::newPassword();
        $panel->secret($password);
        $res = $panel->call($what, 'POST', '/api/v1/websites/wordpress', [
            'domain' => $domain,
            'title' => $domain,
            'admin_user' => $user,
            'admin_email' => $email,
            'admin_password' => $password,
            'php_version' => $php,
        ], SifrunoPanel::START_TIMEOUT);
        $job = $res['data']['job'] ?? null;
        if ($res['status'] !== 202 || !is_array($job) || !SifrunoSite::validId($job['id'] ?? null)) {
            throw $panel->fail($what, $res);
        }
        // The login first: it exists nowhere else. UpdateClientProduct stores
        // the service password the way WHMCS stores every service password,
        // and the client sees it on the service.
        $saved = localAPI('UpdateClientProduct', [
            'serviceid' => (int) ($params['serviceid'] ?? 0),
            'serviceusername' => $user,
            'servicepassword' => $password,
        ]);
        if (($saved['result'] ?? '') !== 'success') {
            throw new SifrunoError('The website for ' . $domain . ' is being created, but WHMCS did not save its WordPress login on the service, so the client cannot see it. Do not run Create again: the website exists. When it is ready, set a new password for the WordPress user ' . $user . ' in WordPress and put it in this service\'s Password field.');
        }
        SifrunoSite::store($params, [SifrunoPanel::JOB_FIELD => $job['id']]);
        $job = SifrunoSite::follow($panel, $what, $job, SifrunoPanel::CREATE_WAIT);
        if (($job['state'] ?? '') === 'failed') {
            throw new SifrunoError($what . '. ' . SifrunoSite::jobFailure($job));
        }
        if (($job['state'] ?? '') === 'succeeded' && SifrunoSite::validId($job['result']['account_id'] ?? null)) {
            SifrunoSite::store($params, [SifrunoPanel::ACCOUNT_FIELD => $job['result']['account_id']]);
        }
    });
}

function sifruno_SuspendAccount(array $params): string
{
    return SifrunoSite::run('SuspendAccount', $params, static function (SifrunoPanel $panel) use ($params): void {
        SifrunoSite::setState($panel, $params, 'suspended');
    });
}

function sifruno_UnsuspendAccount(array $params): string
{
    return SifrunoSite::run('UnsuspendAccount', $params, static function (SifrunoPanel $panel) use ($params): void {
        SifrunoSite::setState($panel, $params, 'active');
    });
}

/**
 * Deletes the website, its database and its hosting account. The service's
 * domain is sent as confirm_domain, so the panel refuses when the website the
 * service points at has another domain.
 */
function sifruno_TerminateAccount(array $params): string
{
    return SifrunoSite::run('TerminateAccount', $params, static function (SifrunoPanel $panel) use ($params): void {
        $domain = SifrunoSite::domain($params);
        $what = 'Could not delete the website for ' . $domain;
        SifrunoSite::change($panel, $params, $domain, $what, static fn (array $site): array => [
            '/api/v1/websites/sites/' . $site['account_id'] . '/delete',
            ['confirm_domain' => $domain, 'expected_revision' => $site['revision']],
        ]);
    });
}

/**
 * Shows the website's state on the service's page in the admin area.
 */
function sifruno_AdminServicesTabFields(array $params): array
{
    $panel = null;
    try {
        $panel = SifrunoPanel::fromParams($params, 'AdminServicesTabFields');
        $domain = SifrunoSite::domain($params);
        $found = SifrunoSite::locate($panel, $params, $domain, 'Could not read the website for ' . $domain);
        $site = $found['site'];
        if ($site !== null) {
            $state = ['active' => 'Live', 'suspended' => 'Suspended', 'recovery_required' => 'Needs a check on the panel', 'partly_deleted' => 'Partly deleted: delete it again to remove the rest'][$site['state']] ?? SifrunoPanel::text($site['state']);
            $url = SifrunoPanel::text($site['url'] ?? '');
            $fields = ['Sifruno website' => SifrunoSite::html($state . ': ' . $site['domain'])];
            if (preg_match('#^https?://#', $url) === 1) {
                $fields['Website address'] = '<a href="' . SifrunoSite::html($url) . '" target="_blank" rel="noopener noreferrer">' . SifrunoSite::html($url) . '</a>';
            }
            $fields['PHP version'] = SifrunoSite::html(SifrunoPanel::text($site['php_version'] ?? ''));
            $fields['Technical details'] = SifrunoSite::html('account ' . $site['account_id'] . ', revision ' . $site['revision']);
            return $fields;
        }
        $job = $found['job'];
        $state = is_array($job) ? ($job['state'] ?? '') : '';
        if ($state === 'running') {
            return ['Sifruno website' => SifrunoSite::html('Being created (' . SifrunoSite::currentStep($job) . ')')];
        }
        if ($state === 'failed') {
            return ['Sifruno website' => SifrunoSite::html(SifrunoSite::jobFailure($job))];
        }
        return ['Sifruno website' => SifrunoSite::html('The panel has no website for ' . $domain . '.')];
    } catch (SifrunoError $e) {
        return ['Sifruno website' => SifrunoSite::html($panel === null ? $e->getMessage() : $panel->scrub($e->getMessage()))];
    } catch (Throwable $e) {
        return ['Sifruno website' => SifrunoSite::html(SifrunoPanel::unexpected('AdminServicesTabFields', $e, $params))];
    }
}
