<?php
/**
 * Stand-ins for the WHMCS functions and objects the Sifruno module uses, so
 * its functions run without WHMCS: logModuleCall, localAPI and a service
 * model with Service Properties. They record every call, so a test can check
 * what the module logged and saved. Used by run.php and by the dev VM proof.
 */

declare(strict_types=1);

define('WHMCS', true);

/** A service's custom fields, as $params['model']->serviceProperties. */
final class SifrunoTestProperties
{
    /** @var array<string, string> */
    public array $values = [];

    public function get(string $name): ?string
    {
        return $this->values[$name] ?? null;
    }

    public function save(array $values): void
    {
        foreach ($values as $name => $value) {
            $this->values[(string) $name] = (string) $value;
        }
    }
}

/** One WHMCS service: its username, password and custom fields. */
final class SifrunoTestService
{
    public SifrunoTestProperties $serviceProperties;
    public string $username = '';
    public string $password = '';

    public function __construct(public int $id)
    {
        $this->serviceProperties = new SifrunoTestProperties();
    }
}

/** What the stand-ins recorded. */
final class SifrunoTestWHMCS
{
    /** @var list<array{module: string, action: string, request: mixed, response: mixed, processed: mixed, replace: array}> */
    public static array $logs = [];
    /** @var list<array{command: string, values: array}> localAPI calls; these hold the password by design */
    public static array $api = [];
    /** @var array<int, SifrunoTestService> */
    public static array $services = [];
    public static bool $apiFails = false;

    public static function service(int $id): SifrunoTestService
    {
        return self::$services[$id] ??= new SifrunoTestService($id);
    }

    /**
     * The parameters WHMCS passes a server module for one service.
     *
     * @param array{host: string, port: int, token: string, ca: string} $server
     */
    public static function params(SifrunoTestService $service, array $server, string $domain, string $email, string $php = '8.3'): array
    {
        return [
            'serviceid' => $service->id,
            'userid' => 1,
            'pid' => 1,
            'serverid' => 1,
            'domain' => $domain,
            'username' => $service->username,
            'password' => $service->password,
            'producttype' => 'hostingaccount',
            'moduletype' => 'sifruno',
            'configoption1' => $php,
            'customfields' => $service->serviceProperties->values,
            'clientsdetails' => ['firstname' => 'Test', 'lastname' => 'Client', 'email' => $email],
            'server' => true,
            'serverip' => '',
            'serverhostname' => $server['host'],
            'serverusername' => '',
            'serverpassword' => $server['token'],
            'serveraccesshash' => $server['ca'],
            'serversecure' => true,
            'serverport' => (string) $server['port'],
            'model' => $service,
        ];
    }
}

function logModuleCall($module, $action, $requestString, $responseData, $processedData = '', $replaceVars = []): void
{
    SifrunoTestWHMCS::$logs[] = [
        'module' => $module,
        'action' => $action,
        'request' => $requestString,
        'response' => $responseData,
        'processed' => $processedData,
        'replace' => $replaceVars,
    ];
}

function localAPI($command, $values, $adminUser = ''): array
{
    SifrunoTestWHMCS::$api[] = ['command' => $command, 'values' => $values];
    if ($command !== 'UpdateClientProduct' || SifrunoTestWHMCS::$apiFails) {
        return ['result' => 'error', 'message' => 'The stand-in refused the call'];
    }
    $id = (int) ($values['serviceid'] ?? 0);
    if (!isset(SifrunoTestWHMCS::$services[$id])) {
        return ['result' => 'error', 'message' => 'Service ID Not Found'];
    }
    $service = SifrunoTestWHMCS::$services[$id];
    if (isset($values['serviceusername'])) {
        $service->username = (string) $values['serviceusername'];
    }
    if (isset($values['servicepassword'])) {
        $service->password = (string) $values['servicepassword'];
    }
    return ['result' => 'success', 'serviceid' => $id];
}
