<?php
// Sifruno's sign-in script for phpMyAdmin (auth_type 'signon'). The
// installer puts it next to phpMyAdmin's index.php; it runs as phpMyAdmin's
// own system user under OpenLiteSpeed's lsphp.
//
//   ?code=CODE      Redeem the one-time code the panel gave the browser, on
//                   the panel's Unix socket (the panel answers this user
//                   only), put the temporary database login in phpMyAdmin's
//                   signon session, and go on to phpMyAdmin.
//   ?signed_out=1   phpMyAdmin's LogoutURL: end the signon session too.
//   (nothing)       phpMyAdmin's SignonURL, for a browser with no login or
//                   one that has ended: say how to open phpMyAdmin again.
//
// The password arrives over the socket and goes only into the session file
// (phpMyAdmin's private session folder). It is never in a URL, a log line,
// the page or a process argument.

declare(strict_types=1);

const SIFRUNO_REDEEM_SOCKET = '/run/sifruno-panel/phpmyadmin.sock';
const SIFRUNO_SESSION_NAME = 'SifrunoPhpMyAdminSignon';
const SIFRUNO_SESSION_PATH = '/var/lib/sifruno-phpmyadmin/sessions';
const SIFRUNO_BASE = '/api/v1/phpmyadmin/';
const SIFRUNO_AGAIN = "Go back to the website's Databases page in the panel and choose Open phpMyAdmin.";

/** Answers with a page that says what happened, why and what to do next, and stops. */
function sifruno_page(int $status, string $what, string $why, string $next): void
{
    $e = static fn (string $s): string => htmlspecialchars($s, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    http_response_code($status);
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    echo "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>", $e($what), "</title></head>\n",
        "<body><main><h1>", $e($what), "</h1><p>", $e($why), "</p><p><strong>Next step:</strong> ", $e($next), "</p></main></body></html>\n";
    exit;
}

/** Starts the signon session phpMyAdmin reads, with the same cookie rules phpMyAdmin's config gives it. */
function sifruno_session(): void
{
    $https = strtolower((string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https';
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.use_trans_sid', '0');
    session_save_path(SIFRUNO_SESSION_PATH);
    session_name(SIFRUNO_SESSION_NAME);
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => SIFRUNO_BASE,
        'domain' => '',
        'secure' => $https,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    if (!session_start()) {
        sifruno_page(500, 'phpMyAdmin could not sign you in.', 'Its session could not be started on the server.', 'Check that ' . SIFRUNO_SESSION_PATH . ' belongs to phpMyAdmin\'s user, then ' . lcfirst(SIFRUNO_AGAIN));
    }
}

/** Ends the signon session and removes its cookie. */
function sifruno_sign_out(): void
{
    if (!isset($_COOKIE[SIFRUNO_SESSION_NAME])) {
        return;
    }
    sifruno_session();
    $_SESSION = [];
    session_destroy();
    $params = session_get_cookie_params();
    setcookie(SIFRUNO_SESSION_NAME, '', [
        'expires' => 1,
        'path' => $params['path'],
        'domain' => $params['domain'],
        'secure' => $params['secure'],
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
}

/**
 * Redeems the code on the panel's socket. Returns the login, or stops with a
 * page when the panel refuses the code or cannot be reached.
 *
 * @return array{user: string, password: string, expires_at: int}
 */
function sifruno_redeem(string $code): array
{
    $errno = 0;
    $error = '';
    $socket = @stream_socket_client('unix://' . SIFRUNO_REDEEM_SOCKET, $errno, $error, 5.0);
    if ($socket === false) {
        sifruno_page(503, 'phpMyAdmin could not sign you in.', 'The panel did not answer on its sign-in socket.', 'Check that the Sifruno panel is running (systemctl status sifruno), then ' . lcfirst(SIFRUNO_AGAIN));
    }
    stream_set_timeout($socket, 5);
    $request = json_encode(['code' => $code], JSON_THROW_ON_ERROR) . "\n";
    $sent = fwrite($socket, $request);
    $raw = $sent === strlen($request) ? stream_get_contents($socket, 4096) : false;
    fclose($socket);
    $answer = is_string($raw) ? json_decode($raw, true) : null;
    if (!is_array($answer)) {
        sifruno_page(502, 'phpMyAdmin could not sign you in.', 'The panel\'s answer on its sign-in socket was empty or not in the expected form.', 'Check that phpMyAdmin\'s PHP runs as the user the panel was given (--phpmyadmin-uid), then ' . lcfirst(SIFRUNO_AGAIN));
    }
    if (isset($answer['error'])) {
        sifruno_page(403, 'This phpMyAdmin link no longer works.', 'Each link signs in once and only within a minute of the click, and this one was already used or has expired.', SIFRUNO_AGAIN);
    }
    $user = $answer['user'] ?? null;
    $password = $answer['password'] ?? null;
    $expires = $answer['expires_at'] ?? null;
    if (!is_string($user) || preg_match('/^SifrunoPMA_[a-f0-9]{20}$/D', $user) !== 1
        || !is_string($password) || preg_match('/^[A-Za-z0-9_-]{43}$/D', $password) !== 1
        || !is_int($expires)) {
        sifruno_page(502, 'phpMyAdmin could not sign you in.', 'The panel\'s answer did not hold a login in the expected form.', 'The panel and this script may be from different releases: run Sifruno\'s installer again, then ' . lcfirst(SIFRUNO_AGAIN));
    }
    return ['user' => $user, 'password' => $password, 'expires_at' => $expires];
}

if (isset($_GET['signed_out'])) {
    sifruno_sign_out();
    sifruno_page(200, 'You signed out of phpMyAdmin.', 'phpMyAdmin no longer holds a login in this browser. The temporary database user ends within the hour.', 'To open phpMyAdmin again, ' . lcfirst(SIFRUNO_AGAIN) . ' You can close this tab.');
}

$code = $_GET['code'] ?? null;
if ($code === null || $code === '') {
    // phpMyAdmin sends the browser here when there is no login, or when the
    // database refused it because the temporary user has been dropped.
    sifruno_sign_out();
    sifruno_page(401, 'phpMyAdmin needs a new sign-in.', 'A sign-in from the panel lasts one hour, and this browser has none that still works.', SIFRUNO_AGAIN);
}
if (!is_string($code) || preg_match('/^[A-Za-z0-9_-]{43}$/D', $code) !== 1) {
    sifruno_page(400, 'This phpMyAdmin link is not valid.', 'Its code is not in the form the panel makes.', SIFRUNO_AGAIN);
}
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
    sifruno_page(405, 'This phpMyAdmin link is not valid.', 'A sign-in link is opened, not sent.', SIFRUNO_AGAIN);
}

$login = sifruno_redeem($code);

sifruno_session();
// A new session ID for the new login, so no ID the browser had before is reused.
session_regenerate_id(true);
$_SESSION = [
    'PMA_single_signon_user' => $login['user'],
    'PMA_single_signon_password' => $login['password'],
    'PMA_single_signon_HMAC_secret' => bin2hex(random_bytes(16)),
    'sifruno_login_expires_at' => $login['expires_at'],
];
session_write_close();
unset($login);

header('Cache-Control: no-store');
header('Location: ' . SIFRUNO_BASE . 'index.php', true, 303);
exit;
