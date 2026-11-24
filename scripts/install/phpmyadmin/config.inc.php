<?php
// phpMyAdmin's configuration, written by Sifruno's installer (install.sh);
// a new run puts this file back. phpMyAdmin signs in only through
// sifruno-signon.php, as a temporary database user the panel made for one
// website's databases, to the local MariaDB server and no other.

declare(strict_types=1);

// The blowfish secret is made at install and only root and phpMyAdmin's
// user can read it. With signon, phpMyAdmin uses it for its own cookies.
require '/etc/sifruno/phpmyadmin/secret.inc.php';

// The panel passes on X-Forwarded-Proto only for a request it received
// over HTTPS, and removes any a browser sent.
$sifrunoHttps = strtolower((string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https';

$cfg['Servers'] = [];
$i = 1;
$cfg['Servers'][$i]['verbose'] = 'This server';
$cfg['Servers'][$i]['host'] = 'localhost';
$cfg['Servers'][$i]['socket'] = '/var/lib/mysql/mysql.sock';
$cfg['Servers'][$i]['compress'] = false;
$cfg['Servers'][$i]['auth_type'] = 'signon';
$cfg['Servers'][$i]['SignonSession'] = 'SifrunoPhpMyAdminSignon';
$cfg['Servers'][$i]['SignonCookieParams'] = [
    'lifetime' => 0,
    'path' => '/',
    'domain' => '',
    'secure' => $sifrunoHttps,
    'httponly' => true,
    'samesite' => 'Strict',
];
$cfg['Servers'][$i]['SignonURL'] = '/sifruno-signon.php';
$cfg['Servers'][$i]['LogoutURL'] = '/sifruno-signon.php?signed_out=1';
$cfg['Servers'][$i]['AllowRoot'] = false;
$cfg['Servers'][$i]['AllowNoPassword'] = false;
// No configuration storage database: the temporary user cannot make one.
$cfg['Servers'][$i]['pmadb'] = '';
$cfg['Servers'][$i]['controluser'] = '';
$cfg['Servers'][$i]['controlpass'] = '';
unset($i, $sifrunoHttps);

$cfg['ServerDefault'] = 1;
$cfg['AllowArbitraryServer'] = false;
$cfg['ZeroConf'] = false;
$cfg['PmaNoRelation_DisableWarning'] = true;
$cfg['TempDir'] = '/var/lib/sifruno-phpmyadmin/tmp';
$cfg['SessionSavePath'] = '/var/lib/sifruno-phpmyadmin/sessions';
$cfg['UploadDir'] = '';
$cfg['SaveDir'] = '';
// No calls from this server to phpmyadmin.net, and no error reports sent.
$cfg['VersionCheck'] = false;
$cfg['SendErrorReports'] = 'never';
// The temporary user's password is the panel's; it is never changed here.
$cfg['ShowChgPassword'] = false;
$cfg['ShowCreateDb'] = false;
$cfg['ShowServerInfo'] = false;
$cfg['ShowPhpInfo'] = false;
$cfg['ShowGitRevision'] = false;
$cfg['AllowThirdPartyFraming'] = false;
