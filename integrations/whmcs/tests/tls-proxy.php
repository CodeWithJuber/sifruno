<?php
/**
 * Puts HTTPS in front of the mock panel, because php -S speaks plain HTTP:
 *   php tls-proxy.php LISTEN_PORT CERT_PEM KEY_PEM TARGET_PORT
 * It serves one connection at a time on 127.0.0.1 and copies bytes both
 * ways. A client that refuses the certificate ends its handshake; the proxy
 * goes on to the next connection. For the module's tests only.
 */

declare(strict_types=1);

[, $listen, $cert, $key, $target] = $argv + array_fill(0, 5, '');
$context = stream_context_create(['ssl' => ['local_cert' => $cert, 'local_pk' => $key, 'verify_peer' => false]]);
$server = stream_socket_server('tls://127.0.0.1:' . $listen, $errno, $error, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);
if ($server === false) {
    fwrite(STDERR, "tls-proxy: cannot listen on $listen: $error\n");
    exit(1);
}
while (true) {
    $client = @stream_socket_accept($server, -1);
    if ($client === false) {
        continue;
    }
    $upstream = @stream_socket_client('tcp://127.0.0.1:' . $target, $errno, $error, 5);
    if ($upstream === false) {
        fclose($client);
        continue;
    }
    relay($client, $upstream);
    fclose($client);
    fclose($upstream);
}

/**
 * Copies until either side closes or both are quiet for 30 seconds. Reads
 * drain each side, since OpenSSL may hold decrypted bytes select() cannot see.
 */
function relay($a, $b): void
{
    stream_set_blocking($a, false);
    stream_set_blocking($b, false);
    while (true) {
        $read = [$a, $b];
        $write = null;
        $except = null;
        if (@stream_select($read, $write, $except, 30) < 1) {
            return;
        }
        foreach ($read as $from) {
            $to = $from === $a ? $b : $a;
            $got = false;
            while (($data = fread($from, 65536)) !== false && $data !== '') {
                $got = true;
                if (!writeAll($to, $data)) {
                    return;
                }
            }
            if (!$got && feof($from)) {
                return;
            }
        }
    }
}

function writeAll($to, string $data): bool
{
    while ($data !== '') {
        $n = @fwrite($to, $data);
        if ($n === false) {
            return false;
        }
        if ($n === 0) {
            usleep(1000);
            continue;
        }
        $data = substr($data, $n);
    }
    return true;
}
