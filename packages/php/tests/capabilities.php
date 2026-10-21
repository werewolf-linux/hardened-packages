<?php
// Run against the installed PHP. Shell probes supply grants and fixtures.
function check(bool $ok): void {
    if (!$ok) {
        throw new RuntimeException('capability probe failed');
    }
}

function denied(callable $call, string $group): void {
    try {
        $call();
    } catch (Error $error) {
        check(str_contains($error->getMessage(), 'php:' . $group));
        return;
    }
    throw new RuntimeException('capability was not denied: ' . $group);
}

switch ($argv[1]) {
case 'floor':
    $groups = [
        'exec' => ['mail', 'mb_send_mail'],
        'namespace' => ['pcntl_unshare', 'pcntl_setns'],
        'process' => ['pcntl_fork', 'pcntl_rfork', 'pcntl_forkx', 'posix_setsid', 'posix_setpgid'],
        'listen' => ['stream_socket_server', 'stream_socket_accept'],
        'special-files' => ['posix_mkfifo', 'posix_mknod'],
        'diagnostics' => ['phpinfo'],
    ];
    foreach ($groups as $functions) {
        foreach ($functions as $function) {
            check(!function_exists($function));
            $evaluated = false;
            try {
                $function($evaluated = true);
            } catch (Error $error) {
                check(str_contains($error->getMessage(), 'undefined function'));
            }
            check(!$evaluated);
        }
    }
    // Ordinary signal handling and process identity queries remain available.
    check(function_exists('pcntl_signal') && function_exists('posix_getpid'));
    echo 'closed';
    break;
case 'namespace':
    // macOS has neither API. Linux package probes must restore unshare.
    check(PHP_OS_FAMILY !== 'Linux' || function_exists('pcntl_unshare'));
    check(!function_exists('pcntl_fork') && !function_exists('system'));
    echo 'namespace';
    break;
case 'process':
    check(function_exists('posix_setpgid'));
    $pid = pcntl_fork();
    check($pid >= 0);
    if ($pid === 0) {
        exit(posix_setsid() > 0 ? 0 : 1);
    }
    check(pcntl_waitpid($pid, $status) === $pid);
    check(pcntl_wifexited($status) && pcntl_wexitstatus($status) === 0);
    check(!function_exists('pcntl_unshare') && !function_exists('pcntl_setns'));
    echo 'forked';
    break;
case 'listen':
    $server = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
    check($server !== false);
    $client = stream_socket_client('tcp://' . stream_socket_get_name($server, false));
    check($client !== false);
    $peer = stream_socket_accept($server, 2);
    check($peer !== false);
    fwrite($peer, 'listening');
    fclose($peer);
    check(stream_get_contents($client) === 'listening');
    fclose($client);
    fclose($server);
    echo 'listening';
    break;
case 'special-files':
    check(posix_mkfifo($argv[2] . '/fifo', 0600));
    check(posix_mknod($argv[2] . '/node', POSIX_S_IFIFO | 0600));
    check(filetype($argv[2] . '/fifo') === 'fifo' && filetype($argv[2] . '/node') === 'fifo');
    unlink($argv[2] . '/fifo');
    unlink($argv[2] . '/node');
    echo 'created';
    break;
case 'diagnostics':
    ob_start();
    phpinfo(INFO_GENERAL);
    check(str_contains(ob_get_clean(), 'PHP Version'));
    echo 'information';
    break;
case 'mail':
    check(mail('probe@example.invalid', 'probe', 'body'));
    check(mb_send_mail('probe@example.invalid', 'probe', 'body'));
    check(error_log('probe', 1, 'probe@example.invalid'));
    echo 'sent';
    break;
case 'mail-denied':
    // error_log() must keep ordinary logging, while its mail mode needs exec.
    check(!@error_log('probe', 1, 'probe@example.invalid'));
    check(error_log('ordinary-log', 3, $argv[2] . '/ordinary.log'));
    echo 'refused';
    break;
case 'mail-revoke':
    check(function_exists('mail') && function_exists('mb_send_mail'));
    unlink($argv[2]);
    check(!@mail('probe@example.invalid', 'probe', 'body'));
    check(!@mb_send_mail('probe@example.invalid', 'probe', 'body'));
    check(!@error_log('probe', 1, 'probe@example.invalid'));
    echo 'refused';
    break;
case 'native-denied':
case 'native-load':
case 'native-revoke':
    $pdo = PDO::connect('sqlite::memory:');
    check(method_exists($pdo, 'loadExtension'));
    check($pdo->query('SELECT 42')->fetchColumn() == 42);
    $loaders = [fn() => $pdo->loadExtension($argv[2] . '/loader.so')];
    if (class_exists('SQLite3', false)) {
        $sqlite = new SQLite3(':memory:');
        check(method_exists($sqlite, 'loadExtension'));
        $loaders[] = fn() => $sqlite->loadExtension('loader.so');
    }
    if ($argv[1] === 'native-revoke') {
        unlink($argv[3]);
    }
    foreach ($loaders as $load) {
        if ($argv[1] === 'native-load') {
            $load();
            check(is_file($argv[2] . '/loader.c.loaded'));
            unlink($argv[2] . '/loader.c.loaded');
        } else {
            denied($load, 'native');
            check(!is_file($argv[2] . '/loader.c.loaded'));
        }
    }
    echo $argv[1] === 'native-load' ? 'loaded' : 'refused';
    break;
case 'ffi-present':
    echo class_exists('FFI', false) ? 'yes' : 'no';
    break;
case 'ffi-denied':
    denied(fn() => FFI::cdef('int abs(int);'), 'native');
    denied(fn() => FFI::load($argv[2]), 'native');
    denied(fn() => FFI::scope('probe'), 'native');
    denied(fn() => FFI::new('int'), 'native');
    denied(fn() => FFI::cast('int', 1), 'native');
    echo 'refused';
    break;
case 'ffi-load':
    check(FFI::cdef('int abs(int);')->abs(-42) === 42);
    check(FFI::load($argv[2])->abs(-42) === 42);
    echo 'loaded';
    break;
case 'ffi-scope':
    check(FFI::scope('probe')->abs(-42) === 42);
    echo 'preloaded';
    break;
default:
    throw new RuntimeException('unknown capability probe');
}
