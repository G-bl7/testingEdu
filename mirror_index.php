<?php
$targetDir = rtrim($_GET['dir'] ?? __DIR__, '/') . '/';

if (!is_dir($targetDir)) {
    http_response_code(400);
    echo "Invalid directory";
    exit;
}

$realTarget = realpath($targetDir);

// ---- download mode ------------------------------------------------
if (isset($_GET['download'])) {
    $file = realpath($targetDir . $_GET['download']);

    // block traversal: must stay inside $realTarget and be a real file
    if ($file === false
        || strncmp($file, $realTarget . DIRECTORY_SEPARATOR, strlen($realTarget) + 1) !== 0
        || !is_file($file)) {
        http_response_code(404);
        exit;
    }

    header('Content-Type: application/octet-stream');
    header('Content-Length: ' . filesize($file));
    readfile($file);
    exit;
}

// ---- listing mode -------------------------------------------------
header('Content-Type: text/plain; charset=utf-8');

function scan(string $base, string $rel = ''): void {
    foreach (scandir($base . $rel) as $item) {
        if ($item === '.' || $item === '..') continue;
        $r = $rel === '' ? $item : "$rel/$item";
        if (is_dir($base . $r)) {
            echo "DIR\t$r\n";
            scan($base, $r);
        } else {
            echo "FILE\t$r\n";
        }
    }
}

scan($targetDir);
