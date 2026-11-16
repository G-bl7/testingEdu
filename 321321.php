<?php
// test.php — file upload with destination path, accepts ANY file type
declare(strict_types=1);

// ---------- configuration ----------
$BASE_DIR = __DIR__ . '/uploads';   // files can ONLY be stored under this folder
$MAX_SIZE = 50 * 1024 * 1024;       // 50 MB — raise if you need bigger files

// To re-enable a whitelist later, set e.g.:
//   $ALLOWED = ['jpg','jpeg','png','gif','webp','pdf','txt','csv','zip'];
// and set $ALLOWED = null to accept everything (current behaviour).
$ALLOWED = null;

$errors  = [];
$savedTo = null;

// ---------- handle POST ----------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $file    = $_FILES['file'] ?? null;
    $relPath = (string)($_POST['path'] ?? '');   // e.g. "docs/2024"

    // 1) upload errors
    if (!$file || !isset($file['error']) || is_array($file['error'])) {
        $errors[] = 'No file received.';
    } elseif ($file['error'] !== UPLOAD_ERR_OK) {
        $map = [
            UPLOAD_ERR_INI_SIZE   => 'File exceeds upload_max_filesize.',
            UPLOAD_ERR_FORM_SIZE  => 'File exceeds MAX_FILE_SIZE.',
            UPLOAD_ERR_PARTIAL    => 'Only partially uploaded.',
            UPLOAD_ERR_NO_FILE    => 'No file selected.',
            UPLOAD_ERR_NO_TMP_DIR => 'Missing temp folder.',
            UPLOAD_ERR_CANT_WRITE => 'Cannot write to disk.',
            UPLOAD_ERR_EXTENSION  => 'Blocked by a PHP extension.',
        ];
        $errors[] = 'Upload failed: ' . ($map[$file['error']] ?? 'code ' . $file['error']);
    } elseif (!is_uploaded_file($file['tmp_name'])) {
        $errors[] = 'Invalid upload.';
    } elseif ($file['size'] > $MAX_SIZE) {
        $errors[] = 'File is larger than ' . ($MAX_SIZE / 1048576) . ' MB.';
    }

    // 2) validate / sanitise the requested path (relative to $BASE_DIR)
    $relPath = trim(str_replace('\\', '/', $relPath), "/ \t\n\r\0\x0B");
    if ($relPath !== '' && !$errors) {
        if (str_contains($relPath, "\0")
            || preg_match('#(^|/)\.\.?(/|$)#', $relPath)   // no "." / ".." segments
            || preg_match('#^[a-zA-Z]:#', $relPath)) {      // no Windows drive letters
            $errors[] = 'Invalid path.';
        } else {
            foreach (explode('/', $relPath) as $seg) {
                if (!preg_match('/^[A-Za-z0-9._-]+$/', $seg)) {
                    $errors[] = 'Path segments may only contain letters, digits, dot, dash, underscore.';
                    break;
                }
            }
        }
    }

    // 3) optional extension whitelist (disabled by default — any type accepted)
    $name = basename((string)$file['name']);
    $ext  = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    if (!$errors && is_array($ALLOWED) && !in_array($ext, $ALLOWED, true)) {
        $errors[] = 'Extension ".' . $ext . '" is not allowed.';
    }

    // 4) create + verify destination folder
    $destDir = null;
    if (!$errors) {
        if (!is_dir($BASE_DIR)) {
            @mkdir($BASE_DIR, 0755, true);
        }
        $destDir = $BASE_DIR . ($relPath !== '' ? '/' . $relPath : '');

        if (!is_dir($destDir) && !@mkdir($destDir, 0755, true)) {
            $errors[] = 'Cannot create destination directory.';
        } else {
            // containment check: the real path must stay inside $BASE_DIR
            $realBase = realpath($BASE_DIR);
            $realDest = realpath($destDir);
            if ($realBase === false || $realDest === false
                || !str_starts_with($realDest . '/', rtrim($realBase, '/') . '/')) {
                $errors[] = 'Destination is outside the allowed base directory.';
            }
        }
    }

    // 5) move the file
    if (!$errors) {
        // Keep the original extension (any type). Sanitise only path-hostile chars.
        $safeName = preg_replace('/[^A-Za-z0-9._-]/', '_', $name);
        $safeName = ltrim($safeName, '.');
        if ($safeName === '') {
            $safeName = 'file';
        }

        $dest = $destDir . '/' . $safeName;
        $i = 1;
        while (file_exists($dest)) {   // never overwrite
            $info = pathinfo($safeName);
            $base = $info['filename'] ?? 'file';
            $suf  = isset($info['extension']) && $info['extension'] !== ''
                  ? '.' . $info['extension']
                  : '';
            $dest = $destDir . '/' . $base . '_' . $i++ . $suf;
        }

        if (move_uploaded_file($file['tmp_name'], $dest)) {
            @chmod($dest, 0644);       // never 0755 — even for .php files
            $savedTo = ltrim(str_replace(__DIR__, '', $dest), '/\\');
        } else {
            $errors[] = 'Could not move the uploaded file.';
        }
    }
}

function e(string $s): string { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }
?>
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Upload file</title></head>
<body>
<h1>Upload a file</h1>
<p><small>Any file type accepted (including <code>.php</code>). Max
   <?= (int)($MAX_SIZE / 1048576) ?> MB.</small></p>

<?php if ($savedTo !== null): ?>
    <p style="color:green">Saved to: <code><?= e($savedTo) ?></code></p>
<?php endif; ?>

<?php foreach ($errors as $err): ?>
    <p style="color:red"><?= e($err) ?></p>
<?php endforeach; ?>

<form method="post" enctype="multipart/form-data">
    <p>
        <label>File:<br>
            <input type="file" name="file" required>
        </label>
    </p>
    <p>
        <label>Destination path (relative to <code>uploads/</code>, optional):<br>
            <input type="text" name="path" value="<?= e($_POST['path'] ?? '') ?>"
                   placeholder="docs/2024">
        </label>
    </p>
    <p><button type="submit">Upload</button></p>
</form>
</body>
</html>
