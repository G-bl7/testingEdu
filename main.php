<?php
// Hard security boundary: nothing outside this directory can ever be browsed.
$allowedRoot = realpath('/www');

// Default working directory when no ?path= is given.
$defaultWorkDir = realpath($allowedRoot . '/tests') ?: $allowedRoot;

/**
 * Safe "is $path inside $root" check (handles the /www/tests vs /www/tests2 case).
 */
function isWithin(string $path, string $root): bool
{
    $root = rtrim($root, DIRECTORY_SEPARATOR);
    if ($root === '') {
        return true; // root is filesystem root
    }
    return $path === $root
        || strpos($path . DIRECTORY_SEPARATOR, $root . DIRECTORY_SEPARATOR) === 0;
}

// Working directory now comes from the URL (?path=...), defaults to $defaultWorkDir.
$requestedPath = isset($_GET['path']) ? trim($_GET['path']) : '';

if ($requestedPath === '') {
    $requestedPath = $defaultWorkDir;
} elseif ($requestedPath[0] !== '/' && !preg_match('#^[A-Za-z]:[\\\\/]#', $requestedPath)) {
    // Relative paths are resolved against the default working directory.
    $requestedPath = $defaultWorkDir . DIRECTORY_SEPARATOR . $requestedPath;
}

$targetPath = realpath($requestedPath);

// Security check: must exist and stay strictly inside $allowedRoot.
if ($targetPath === false || !isWithin($targetPath, $allowedRoot)) {
    $error = 'Access denied or folder not found.';
    $targetPath = $defaultWorkDir;
}

// Handle file downloads when the resolved path is a file.
if (is_file($targetPath)) {
    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . basename($targetPath) . '"');
    header('Content-Length: ' . filesize($targetPath));
    readfile($targetPath);
    exit;
}

$currentPath = $targetPath;
$items = is_dir($currentPath) ? scandir($currentPath) : [];
?>

<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Folder Browser</title>
</head>
<body>

    <form method="GET" action="tests.php">
        <label for="path">Working directory (inside <?php echo htmlspecialchars($allowedRoot); ?>):</label>
        <input type="text" id="path" name="path"
               value="<?php echo htmlspecialchars($currentPath); ?>"
               placeholder="e.g. /www/tests/subfolder" size="50">
        <button type="submit">Go</button>
        <a href="tests.php">Reset</a>
    </form>

    <?php if (isset($error)): ?>
        <p style="color: red;"><?php echo htmlspecialchars($error); ?></p>
    <?php endif; ?>

    <h3>Browsing: <?php echo htmlspecialchars($currentPath); ?></h3>
    <ul>
        <?php
            $parent = dirname($currentPath);
            $hasParent = $currentPath !== $allowedRoot && isWithin($parent, $allowedRoot);
        ?>
        <?php if ($hasParent): ?>
            <li><a href="?path=<?php echo urlencode($parent); ?>">[..] Parent Directory</a></li>
        <?php endif; ?>

        <?php foreach ($items as $item): ?>
            <?php if ($item === '.' || $item === '..') continue; ?>
            <?php $fullItemPath = $currentPath . DIRECTORY_SEPARATOR . $item; ?>
            <?php if (is_dir($fullItemPath)): ?>
                <li><strong>[DIR]</strong> <a href="?path=<?php echo urlencode($fullItemPath); ?>"><?php echo htmlspecialchars($item); ?></a></li>
            <?php else: ?>
                <li>[FILE] <a href="?path=<?php echo urlencode($fullItemPath); ?>"><?php echo htmlspecialchars($item); ?></a></li>
            <?php endif; ?>
        <?php endforeach; ?>
    </ul>

</body>
</html>
