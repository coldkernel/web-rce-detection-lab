<?php
// Intentionally vulnerable lab. Authenticated upload with an extension denylist.
session_start();

if (empty($_SESSION['user'])) {
    header('Location: login.php');
    exit;
}

$denylist = ['php', 'phtml', 'phar', 'php3', 'php4', 'php5', 'php7', 'phps'];
$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $name = basename($_FILES['file']['name']);
    $ext  = strtolower(pathinfo($name, PATHINFO_EXTENSION));

    if (in_array($ext, $denylist, true)) {
        $message = 'Blocked: executable extension.';
    } else {
        // The file keeps its original name and lands inside the web root.
        $dest = __DIR__ . '/uploads/' . $name;
        if (move_uploaded_file($_FILES['file']['tmp_name'], $dest)) {
            $message = 'Saved as uploads/' . htmlspecialchars($name);
        } else {
            $message = 'Upload failed.';
        }
    }
}
?>
<!doctype html>
<html><head><meta charset="utf-8"><title>Upload (lab)</title></head>
<body>
<h2>Upload a document</h2>
<?php if ($message) echo '<p>' . $message . '</p>'; ?>
<form method="post" enctype="multipart/form-data">
  <input type="file" name="file">
  <button type="submit">Upload</button>
</form>
<p><a href="index.php">Back</a></p>
</body></html>
