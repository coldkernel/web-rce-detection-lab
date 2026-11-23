<?php
// Intentionally vulnerable. Run only on a machine you control.
session_start();

// "Remember the visitor's browser" feature. It stores the raw User-Agent in the
// session, which means a request header I control is written to a file on disk.
$_SESSION['ua'] = $_SERVER['HTTP_USER_AGENT'] ?? '';

$page = $_GET['page'] ?? 'home.php';

// Traversal filter that strips "../" once and does not recurse.
// "....//" survives the single pass and becomes "../" afterwards.
$page = str_replace('../', '', $page);

$path = __DIR__ . '/pages/' . $page;

$user = $_SESSION['user'] ?? null;
echo "<!doctype html><html><head><meta charset='utf-8'><title>Intranet portal (lab)</title></head><body>";
echo "<nav><a href='?page=home.php'>Home</a> | <a href='?page=about.php'>About</a> | <a href='upload.php'>Upload</a> | ";
echo $user
    ? "logged in as " . htmlspecialchars($user) . " (<a href='logout.php'>logout</a>)"
    : "<a href='login.php'>Login</a>";
echo "</nav><hr>";

// The sink: user input decides which local file is included and executed.
include $path;

echo "</body></html>";
