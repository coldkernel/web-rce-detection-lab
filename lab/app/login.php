<?php
// Intentionally vulnerable lab. Fixed credentials: intern / intern
session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (($_POST['user'] ?? '') === 'intern' && ($_POST['pass'] ?? '') === 'intern') {
        $_SESSION['user'] = 'intern';
        header('Location: index.php');
        exit;
    }
    $error = 'Wrong username or password.';
}
?>
<!doctype html>
<html><head><meta charset="utf-8"><title>Login (lab)</title></head>
<body>
<h2>Login</h2>
<?php if (!empty($error)) echo '<p>' . htmlspecialchars($error) . '</p>'; ?>
<form method="post">
  <label>User <input name="user"></label><br>
  <label>Password <input name="pass" type="password"></label><br>
  <button type="submit">Sign in</button>
</form>
<p><a href="index.php">Back</a></p>
</body></html>
