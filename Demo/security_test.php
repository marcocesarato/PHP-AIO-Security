<?php
require_once '../security.class.php';
Security::putInSafety();
Security::cleanGlobals();

ob_start();

echo <<<HTML
<!DOCTYPE html>
<html>
<head>
  <title>Globals Test</title>
</head>
<body>
  <h1>Security Test</h1>
  <h3>From here is possible test output security, CSRF, WAF (Firewall) and external form request protection</h3>
  <h3>You can also test the AntiDOS refreshing the page many times (hold pressed F5)</h3>
  <form action="#" method="POST">
    <label>Username</lable>
    <input type="text" name="username"><br>
    <label>Password</lable>
    <input type="password" name="password"><br>
    <button name="submit" type="submit">Login</button>
  </form>
</body>
</html>
HTML;

if(isset($_POST['submit'])){
  echo "<h3>Result</h3>";
  echo "<pre>";
  var_dump($_POST);
  echo "</pre>";
}

$output = Security::output(ob_get_clean());
echo $output;
?>
