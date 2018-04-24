<?php
require_once '../security.class.php';
Security::putInSafety();
Security::cleanGlobals();

$old_captcha_code = Security::captchaCode();
$verify_captcha = Security::captchaVerify(); // PS: call before Security::printCaptcha() / Security::captcha()
$captcha = Security::captchaPrint('captcha');
$new_captcha_code = Security::captchaCode();

ob_start();

echo <<<HTML
<!DOCTYPE html>
<html>
<head>
  <title>Captcha Test</title>
  <style>
  .captcha {
    height: 25px;
    box-sizing: border-box;
    float: left;
  }
  .clear {
    clear: both;
  }
</style>
</head>
<body>
  <h1>Captcha Test</h1>
  <h3>From here is possible test output security, CSRF, WAF (Firewall) and Captcha protection</h3>
  <p><b>PS: call Security::secureCaptcha(); before Security::printCaptcha() / Security::captcha()</b></p>
  <form action="#" method="POST">
    <label>Username</lable>
    <input type="text" name="username"><br>
    <label>Password</lable>
    <input type="password" name="password"><br>
    <br>
    <label>Captcha</lable><br><br>
    $captcha<br>
    <div class="clear"></div><br>
    <button name="submit" type="submit">Login</button>
  </form>
</body>
</html>
HTML;

if (isset($_POST['submit'])) {
	echo "<h3>Result</h3>";
	echo "VERIFY CAPTCHA:<br>";
	echo "<pre>";
	var_dump($verify_captcha);
	echo "</pre>";
	echo "FORM DATA:<br>";
	echo "<pre>";
	var_dump($_POST);
	echo "</pre>";
	echo "OLD CAPTCHA CODE: ".$old_captcha_code."<br>";
	echo "NEW CAPTCHA CODE: ".$new_captcha_code;
}

$output = Security::output(ob_get_clean());
echo $output;
?>
