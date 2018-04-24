<?php
require_once '../security.class.php';
Security::putInSafety();

if(!isset($_COOKIE['TEST']))
	Security::setCookie('TEST', 'Test Message');

echo "<h1>Cookies Test</h1>";
echo "Check on your browser the real value of the cookies through a plugin as <a href='https://chrome.google.com/webstore/detail/cookie-inspector/jgbbilmfbammlbbhmmgaagdkbkepnijn'>Cookie Inspector</a> (chrome) or <a href='https://addons.mozilla.org/en-US/firefox/addon/cookies-manager-plus/'>Cookie Manager</a> (firefox)";
echo "<pre>";
var_dump($_COOKIE);
echo "</pre>";
?>
