<?php
require_once '../security.class.php';
Security::putInSafety();
Security::cleanGlobals();

echo <<<HTML
<h1>Security XSS Test</h1>
PS: On \$_GET & \$_COOKIE html is not permitted<br><br>
<pre>
\$_REQUEST[xss]: $_REQUEST['xss']\n\r
\$_GET[xss]    : $_GET['xss']\n\r
\$_POST[xss]   : $_POST['xss']\n\r
\$_COOKIE[xss] : $_COOKIE['xss']\n\r
</pre>
HTML;
?>
