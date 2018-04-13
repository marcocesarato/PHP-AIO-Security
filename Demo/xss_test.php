<?php
require_once '../security.class.php';
Security::putInSafety();
Security::cleanGlobals();

$debug = var_export(Security::debugGlobals(), true);

echo <<<HTML
<h1>Security XSS Test</h1>
PS: On \$_GET & \$_COOKIE html is not permitted<br><br>
<pre>
$debug
</pre>
HTML;
?>
