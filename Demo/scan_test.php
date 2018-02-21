<?php
require_once '../security.class.php';

echo <<<HTML
<h1>Security Scan Test</h1>
<h2>Potentially evil files</h2>
<pre>
HTML;
var_dump(Security::secureScanPath(__DIR__."/*.php"));
echo '</pre>';
?>
