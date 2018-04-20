<?php
require_once '../security.class.php';
Security::putInSafety();
Security::cleanGlobals();

echo "<pre>";
var_dump(Security::debugGlobals());
echo "</pre>";
?>
