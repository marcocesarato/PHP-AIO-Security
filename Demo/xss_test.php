<?php
require_once '../security.class.php';
Security::putInSafety();
Security::cleanGlobals();
echo $_GET['xss'];
?>
