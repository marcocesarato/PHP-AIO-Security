<?php
require_once '../security.class.php';
var_dump(Security::secureScanPath(__DIR__."/*.php"));
?>
