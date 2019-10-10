<?php

require_once '../src/Security.php';
use marcocesarato\security\Security;

Security::putInSafety();
Security::cleanGlobals();

echo '<pre>';
var_dump(Security::debugGlobals());
echo '</pre>';
