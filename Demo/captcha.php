<?php
require_once '../security.class.php';
Security::secureSession();
Security::captcha();
?>
