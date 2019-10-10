<?php

require_once '../src/Security.php';
use marcocesarato\security\Security;

Security::secureSession();
Security::captcha();
