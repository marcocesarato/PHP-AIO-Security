<?php
require_once '../security.class.php';
Security::putInSafety();

$attempts = $_SESSION['DOS_ATTEMPTS'];
$attempts_timer = $_SESSION['DOS_ATTEMPTS_TIMER'];
$timer = $_SESSION['DOS_TIMER'];
$couter = $_SESSION['DOS_COUNTER'];

echo <<<HTML
<h1>DOS Test</h1>
ATTEMPTS: $attempts<br>
ATTEMPTS TIMER: $attempts_timer<br>
TIMER: $timer<br>
COUNTER: $couter<br>
HTML;
?>
