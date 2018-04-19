<?php
require_once '../security.class.php';

$password = Security::generatePassword(15);
$guid = Security::generateGUID();
$uf_password = Security::generateFriendlyPassword('Marco Cesarato 2018', 1);
$enc_password = Security::passwordHash($password);
$check = Security::passwordVerify($password, $enc_password);
$check_false = Security::passwordVerify($password, $enc_password.'_fail');

echo <<<HTML
<h1>Password Tests</h1>
<h2>GUID Generation</h2>
<pre>$guid</pre>
<h2>Password Generation</h2>
<pre>Security::generatePassword(15) = "$password"</pre>
<h2>Password Friendly Generation</h2>
<pre>Security::generateFriendlyPassword('Marco Cesarato 2018', 1) = "$uf_password"</pre>
<h2>Password Encryption</h2>
<pre>Security::passwordHash("$password") = "$enc_password"</pre>
<h2>Password Verify</h2>
<pre>
HTML;
var_dump($check);
echo <<<HTML
</pre>
<h2>Password Verify (Miss Match)</h2>
<pre>
HTML;
var_dump($check_false);
echo '</pre>';
?>
