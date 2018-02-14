# PHP Security Class
_IF YOU USE ON YOUR PROJECT SOME OF THESE METHODS PLEASE TO CREDIT ME :) THANK YOU!_


This is a security class in php with some userfull static methods

1) Move **.htaccess** on your ROOT directory

2) Include the class
```php
include 'security.class.php';
```

3) Just create a new object to be more at safe (the constructor filter \$_REQUEST and \$_GET globals, add some userfull headers for security and check if there is an **Hijacking**)
```php
$security = new Security();
```

or just call

```php
Security::putInSafety();
```

4) Prevent **XSS/SQL Injection** on your variables with:

```php
$is_html = true;        // optional
$have_quotes = true;    // optional
$escape_string = true;  // optional
$var = Security::clean($_POST['var'], $is_html, $have_quotes, $escape_string);
echo = $var; 
```
or (THIS COULD COMPROMISE THE DATA IF YOU SEND HTML)
```php
Security::cleanGlobals();
```
5) Use **output** method to filter your output (it also check for **CSRF**)

```php
ob_start()
    
// ... Your code ...
    
$output = Security::output(ob_get_clean());
echo = $output; 
```


Enjoy!

## Methods available:

| Method                                                       | Description                                                  |
| :----------------------------------------------------------- | ------------------------------------------------------------ |
| cleanGlobals()                                               | Clean in automatic \$_POST, \$_GET, \$_REQUEST and \$_COOKIE |
| output($buffer)                                              | Fix some elements on output buffer (to use with ob_start)    |
| putInSafety()                                                | Put in safety the page                                       |
| headers()                                                    | Set some headers and php setting with secure values          |
| secureCookies()                                              | Set cookies in root path and with SameSite=Strict            |
| headersCache()                                               | Set cache cookies                                            |
| compressHTML($html)                                          | Compress HTML                                                |
| compressJS($js)                                              | Compress JS                                                  |
| compressCSS($css)                                            | Compress CSS                                                 |
| secureHTML(\$html)                                           | Repair security issue on template                            |
| clean(\$data, \$html = true, \$quotes = true)                | Clean variables (recursive)                                  |
| stringEscape($var)                                           | String escape similar at mysql_real_escape                   |
| recursiveStripTagsContent($data)                             | Strip tags and contents (recursive)                          |
| recursiveStripTags($data)                                    | Strip tags  (recursive)                                      |
| cleanXSS($data)                                              | Strip XSS code (recursive)                                   |
| recursiveTrim($data)                                         | Trim (recursive)                                             |
| recursiveStripslashes(\$data)                                | Stripslashes (recursive)                                     |
| secureCSRF()                                                 | Check for CSRF                                               |
| clientIP()                                                   | Get Real client IP Address                                   |
| secureHijacking()                                            | Hijacking prevention                                         |
| getCookie($name)                                             | Get encrypted cookie                                         |
| setCookie(\$name, \$value, \$expires = 2592000, \$path = "/", \$domain = null, \$secure = false, \$httponly = true) | Set encrypted cookie                                         |
| crypt(['encrypt'\|'decrypt'], \$string)                      | Encrypt and Decrypt                                          |
| secureDownload($filename)                                    | Safe Download                                                |
| secureUpload($file, $path)                                   | Safe Upload                                                  |


