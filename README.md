# PHP Security Class
_IF YOU USE ON YOUR PROJECT SOME OF THESE METHODS PLEASE TO CREDIT ME :) THANK YOU!_

This is a security class in php with some userfull static methods





1) Move **.htaccess** on your ROOT directory

1-1) Move the class on directory and config the class. These are the options:

```php
$session_name = "XSESSID";
$csrf_session = "_CSRFTOKEN";
$csrf_formtoken = "_FORMTOKEN";
$hijacking_salt = "_SALT";
$headers_cache_days = 30; // Cache on NO HTML response (set 0 to disable)
$block_tor = true; // If you want block TOR clients
$escape_string = true; // If you use PDO I recommend to set this to false
```

1-2) Include the class

```php
include 'security.class.php';
```





2) Just create a new object to be more at safe (the **constructor/putInSafety** filter \$_REQUEST and \$_GET globals, add some userfull headers for security, check if there is an **Hijacking** and check the URL Request)

```php
$is_api = false; // default is FALSE (this remove some check that could block API request)
$security = new Security($is_api);
```

or just call

```php
$is_api = false; // default is FALSE
Security::putInSafety($is_api);
```



**NOTES:**

*Constructor and putInSafety are the **same** thing*

*These methods call **session_start** then **don't** use it before/after*

*The global **$_POST** is not filtered. If you want it I could add this if someone will request this feature. Anyway if you want filter it write* `$_POST = Security::clean($_POST);` 





3) Prevent **XSS/SQL Injection** on your variables with:

```php
$is_html = true;        // deafult is TRUE
$have_quotes = true;    // deafult is TRUE
$escape_string = true;  // deafult is TRUE except if you set FALSE in class config
$var = Security::clean($_POST['var'], $is_html, $have_quotes, $escape_string);
echo = $var; 
```
or (THIS COULD COMPROMISE THE DATA IF YOU SEND HTML)
```php
Security::cleanGlobals();
```




4) Use **output** method to filter your output (it also check for **CSRF**)

```php
ob_start()
    
// ... Your code ...
    
$output = Security::output(ob_get_clean());
echo = $output; 
```





Enjoy!





## Methods available:

*Sorry for bad order this will be fix soon*

| Method                                                       | Description                                                  |
| :----------------------------------------------------------- | ------------------------------------------------------------ |
| cleanGlobals()                                               | Clean in automatic \$_POST, \$_GET, \$_REQUEST and \$_COOKIE |
| secureRequest()                                              | URL request XSS/SQL Injections prevention                    |
| secureFormRequest()                                          | Check if the refer is equal to the origin                    |
| output($buffer)                                              | Fix some elements on output buffer (to use with ob_start)    |
| putInSafety($is_ap = falsei)                                 | Put in safety the page                                       |
| headers($is_ap = false)                                      | Set some headers and php setting with secure values          |
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
| secureUpload(\$file, $path)                                  | Safe Upload                                                  |
| secureBots()                                                 | Check and block bad bots                                     |
| secureBlockTor()                                             | Block Tor clients                                            |
| clientIsTor()                                                | Check if client use Tor (return bool)                        |

