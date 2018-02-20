# PHP Security Class
_IF YOU USE ON YOUR PROJECT SOME OF THESE METHODS PLEASE TO CREDIT ME :) THANK YOU!_

This is a security class in php with some userfull static methods



1-0 - Move **.htaccess** on your ROOT directory

1-1 - Move the class on directory and config the class if you need it. 

These are the options:

```php
// Config
$session_name = "XSESSID";
$csrf_session = "_CSRFTOKEN";
$csrf_formtoken = "_FORMTOKEN";
$hijacking_salt = "_SALT";
$headers_cache_days = 30; // Cache on NO HTML response (set 0 to disable)
$escape_string = true; // If you use PDO I recommend to set this to false
$scan_path = "./*.php"; // Folder to scan at start
$scanner_whitelist = array('./includes','./admin'); // Example of scan whitelist
// Autostart
$auto_session_manager = true; // Run session at start
$auto_scanner = false; // Could have a bad performance impact (anyway you can try)
$auto_block_tor = true; // If you want block TOR clients
$auto_clean_global = false; // Global clean at start
```

1-2 - Include the class

```php
include 'classes/security.class.php';
```



2 - Just create a new object to be more at safe (the **constructor/putInSafety** filter \$_REQUEST and \$_GET globals, add some userfull headers for security, check if there is an **Hijacking** and check the URL Request)

```php
$isAPI = false; // default is FALSE (this remove some check that could block API request)
$security = new Security($isAPI);
```

or just call

```php
$isAPI = false; // default is FALSE
Security::putInSafety($isAPI);
```



**NOTES:**

*<sup>1</sup> You can also call only the methods that you need instead this method*

*<sup>2</sup> Constructor and putInSafety are the **same** thing*

*<sup>3</sup> These methods call **session_start** then **don't** use it before/after*

*<sup>4</sup> global **$_POST** is not filtered. If you want it I could add this if someone will request this feature. Anyway if you want filter it write* `$_POST = Security::clean($_POST);` 



3 - Prevent **XSS/SQL Injection** on your variables with:

```php
$is_html = true;        // deafult is TRUE
$have_quotes = true;    // deafult is TRUE
$escape_string = true;  // deafult is TRUE except if you set FALSE in class config
$var = Security::clean($_POST['var'], $is_html, $have_quotes, $escape_string);
echo = $var; 
```
or 

```php
Security::cleanGlobals();
```

__PS:__ THIS COULD COMPROMISE DATA IF YOU SEND HTML WITH INLINE JAVASCRIPT

_send with htmlentities could be a solution if you want inline js and clean globals_



4 - Use **output** method to filter your output (it also check for **CSRF**)

```php
ob_start()
    
// ... Your code ...
    
$output = Security::output(ob_get_clean());
echo = $output; 
```



Enjoy!





## Methods available:

### Generic Methods

| Method                    | Params         | Return | Description                                                  |
| ------------------------- | -------------- | ------ | ------------------------------------------------------------ |
| __construct / putInSafety | $isAPI = false | Void   | Call some methods:<br /><br />headers `$isAPI`<br />secureSession `$isAPI`<br />secureFormRequest `$isAPI`<br />secureBots<br />secureRequest<br />secureBlockTor<br />secureHijacking<br />secureCookies |
| secureCSRF                | -              | Void   | Check for CSRF                                               |
| secureRequest             | -              | Void   | Check the request method, the user agent, and the URL to prevent some XSS/SQL Injections |
| secureFormRequest         | $isAPI = false | Void   | Check if the REFERER is equal to the origin                  |
| secureSession             | -              | Void   | Set custom session name for prevent fast identification of php and add some secure param to session cookie. PS: This method call `session_start` |
| headers                   | $isAPI = false | Void   | Set some secure headers (to prevent some XSS, Clickjacking and others bad requests) and secure php setting |
| headersCache              |                | Void   | Set cache headers                                            |
| secureCookies             | -              | Void   | Set some secure paramenter on cookies (autoencryption soon...) |
| secureBots                | -              | Void   | Block some bad bot                                           |
| secureBlockTor            | -              | Void   | Block Tor client if in class settings is set to TRUE         |
| secureHijacking           | -              | Void   | Prevent Hijacking and delete session                         |

### Cleaning Methods

| Method                    | Params                                 | Return | Description                                                  |
| ------------------------- | -------------------------------------- | ------ | ------------------------------------------------------------ |
| clean                     | \$data, \$html = true, \$quotes = true | Mixed  | Clean value form XSS, SQL Injection etc...                   |
| cleanGlobals              | -                                      | Void   | Clean all input global vars (\$\__REQUEST,\$\__*POST,*\$\__GET,_\$\_COOKIE)<br />THIS COULD COMPROMISE DATA IF YOU SEND HTML WITH INLINE JAVASCRIPT |
| cleanXSS                  | $data                                  | Mixed  | Clean value from XSS                                         |
| stringEscape              | $data                                  | Mixed  | Clean from SQL Injection (similar at mysql_real_escape)      |
| recursiveStripTagsContent | $data                                  | Mixed  | Strip tags and contents                                      |
| recursiveTrim             | $data                                  | Mixed  | Trim                                                         |
| recursiveStripslashes     | $data                                  | Mixed  | Strip slashes                                                |

### Output Methods

| Method       | Params  | Return | Description                                                  |
| ------------ | ------- | ------ | ------------------------------------------------------------ |
| output       | $buffer | String | Put in safety HTML if is HTML, compress HTML if is HTML, check for CSRF and add cache headers if isn't HTML (usually used with ob_start) |
| secureHTML   | $buffer | String | Put in safety some html elements on output buffer and add automatically the CSRF token |
| compressHTML | $html   | String | Compression of HTML                                          |
| compressJS   | $js     | String | Compression of JS                                            |
| compressCSS  | $css    | String | Compression of CSS                                           |

### Utility Methods

| Method         | Params                                                       | Return  | Description                                                  |
| -------------- | ------------------------------------------------------------ | ------- | ------------------------------------------------------------ |
| crypt          | (encrypt\|decrypt), \$string                                 | String  | Encrypt and decrypt strings                                  |
| getCookie      | $name                                                        | String  | Get decrypted cookie                                         |
| setCookie      | \$name, \$value, \$expires = 2592000, \$path = "/", \$domain = null, \$secure = false, \$httponly = true | Boolean | Set encrypted cookie                                         |
| clientIP       | -                                                            | String  | Get real client IP address                                   |
| clientIsTor    | -                                                            | Boolean | Check if client use TOR                                      |
| secureDownload | \$filename                                                   | Void    | Secure headers for download request                          |
| secureUpload   | \$file, \$path                                               | Boolean | File upload with scan                                        |
| secureScan     | $path                                                        | Void    | Scan files in directory recursively and rename bad files if detected |
| secureScanFile | $filepath                                                    | Boolean | Scan file (detect for shell or php code infected)            |
| secureScanPath | $path                                                        | Array   | Scan files in directory recursively (detect for shell or php code infected) |