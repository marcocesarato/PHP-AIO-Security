# PHP AIO Security Class + Antimalware
__Version 0.2.2__

_IF YOU USE ON YOUR PROJECT SOME OF THESE METHODS PLEASE TO CREDIT ME :) THANK YOU!_

This is a security class in php with some useful and automatic static methods. 

Also in _Demo_ folder there is my __antimalware scanner__ userful for check virus on our projects. 

__Read more__ after the _instructions_ section if you interested.

The objective of this class is offer an automatic system of protection for developer's projects and simplify some security operations as the check of CSRF or XSS all in a simple class. In fact you could just call the main method to have better security yet without too much complicated operations.

### Instructions

1-0 - Move **.htaccess** on your ROOT directory

1-1 - Move the class on directory and config the class if you need it. 

These are the options:

```php
// Config
$basedir = __DIR__; // Project basedir where is located .htaccess
$session_name = "XSESSID";
$session_lifetime = 288000; // 8 hours
$session_regenerate_id = false;
$csrf_session = "_CSRFTOKEN";
$csrf_formtoken = "_FORMTOKEN";
$hijacking_salt = "_SALT";
$headers_cache_days = 30; // Cache on NO HTML response (set 0 to disable)
$escape_string = true; // If you use PDO I recommend to set this to false
$scanner_path = "./*.php"; // Folder to scan at start and optionally the file extension
$scanner_whitelist = array('./shell.php','./libs'); // Example of scan whitelist
// Autostart
$auto_session_manager = true; // Run session at start
$auto_scanner = false; // Could have a bad performance impact (anyway you can try)
$auto_block_tor = true; // If you want block TOR clients
$auto_clean_global = false; // Global clean at start
```

__PS:__ *You can always change the configuration as following for each parameters or simply editing the var if you need only static var:*

```php
Security::$session_name = "MYSESSID"
```

1-2 - Include the class

```php
include 'classes/security.class.php';
```

2 - Just create a new object to be more at safe (the **constructor/putInSafety** filter \$_REQUEST and \$_GET globals, add some useful headers for security, check if there is an **Hijacking** and check the URL Request)

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
$is_html = true;        // default is TRUE
$have_quotes = true;    // default is TRUE
$escape_string = true;  // default is TRUE except if you set FALSE in class config
$var = Security::clean($_POST['var'], $is_html, $have_quotes, $escape_string);
echo $var; 
```
or 

```php
Security::cleanGlobals();
```

__PS:__ THIS COULD COMPROMISE DATA IF YOU SEND HTML WITH INLINE JAVASCRIPT

_send with htmlentities could be a solution if you want inline js and clean globals at the same time_



4 - Use **output** method to filter your output (it also check for **CSRF**)

```php
ob_start()
    
// ... Your code ...
    
$output = Security::output(ob_get_clean());
echo = $output; 
```

Enjoy!



### AMWSCAN - Antimalware Scanner

On the __Demo__ folder there is also my __antimalware__ (Demo/scanner.php) that use the scan definitions of __PHP AIO Security Class__. To use it you run the php file from a console try it! 

__Suggestion:__ if you run the scanner on a Wordpress project type _-exploits_ as argument for a better check.



## Methods available:

### Generic Methods

| Method                    | Params         | Return | Description                                                  |
| ------------------------- | -------------- | ------ | ------------------------------------------------------------ |
| __construct / putInSafety | $isAPI = false | Void   | Call some methods:<br /><br />headers `$isAPI`<br />secureSession `$isAPI`<br />secureFormRequest `$isAPI`<br />secureBots<br />secureRequest<br />secureBlockTor<br />secureHijacking<br />secureCookies |
| secureCSRF                | -              | Void   | Check for CSRF                                               |
| secureCSRFToken           | -              | String | Get CSRF Token                                               |
| secureRequest             | -              | Void   | Enable the WAF (Firewall) then check the request method and the URL to prevent some XSS/SQL Injections and bad requests |
| secureFormRequest         | $isAPI = false | Void   | Check if the form origin come from the same website          |
| secureSession             | -              | Void   | Set custom session name for prevent fast identification of php and add some secure param to session cookie. PS: This method call `session_start` |
| headers                   | $isAPI = false | Void   | Set some secure headers (to prevent some XSS, Clickjacking and others bad requests) and secure php setting |
| headersCache              |                | Void   | Set cache headers                                            |
| secureCookies             | -              | Void   | Set some secure parameter on cookies (autoencryption soon...) |
| secureDOS                 | -              | Void   | Block clients that do too much requests (after 10 requests within 1.5 seconds consecutive detect a DOS attempt, the first 4 times the client must wait 10 seconds after that its IP will be banned from the server) |
| secureBlockBots           | -              | Void   | Block some generic bad bots/crawler/spiders                  |
| secureBlockTor            | -              | Void   | Block TOR clients                                            |
| secureHijacking           | -              | Void   | Prevent Hijacking and delete session                         |

### Cleaning Methods

| Method           | Params                                 | Return | Description                                                  |
| ---------------- | -------------------------------------- | ------ | ------------------------------------------------------------ |
| clean            | \$data, \$html = true, \$quotes = true | Mixed  | Clean value form XSS, SQL Injection etc… recursively         |
| cleanGlobals     | -                                      | Void   | Clean all input global vars (\$\__REQUEST,\$\__*POST,*\$\__GET,_\$\_COOKIE)<br />THIS COULD COMPROMISE DATA IF YOU SEND HTML WITH INLINE JAVASCRIPT |
| cleanXSS         | $data                                  | Mixed  | Clean value from XSS recursively                             |
| stringEscape     | $data                                  | Mixed  | Clean from SQL Injection (similar at mysql_real_escape) recursively |
| stripTags        | $data                                  | Mixed  | Strip tags recursively                                       |
| stripTagsContent | \$data, \$tags = '', \$invert = false  | Mixed  | Strip tags and contents recursively                          |
| trim             | $data                                  | Mixed  | Trim recursively                                             |
| stripslashes     | $data                                  | Mixed  | Strip slashes recursively                                    |

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
| unsetCookie    | $name                                                        | String  | Unset a cookie                                               |
| clientIP       | -                                                            | String  | Get real client IP address                                   |
| clientIsTor    | -                                                            | Boolean | Check if client use TOR                                      |
| secureDownload | \$filename                                                   | Void    | Secure headers for download request                          |
| secureUpload   | \$file, \$path                                               | Boolean | File upload with scan                                        |
| secureScan     | $path                                                        | Void    | Scan files in directory recursively and rename bad files if detected |
| secureScanFile | $filepath                                                    | Boolean | Scan file (detect for shell or php code infected)            |
| secureScanPath | $path                                                        | Array   | Scan files in directory recursively (detect for shell or php code infected) |
