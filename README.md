# PHP AIO Security Class + Antimalware

**Version:** 0.2.8.164 beta

**Github:** https://github.com/marcocesarato/PHP-AIO-Security-Class

**Author:** Marco Cesarato

_IF YOU USE ON YOUR PROJECT SOME OF THESE METHODS PLEASE TO CREDIT ME :) THANK YOU!_


## Description

This is a security class in php with some useful and automatic static methods. 

The objective of this class is offer an automatic system of protection for developer's projects and simplify some security operations as the check of CSRF or XSS all in a simple class. In fact you could just call the main method to have better security yet without too much complicated operations.

Also in _Demo_ folder there is my __antimalware scanner__ userful for check virus on our projects. 

__Read more__ after the _instructions_ section if you interested.

Link Repository: https://github.com/marcocesarato/PHP-Antimalware-Scanner

### Instructions

1.0 - Move **.htaccess** on your ROOT directory

1.1 - Move the class on directory and config the class if you need it. 

These are the options:

```php
// Config
$basedir = __DIR__; // Project basedir where is located .htaccess
$salt = "_SALT"; // Salt for crypt
$session_name = "XSESSID"; // Session cookie name
$session_lifetime = 288000; // Session lifetime | default = 8 hours
$session_regenerate_id = false; // Regenerate session id
$session_database = false; // Store sessions on database
$csrf_session = "_CSRFTOKEN"; // CSRF session token name
$csrf_formtoken = "_FORMTOKEN"; // CSRF form token input name 
$headers_cache = true; // Enable header cache
$cookies_encrypted = false; // Encrypt cookies [PHP 5.3+]
$cookies_enc_prefix = 'SEC_'; // Cookies encrypted prefix
$headers_cache_days = 30; // Cache on NO HTML response (set 0 to disable)
$scanner_path = "./*.php"; // Folder to scan at start and optionally the file extension
$scanner_whitelist = array('./shell.php','./libs'); // Example of scan whitelist
$escape_string = true; // If you use PDO I recommend to set this to false
$clean_post_xss = true; // Remove XSS on post global
$compress_output = true; // Compress output
$force_https = false; // Force HTTPS
$hide_errors = true;  // Hide php errors (useful for hide vulnerabilities)
$database = null; // PDO instance for store sessions if enabled before

// Autostart
$auto_session_manager = true; // Run session at start
$auto_cookies_decrypt = true; // Auto encrypt cookies [PHP 5.3+]

$auto_scanner = false; // Could have a bad performance impact and could detect false positive, then try the method secureScanPath before enable this. BE CAREFUL

$auto_block_tor = true; // If you want block TOR clients
$auto_clean_global = false; // Global clean at start
$auto_antidos = true; // Block the client ip when there are too many requests

// Error Template
$error_callback = null; // Set a callback on errors
$error_template = '<html><head><title>${ERROR_TITLE}</title></head><body>${ERROR_BODY}</body></html>';
```

`$auto_scanner = true;`  Could have a bad performance impact and could detect __false positive__, then try the method __secureScanPath__, that return an *array* with all probable malware, before enable this feature.

__PS:__ *You can change the configuration as following for each parameters or simply editing the var directly on the class file:*

```php
Security::$session_name = "MYSESSID"
```

1.2 - Include the class

```php
include 'classes/security.class.php';
```

1.3 - Session store on database (Optional) (PDO/CPDO instances only)

```php
$conn = new PDO(...);
Security::setDatabase($conn); // Or Security::$database = $conn;
```

2.0 - Just create a new object to be more at safe (the **constructor/putInSafety** filter \$_REQUEST and \$_GET globals, add some useful headers for security, check if there is an **Hijacking** and check the URL Request)

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

*<sup>4</sup> global **$_POST** is not filtered. If you dont enable the cleanGlobals feature on settings*



All the uncleaned data can be recovered calling the following globals:

```php
$GLOBALS['UNSAFE_SERVER'] = $_SERVER;
$GLOBALS['UNSAFE_COOKIE'] = $_COOKIE;
$GLOBALS['UNSAFE_GET'] = $_GET;
$GLOBALS['UNSAFE_POST'] = $_POST;
$GLOBALS['UNSAFE_REQUEST'] = $_REQUEST;
```



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

__PS:__ THIS COULD COMPROMISE DATA IF YOU SEND HTML WITH SCRIPT TAGS

_send with htmlentities could be a solution if you want inline js and clean globals at the same time_



4 - Use **output** method to filter your output (it also check for **CSRF**)

```php
ob_start()
    
// ... Your code ...
    
$output = Security::output(ob_get_clean());
echo = $output; 
```

Enjoy!



### AMWSCAN - PHP Antimalware Scanner

![](cover.png)

On the __Demo__ folder there is also my __antimalware__ (Demo/scanner.php) that use the scan definitions of __PHP AIO Security Class__. To use it you run the php file from a console try it! 

__Suggestion:__ if you run the scanner on a Wordpress project type _--exploits_ as argument for a better check.

Link Repository: https://github.com/marcocesarato/PHP-Antimalware-Scanner

#### Usage

```
OPTIONS:

    -e   --exploits    Check only exploits and not the functions
    -h   --help        Show the available options
    -l   --log         Write a log file 'scanner.log' with all the operations done
    -p   --path <dir>  Define the path to scan
    -s   --scan        Scan only mode without check and remove malware. It also write
                       all malware paths found to 'scanner_infected.log' file

NOTES: Better if your run with php -d disable_functions=''
USAGE: php -d disable_functions='' scanner -p ./mywebsite/http/ -l
```



## Methods available:

### Generic Methods

| Method                    | Params             | Return | Description                                                  |
| ------------------------- | ------------------ | ------ | ------------------------------------------------------------ |
| setDatabase               | $conn              | Void   | Set PDO datbase instance for store sessions (only if enabled)                                              |
| __construct / putInSafety | $isAPI = false     | Void   | Call some methods:<br /><br />headers `$isAPI`<br />secureSession `$isAPI`<br />secureFormRequest `$isAPI`<br />secureBots<br />secureRequest<br />secureBlockTor<br />secureHijacking<br />secureCookies |
| secureCSRF                | -                  | Void   | Check for CSRF                                               |
| secureCSRFCompare         | -                  | Bool   | Compare CSRF Token                                              |
| secureCSRFGenerate        | -                  | String | Generate CSRF Token                                               |
| secureCSRFToken           | -                  | String | Get CSRF Token                                               |
| secureRequest             | -                  | Void   | Enable the WAF (Firewall) then check the request method and the URL to prevent some XSS/SQL Injections and bad requests |
| secureFormRequest         | $isAPI = false     | Void   | Check if the form origin come from the same website          |
| secureSession             | -                  | Void   | Set custom session name for prevent fast identification of php and add some secure param to session cookie. PS: This method call `session_start` |
| headers                   | $isAPI = false     | Void   | Set some secure headers (to prevent some XSS, Clickjacking and others bad requests) and secure php setting |
| headersCache              | $cache_days = null | Void   | Set cache headers                                            |
| secureCookies             | -                  | Void   | Set some secure parameter on cookies (autoencryption soon...) |
| secureDOS                 | -                  | Void   | Block clients that do too much requests (after 10 requests within 1.5 seconds consecutive detect a DOS attempt, the first 4 times the client must wait 10 seconds after that its IP will be banned from the server) |
| secureBlockBots           | -                  | Void   | Block some generic bad bots/crawler/spiders                  |
| secureBlockTor            | -                  | Void   | Block TOR clients                                            |
| secureHijacking           | -                  | Void   | Prevent Hijacking and delete session                         |

### Cleaning Methods

| Method           | Params                                               | Return | Description                                                  |
| ---------------- | ---------------------------------------------------- | ------ | ------------------------------------------------------------ |
| clean            | \$data, \$html = true, \$quotes = true, \$xss = true | Mixed  | Clean value form XSS, SQL Injection etc… recursively         |
| cleanGlobals     | -                                                    | Void   | Clean all input global vars (\$\__REQUEST,\$\__*POST,*\$\__GET,_\$\_COOKIE)<br />THIS COULD COMPROMISE SOME DATA |
| restoreGlobals   | -                                                    | Void   | Restore globals to uncleaned/unsafe globals                  |
| debugGlobals     | -                                                    | Array  | Return an array with the safe, unsafe and the current globals, this is userful for comparing |
| escapeXSS        | $data                                                | Mixed  | Clean value from XSS recursively                             |
| escapeSQL        | $data                                                | Mixed  | Clean from SQL Injection (similar at mysql_real_escape) recursively |
| escapeAttr       | $data                                                | Mixed  | Escape for HTML attribute values<br />`<html attr="&quot;">`  recursively |
| stripTags        | $data                                                | Mixed  | Strip tags recursively                                       |
| stripTagsContent | \$data, \$tags = '', \$invert = false                | Mixed  | Strip tags and contents recursively                          |
| trim             | $data                                                | Mixed  | Trim recursively                                             |
| stripslashes     | $data                                                | Mixed  | Strip slashes recursively                                    |



### Output Methods

| Method         | Params                                                       | Return | Description                                                  |
| -------------- | ------------------------------------------------------------ | ------ | ------------------------------------------------------------ |
| output         | \$buffer, \$type = (html\|css\|js\|json\|xml\|csv\|txt), $cache_days = null, \$compress = true | String | Put in safety HTML if is HTML, compress HTML if is HTML, check for CSRF and add cache headers if isn't HTML (usually used with ob_start) |
| secureHTML     | $buffer                                                      | String | Put in safety some html elements, block old browsers console scripts executions on output buffer and add automatically the CSRF token |
| captcha        | $base64 = false                                              | Void   | Print captcha image and die or if base64 return the image in base64. |
| captchaVerify  | \$input_name = 'captcha'                                     | Void   | Validate captcha                                             |
| captchaPrint   | \$class = '', \$input_name = 'captcha'                       | String | Return the captcha input field and the image in html         |
| captchaCode    | -                                                            | String | Get captcha code                                             |
| compressOutput | $buffer                                                      | String | Compression generic                                          |
| compressHTML   | $html                                                        | String | Compression of HTML                                          |
| compressJS     | $js                                                          | String | Compression of JS                                            |
| compressCSS    | $css                                                         | String | Compression of CSS                                           |
| error          | \$code = 404, \$message = "Not found!", \$title = 'Error'    | Void   | Error <br />(use \$error_template and \$error_callback)      |

### Utility Methods

| Method                   | Params                                                       | Return  | Description                                                  |
| ------------------------ | ------------------------------------------------------------ | ------- | ------------------------------------------------------------ |
| encrypt                  | \$string, \$key = null                                       | String  | Encrypt strings                                              |
| decrypt                  | \$string, \$key = null                                       | String  | Decrypt strings                                              |
| generateGUID             | -                                                            | String  | Generate a GUID                                              |
| generatePassword         | \$length = 8, \$available_sets = 'luns'<br /><br />(l = lowercase, u = uppercase, n = numbers, s = special chars) | String  | Generate a completly random and strong password              |
| generateFriendlyPassword | \$string, \$strong_lv = 1                                    | String  | Generate a user friendly random password. Strong level go from 0 to 2.<br /><br />EXAMPLE: <br />Marco Cesarato 1996 <br />Ce$Ar4t0_m4RCo_1996 |
| passwordHash             | \$password, \$cost = 10 (4-30)                               | String  | Hash the passwords                                           |
| passwordVerify           | \$password, \$hash                                           | Boolean | Verify if password hash (returned by passwordHash) match     |
| passwordStrength         | \$password                                                   | Integer | Return password strength score from 0 to 10 (under 6 is a bad score) |
| getCookie                | $name                                                        | String  | Get decrypted cookie                                         |
| setCookie                | \$name, \$value, \$expires = 2592000, \$path = "/", \$domain = null, \$secure = false, \$httponly = true | Boolean | Set encrypted cookie                                         |
| checkHTTPS               | -                                                            | Boolean | Check if site is running over https                          |
| unsetCookie              | $name                                                        | String  | Unset a cookie                                               |
| clientIP                 | -                                                            | String  | Get real client IP address                                   |
| clientIsTor              | -                                                            | Boolean | Check if client use TOR                                      |
| secureJSONP              | \$json, \$callback                                           | String  | Prevent malicious callbacks from being used in JSONP requests. |
| secureDownload           | \$filename, $name = null                                     | Void    | Secure headers for download request                          |
| secureUpload             | \$file, \$path                                               | Boolean | File upload with scan                                        |
| secureScan               | $path                                                        | Void    | Scan files in directory recursively and rename bad files if detected |
| secureScanFile           | $filepath                                                    | Boolean | Scan file (detect for shell or php code infected)            |
| secureScanPath           | $path                                                        | Array   | Scan files in directory recursively (detect for shell or php code infected) |
| environmentCheck         | -                                                            | Array   | Check environment configuration and return the current and the recommended php.ini configuration |
