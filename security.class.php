<?php

/**
 * AIO Security Class
 * @category  Security
 * @author    Marco Cesarato <cesarato.developer@gmail.com>
 * @copyright Copyright (c) 2014-2018
 * @license   http://opensource.org/licenses/gpl-3.0.html GNU Public License
 * @link      https://github.com/marcocesarato/PHP-AIO-Security-Class
 * @version   0.2.3
 */

class Security
{
	// Config
	public static $basedir = __DIR__; // Project basedir where is located .htaccess
	public static $session_name = "XSESSID";
	public static $session_lifetime = 288000; // 8 hours
	public static $session_regenerate_id = false;
	public static $csrf_session = "_CSRFTOKEN";
	public static $csrf_formtoken = "_FORMTOKEN";
	public static $hijacking_salt = "_SALT";
	public static $headers_cache_days = 30; // Cache on NO HTML response (set 0 to disable)
	public static $escape_string = true; // If you use PDO I recommend to set this to false
	public static $scanner_path = "./*.php"; // Folder to scan at start and optionally the file extension
	public static $scanner_whitelist = array('./shell.php', './libs'); // Example of scan whitelist

	// Autostart
	public static $auto_session_manager = true; // Run session at start
	public static $auto_scanner = false; // Could have a bad performance impact and could detect false positive,
										 // then try the method secureScanPath before enable this. BE CAREFUL
	public static $auto_block_tor = true; // If you want block TOR clients
	public static $auto_clean_global = false; // Global clean at start
	public static $auto_antidos = true; // Block the client ip when there are too many requests

	/**
	 * Security constructor.
	 */
	function __construct($API = false) {
		self::putInSafety($API);
	}

	/**
	 * Secure initialization
	 */
	public static function putInSafety($API = false) {

		if (!$API) {
			if (self::$auto_session_manager)
				self::secureSession();
			if (self::$auto_scanner)
				self::secureScan(self::$scanner_path);
			self::secureFormRequest();
		}

		if (self::$auto_antidos)
			self::secureDOS();

		self::secureRequest();
		self::secureBlockBots();

		if (self::$auto_block_tor)
			self::secureBlockTor();

		self::saveUnsafeGlobals();
		if (self::$auto_clean_global) {
			self::cleanGlobals();
		} else {
			$_SERVER = self::clean($_SERVER, false, false);
			$_COOKIE = self::clean($_COOKIE, false);
			$_GET = self::clean($_GET, false, false);
			$_REQUEST = self::clean($_REQUEST);
			$_REQUEST = array_merge($_REQUEST, $_GET);
			$_REQUEST = array_diff($_REQUEST, $_COOKIE);
		}

		self::secureHijacking();
		self::headers($API);
		self::secureCookies();

	}

	/**
	 * Custom session name for prevent fast identification of php
	 */
	public static function secureSession() {
		self::unsetCookie('PHPSESSID');

		ini_set("session.cookie_httponly", true);
		ini_set("session.use_trans_sid", false);
		ini_set('session.use_only_cookies', true);
		ini_set("session.cookie_secure", self::checkHTTPS());
		ini_set("session.gc_maxlifetime", self::$session_lifetime);

		session_name(self::$session_name);
		session_start();
		if (self::$session_regenerate_id)
			session_regenerate_id(true);
	}

	/**
	 * Clean all input globals received
	 * BE CAREFUL THIS METHOD COULD COMPROMISE HTML DATA IF SENT WITH INLINE JS
	 * (send with htmlentities could be a solution if you want send inline js and clean globals at the same time)
	 */
	public static function cleanGlobals() {
		self::saveUnsafeGlobals();
		$_SERVER = self::clean($_SERVER, false, false);
		$_COOKIE = self::clean($_COOKIE, false);
		$_GET = self::clean($_GET, false, false);
		$_POST = self::clean($_POST);
		$_REQUEST = array_merge($_GET, $_POST);
	}

	private static $savedGlobals = false;

	/**
	 * Save uncleaned globals
	 */
	private static function saveUnsafeGlobals() {
		if (!self::$savedGlobals) {
			$GLOBALS['UNSAFE_SERVER'] = $_SERVER;
			$GLOBALS['UNSAFE_COOKIE'] = $_COOKIE;
			$GLOBALS['UNSAFE_GET'] = $_GET;
			$GLOBALS['UNSAFE_POST'] = $_POST;
			$GLOBALS['UNSAFE_REQUEST'] = $_REQUEST;
			self::$savedGlobals = true;
		}
	}

	/**
	 * Restore unsafe globals
	 */
	public static function restoreGlobals(){
		$_SERVER = $GLOBALS['UNSAFE_SERVER'];
		$_COOKIE = $GLOBALS['UNSAFE_COOKIE'];
		$_GET = $GLOBALS['UNSAFE_GET'];
		$_POST = $GLOBALS['UNSAFE_POST'];
		$_REQUEST = $GLOBALS['UNSAFE_REQUEST'];
	}

	/**
	 * Userful to compare unsafe globals with safe globals
	 * @return array
	 */
	public static function debugGlobals(){
		$compare = array();
		// SERVER
		$compare['SERVER']['current'] = $_SERVER;
		$compare['SERVER']['unsafe'] = $GLOBALS['UNSAFE_SERVER'];
		$compare['SERVER']['safe'] = self::clean($GLOBALS['UNSAFE_SERVER']);
		// COOKIE
		$compare['COOKIE']['current'] = $_COOKIE;
		$compare['COOKIE']['unsafe'] = $GLOBALS['UNSAFE_COOKIE'];
		$compare['COOKIE']['safe'] = self::clean($GLOBALS['UNSAFE_COOKIE']);
		// GET
		$compare['GET']['current'] = $_GET;
		$compare['GET']['unsafe'] = $GLOBALS['UNSAFE_GET'];
		$compare['GET']['safe'] = self::clean($GLOBALS['UNSAFE_GET']);
		// POST
		$compare['POST']['current'] = $_POST;
		$compare['POST']['unsafe'] = $GLOBALS['UNSAFE_POST'];
		$compare['POST']['safe'] = self::clean($GLOBALS['UNSAFE_POST']);
		// REQUEST
		$compare['REQUEST']['current'] = $_REQUEST;
		$compare['REQUEST']['unsafe'] = $GLOBALS['UNSAFE_REQUEST'];
		$compare['REQUEST']['safe'] = self::clean($GLOBALS['UNSAFE_REQUEST']);
		return $compare;
	}

	/**
	 * Fix some elements on output buffer (to use with ob_start)
	 * @param $buffer
	 * @return string
	 */
	public static function output($buffer) {
		if (self::isHTML($buffer)) {
			self::secureCSRF();
			$buffer = self::secureHTML($buffer);
			$buffer = self::compressHTML($buffer);
		} else {
			self::headersCache();
			header('Content-Length: ' . strlen($buffer)); // For cache header
		}
		return $buffer;
	}

	/**
	 * Security Headers
	 */
	public static function headers($API = false) {
		// Headers
		@header("Accept-Encoding: gzip, deflate");
		@header("Strict-Transport-Security: max-age=16070400; includeSubDomains; preload");
		@header("X-UA-Compatible: IE=edge,chrome=1");
		@header("X-XSS-Protection: 1; mode=block");
		@header("X-Frame-Options: sameorigin");
		@header("X-Content-Type-Options: nosniff");
		@header("X-Permitted-Cross-Domain-Policies: master-only");
		@header("Referer-Policy: origin");
		@header("X-Download-Options: noopen");
		if (!$API) @header("Access-Control-Allow-Methods: GET, POST");
		else @header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE");

		header_remove("X-Powered-By");
		header_remove("Server");

		// Php settings
		ini_set('expose_php', 'off');
		ini_set('allow_url_fopen', 'off');
		ini_set('magic_quotes_gpc', 'off');
		ini_set('register_globals', 'off');
		ini_set('session.cookie_httponly', 'on');
		ini_set('session.use_only_cookies', 'on');
	}

	/**
	 * Security Cookies
	 */
	public static function secureCookies() {
		foreach ($_COOKIE as $key => $value) {
			//$value = self::clean(self::getCookie($key), false, false);
			//self::setCookie($key, $value, 0, '/; SameSite=Strict', null, false, true);
			if ($key != self::$session_name)
				setcookie($key, $value, 0, '/; SameSite=Strict', null, false, self::checkHTTPS());
		}
	}

	/**
	 * Check if the request is secure
	 */
	public static function secureRequest() {

		// Disable methods
		if (preg_match("/^(HEAD|TRACE|TRACK|DEBUG|OPTIONS)/i", $_SERVER['REQUEST_METHOD']))
			self::permission_denied();

		// Check REQUEST_URI
		$_REQUEST_URI = urldecode($_SERVER['REQUEST_URI']);
		if (preg_match("/(<|%3C)([^s]*s)+cript.*(>|%3E)/i", $_REQUEST_URI) ||
			preg_match("/(<|%3C)([^e]*e)+mbed.*(>|%3E)/i", $_REQUEST_URI) ||
			preg_match("/(<|%3C)([^o]*o)+bject.*(>|%3E)/i", $_REQUEST_URI) ||
			preg_match("/(<|%3C)([^i]*i)+frame.*(>|%3E)/i", $_REQUEST_URI) ||
			preg_match("/(<|%3C)([^o]*o)+bject.*(>|%3E)/i", $_REQUEST_URI) ||
			preg_match("/base64_(en|de)code[^(]*\([^)]*\)/i", $_REQUEST_URI) ||
			preg_match("/(%0A|%0D|\\r|\\n)/", $_REQUEST_URI) ||
			preg_match("/union([^a]*a)+ll([^s]*s)+elect/i", $_REQUEST_URI))
			self::permission_denied();

		// Check QUERY_STRING
		$_QUERY_STRING = urldecode($_SERVER['QUERY_STRING']);
		if (preg_match("/(<|%3C)([^s]*s)+cript.*(>|%3E)/i", $_QUERY_STRING) ||
			preg_match("/(<|%3C)([^e]*e)+mbed.*(>|%3E)/i", $_QUERY_STRING) ||
			preg_match("/(<|%3C)([^o]*o)+bject.*(>|%3E)/i", $_QUERY_STRING) ||
			preg_match("/(<|%3C)([^i]*i)+frame.*(>|%3E)/i", $_QUERY_STRING) ||
			preg_match("/(<|%3C)([^o]*o)+bject.*(>|%3E)/i", $_QUERY_STRING) ||
			preg_match("/base64_(en|de)code[^(]*\([^)]*\)/i", $_QUERY_STRING) ||
			preg_match("/(%0A|%0D|\\r|\\n)/i", $_QUERY_STRING) ||
			preg_match("/(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|%2e%2e%5c)/i", $_QUERY_STRING) ||
			preg_match("/(;|<|>|'|\"|\)|%0A|%0D|%22|%27|%3C|%3E|%00).*(\*|union|select|insert|cast|set|declare|drop|update|md5|benchmark).*/i", $_QUERY_STRING) ||
			preg_match("/union([^a]*a)+ll([^s]*s)+elect/i", $_QUERY_STRING))
			self::permission_denied();
	}


	/**
	 * Secure Form Request check if the referer is equal to the origin
	 */
	public static function secureFormRequest() {
		if ($_SERVER["REQUEST_METHOD"] == "POST") {
			$referer = $_SERVER["HTTP_REFERER"];
			if (!isset($referer) || strpos($_SERVER["SERVER_NAME"], $referer) != 0)
				self::permission_denied();
		}
	}

	/**
	 * Cache Headers
	 */
	public static function headersCache() {
		// Cache Headers
		$days_to_cache = self::$headers_cache_days * (60 * 60 * 24);
		$ts = gmdate("D, d M Y H:i:s", time() + $days_to_cache) . " GMT";
		@header("Expires: $ts");
		@header("Pragma: cache");
		@header("Cache-Control: max-age=$days_to_cache, must-revalidate");
	}

	/**
	 * Compress HTML
	 * @param $buf
	 * @return string
	 */
	public static function compressHTML($buf) {
		ini_set("zlib.output_compression", "On");
		ini_set("zlib.output_compression_level", "9");
		if (self::isHTML($buf))
			$buf = preg_replace(array('/<!--[^\[](.*)[^\]]-->/Uis', "/[[:blank:]]+/", '/\s+/'), array('', ' ', ' '), str_replace(array("\n", "\r", "\t"), '', $buf));
		return $buf;
	}

	/**
	 * Compress CSS
	 * @param $buffer
	 * @return string
	 */
	public static function compressCSS($buffer) {
		ini_set("zlib.output_compression", "On");
		ini_set("zlib.output_compression_level", "9");
		return preg_replace(array('#\/\*[\s\S]*?\*\/#', '/\s+/'), array('', ' '), str_replace(array("\n", "\r", "\t"), '', $buffer));
	}

	/**
	 * Compress Javascript
	 * @param $buffer
	 * @return string
	 */
	public static function compressJS($buffer) {
		ini_set("zlib.output_compression", "On");
		ini_set("zlib.output_compression_level", "9");
		return str_replace(array("\n", "\r", "\t"), '', preg_replace(array('#\/\*[\s\S]*?\*\/|([^:]|^)\/\/.*$#m', '/\s+/'), array('', ' '), $buffer));
	}

	/**
	 * Check if string is HTML
	 * @param $string
	 * @return bool
	 */
	public static function isHTML($string) {
		//return self::secureStripTagsContent($string) == '' ? true : false;
		return preg_match('/<html.*>/', $string) ? true : false;
	}

	/**
	 * Repair security issue on template
	 * @param $buffer
	 * @return string
	 */
	public static function secureHTML($buffer) {
		$doc = new DOMDocument();
		$doc->formatOutput = true;
		$doc->preserveWhiteSpace = false;
		$doc->loadHTML($buffer);

		$days_to_cache = self::$headers_cache_days * (60 * 60 * 24);
		$ts = gmdate("D, d M Y H:i:s", time() + $days_to_cache) . " GMT";
		$tags = $doc->getElementsByTagName('head');
		foreach ($tags as $tag) {

			$item = $doc->createElement("meta");
			$item->setAttribute("http-equiv", "cache-control");
			$item->setAttribute("content", "max-age=$days_to_cache, must-revalidate");
			$tag->appendChild($item);

			$item = $doc->createElement("meta");
			$item->setAttribute("http-equiv", "expires");
			$item->setAttribute("content", $ts);
			$tag->appendChild($item);

			$item = $doc->createElement("meta");
			$item->setAttribute("http-equiv", "pragma");
			$item->setAttribute("content", "cache");
			$tag->appendChild($item);
		}

		$tags = $doc->getElementsByTagName('input');
		foreach ($tags as $tag) {
			$type = array("text", "search", "password", "datetime", "date", "month", "week", "time", "datetime-local", "number", "range", "email", "color");
			if (in_array($tag->getAttribute('type'), $type)) {
				$tag->setAttribute("autocomplete", "off");
			}
		}

		$tags = $doc->getElementsByTagName('form');
		foreach ($tags as $tag) {
			$tag->setAttribute("autocomplete", "off");
			// CSRF
			$token = $_SESSION[self::$csrf_session];
			$item = $doc->createElement("input");
			$item->setAttribute("name", self::$csrf_formtoken);
			$item->setAttribute("type", "hidden");
			$item->setAttribute("value", self::stringEscape($token));
			$tag->appendChild($item);
		}

		$tags = $doc->getElementsByTagName('a');
		foreach ($tags as $tag) {
			$tag->setAttribute("rel", "noopener noreferrer");
		}
		$output = $doc->saveHTML();
		return $output;
	}

	/**
	 * Clean variables (recursive)
	 * @param $data
	 * @param bool $html
	 * @param bool $quotes
	 * @param bool $escape
	 * @return mixed
	 */
	public static function clean($data, $html = true, $quotes = true, $escape = true) {
		if (is_array($data)) {
			foreach ($data as $k => $v) {
				$data[$k] = self::clean($v, $html, $quotes, $escape);
			}
		} else {
			$data = self::secureVar($data, $html, $quotes, $escape);
		}
		return $data;
	}

	/**
	 * Clean variable
	 * @param $data
	 * @param bool $html
	 * @param bool $quotes
	 * @param bool $escape
	 * @return mixed
	 */
	private static function secureVar($data, $html = true, $quotes = true, $escape = true) {
		if (!$quotes) $data = str_replace(array('\'', '"'), '', $data);
		if (!$html) $data = self::stripTags(self::stripTagsContent($data));
		$data = self::cleanXSS($data);
		if ($escape && self::$escape_string) {
			$data = self::stripslashes($data);
			$data = self::stringEscape($data);
		}
		return $data;
	}

	/**
	 * String escape
	 * @param $data
	 * @return mixed
	 */
	public static function stringEscape($data) {
		if (is_array($data)) {
			foreach ($data as $k => $v) {
				$data[$k] = self::stringEscape($v);
			}
		} else {
			if (!empty($data) && is_string($data)) {
				$search = array("\\", "\x00", "\n", "\r", "'", '"', "\x1a");
				$replace = array("\\\\", "\\0", "\\n", "\\r", "\'", '\"', "\\Z");
				$data = str_replace($search, $replace, $data);
			}
		}
		return $data;
	}

	/**
	 * Strip tags recursive
	 * @param $data
	 * @return mixed
	 */
	public static function stripTags($data) {
		if (is_array($data)) {
			foreach ($data as $k => $v) {
				$data[$k] = self::stripTags($v);
			}
		} else {
			$data = trim(strip_tags($data));
		}
		return $data;
	}

	/**
	 * Trim recursive
	 * @param $data
	 * @return mixed
	 */
	public static function trim($data) {
		if (is_array($data)) {
			foreach ($data as $k => $v) {
				$data[$k] = self::trim($v);
			}
		} else {
			$data = trim($data);
		}
		return $data;
	}

	/**
	 * Strip tags and contents recursive
	 * @param $data
	 * @return mixed
	 */
	public static function stripTagsContent($data, $tags = '', $invert = false) {
		if (is_array($data)) {
			foreach ($data as $k => $v) {
				$data[$k] = self::stripTagsContent($v, $tags, $invert);
			}
		} else {
			$data = trim(self::_stripTagsContent($data, $tags, $invert));
		}
		return $data;
	}

	/**
	 * Strip tags and contents
	 * @param $text
	 * @param string $tags
	 * @param bool $invert
	 * @return string
	 */
	private static function _stripTagsContent($text, $tags = '', $invert = false) {
		preg_match_all('/<(.+?)[\s]*\/?[\s]*>/si', trim($tags), $tags);
		$tags = array_unique($tags[1]);
		if (is_array($tags) AND count($tags) > 0) {
			if ($invert == false) {
				return preg_replace('@<(?!(?:' . implode('|', $tags) . ')\b)(\w+)\b.*?>.*?</\1>@si', '', $text);
			} else {
				return preg_replace('@<(' . implode('|', $tags) . ')\b.*?>.*?</\1>@si', '', $text);
			}
		} elseif ($invert == false) {
			return preg_replace('@<(\w+)\b.*?>.*?</\1>@si', '', $text);
		}
		return $text;
	}

	/**
	 * XSS escape
	 * @param $data
	 * @return mixed
	 */
	public static function cleanXSS($data) {
		if (is_array($data)) {
			foreach ($data as $k => $v) {
				$data[$k] = self::cleanXSS($v);
			}
		} else {
			$data = self::stripXSS($data);
		}
		return $data;
	}

	/**
	 * Fix XSS
	 * @param $data
	 * @return string
	 */
	private static function stripXSS($data) {
		$data = str_replace(array("&amp;", "&lt;", "&gt;"), array("&amp;amp;", "&amp;lt;", "&amp;gt;"), $data);
		$data = preg_replace("/(&#*\w+)[- ]+;/u", "$1;", $data);
		$data = preg_replace("/(&#x*[0-9A-F]+);*/iu", "$1;", $data);
		$data = html_entity_decode($data, ENT_COMPAT, "UTF-8");
		$data = preg_replace('#(<[^>]+?[- "\'])(?:on|xmlns)[^>]*+>#iu', '$1>', $data);
		$data = preg_replace('#([a-z]*)[- ]*=[- ]*([`\'"]*)[- ]*j[- ]*a[- ]*v[- ]*a[- ]*s[- ]*c[- ]*r[- ]*i[- ]*p[- ]*t[- ]*:#iu', '$1=$2nojavascript', $data);
		$data = preg_replace('#([a-z]*)[- ]*=([\'"]*)[- ]*v[- ]*b[- ]*s[- ]*c[- ]*r[- ]*i[- ]*p[- ]*t[- ]*:#iu', '$1=$2novbscript', $data);
		$data = preg_replace('#([a-z]*)[- ]*=([\'"]*)[- ]*-moz-binding[- ]*:#u', '$1=$2nomozbinding', $data);
		$data = preg_replace('#(<[^>]+?)style[- ]*=[- ]*[`\'"]*.*?expression[- ]*\([^>]*+>#i', '$1>', $data);
		$data = preg_replace('#(<[^>]+?)style[- ]*=[- ]*[`\'"]*.*?behaviour[- ]*\([^>]*+>#i', '$1>', $data);
		$data = preg_replace('#(<[^>]+?)style[- ]*=[- ]*[`\'"]*.*?s[- ]*c[- ]*r[- ]*i[- ]*p[- ]*t[- ]*:*[^>]*+>#iu', '$1>', $data);
		$data = preg_replace('#</*\w+:\w[^>]*+>#i', '', $data);
		do {
			$old_data = $data;
			$data = preg_replace("#</*(?:applet|b(?:ase|gsound|link)|embed|frame(?:set)?|i(?:frame|layer)|l(?:ayer|ink)|meta|object|s(?:cript|tyle)|title|xml)[^>]*+>#i", "", $data);
		} while ($old_data !== $data);
		$data = str_replace(chr(0), '', $data);
		$data = preg_replace('%&\s*\{[^}]*(\}\s*;?|$)%', '', $data);
		//$data = str_replace('&', '&amp;', $data);
		$data = preg_replace('/&amp;#([0-9]+;)/', '&#\1', $data);
		$data = preg_replace('/&amp;#[Xx]0*((?:[0-9A-Fa-f]{2})+;)/', '&#x\1', $data);
		$data = preg_replace('/&amp;([A-Za-z][A-Za-z0-9]*;)/', '&\1', $data);
		return $data;
	}

	/**
	 * Stripslashes recursive
	 * @param $data
	 * @return mixed
	 */
	public static function stripslashes($data) {
		if (is_array($data)) {
			foreach ($data as $k => $v) {
				$data[$k] = self::stripslashes($v);
			}
		} else {
			if (get_magic_quotes_gpc()) $data = stripslashes($data);
		}
		return $data;
	}

	/**
	 * CSRF token compare only on POST REQUEST
	 */
	public static function secureCSRF() {
		if ($_SERVER["REQUEST_METHOD"] == "POST") {
			if (!self::secureCSRFCompare())
				self::permission_denied();
		}
		if (!isset($_SESSION[self::$csrf_session])) {
			self::secureCSRFGenerate();
		}
	}

	/**
	 * CSRF token compare
	 * @return bool
	 */
	private static function secureCSRFCompare() {
		$referer = $_SERVER["HTTP_REFERER"];
		if (!isset($referer)) return false;
		if (strpos($_SERVER["SERVER_NAME"], $referer) != 0) return false;
		$token = $_SESSION[self::$csrf_session];
		if ($_POST[self::$csrf_formtoken] == $token) {
			self::secureCSRFGenerate();
			return true;
		}
		return false;
	}

	/**
	 * Generate CSRF Token
	 */
	private static function secureCSRFGenerate() {
		$random = uniqid(mt_rand(1, mt_getrandmax()));
		$_SESSION[self::$csrf_session] = md5($random . time() . ":" . session_id());
	}

	/**
	 * Get CSRF Token
	 * @return mixed
	 */
	public static function secureCSRFToken() {
		$token = $_SESSION[self::$csrf_session];
		return $token;
	}

	/**
	 * Check if clients use Tor
	 * @return bool
	 */
	public static function clientIsTor() {
		$ip = self::clientIP();
		$ip_server = gethostbyname($_SERVER['SERVER_NAME']);

		$query = array(
			implode('.', array_reverse(explode('.', $ip))),
			$_SERVER["SERVER_PORT"],
			implode('.', array_reverse(explode('.', $ip_server))),
			'ip-port.exitlist.torproject.org'
		);

		$torExitNode = implode('.', $query);

		$dns = dns_get_record($torExitNode, DNS_A);

		if (array_key_exists(0, $dns) && array_key_exists('ip', $dns[0])) {
			if ($dns[0]['ip'] == '127.0.0.2') return true;
		}

		return false;
	}

	/**
	 * Block Tor clients
	 */
	public static function secureBlockTor() {
		if (self::clientIsTor())
			self::permission_denied();
	}

	/**
	 * Get Real IP Address
	 * @return string
	 */
	public static function clientIP() {
		foreach (
			array(
				'HTTP_CF_CONNECTING_IP',
				'HTTP_CLIENT_IP',
				'HTTP_X_FORWARDED_FOR',
				'HTTP_X_FORWARDED',
				'HTTP_X_CLUSTER_CLIENT_IP',
				'HTTP_FORWARDED_FOR',
				'HTTP_FORWARDED',
				'REMOTE_ADDR'
			) as $key) {
			if (array_key_exists($key, $_SERVER) === true) {
				foreach (explode(',', $_SERVER[$key]) as $ip) {
					if ($ip == "::1") return "127.0.0.1";
					return $ip;
				}
			}
		}
		return "0.0.0.0";
	}

	/**
	 * Prevent bad bots
	 */
	public static function secureBlockBots() {
		// Block bots
		if (preg_match("/(spider|crawler|slurp|teoma|archive|track|snoopy|lwp|client|libwww)/i", $_SERVER['HTTP_USER_AGENT']) ||
			preg_match("/(havij|libwww-perl|wget|python|nikto|curl|scan|java|winhttp|clshttp|loader)/i", $_SERVER['HTTP_USER_AGENT']) ||
			preg_match("/(%0A|%0D|%27|%3C|%3E|%00)/i", $_SERVER['HTTP_USER_AGENT']) ||
			preg_match("/(;|<|>|'|\"|\)|\(|%0A|%0D|%22|%27|%28|%3C|%3E|%00).*(libwww-perl|wget|python|nikto|curl|scan|java|winhttp|HTTrack|clshttp|archiver|loader|email|harvest|extract|grab|miner)/i", $_SERVER['HTTP_USER_AGENT']))
			self::permission_denied();
		// Block Fake google bot
		self::blockFakeGoogleBots();
	}

	/**
	 * Prevent Fake Google Bots
	 */
	private static function blockFakeGoogleBots() {
		$user_agent = (isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '');
		if (preg_match('/googlebot/i', $user_agent, $matches)) {
			$ip = self::clientIP();
			$name = gethostbyaddr($ip);
			$host_ip = gethostbyname($name);
			if (preg_match('/googlebot/i', $name, $matches)) {
				if ($host_ip != $ip)
					self::permission_denied();
			} else self::permission_denied();
		}
	}

	/**
	 * Hijacking prevention
	 */
	public static function secureHijacking() {
		if (!empty($_SESSION['HTTP_USER_TOKEN']) && $_SESSION['HTTP_USER_TOKEN'] != md5($_SERVER['HTTP_USER_AGENT'] . ':' . self::clientIP() . ':' . self::$hijacking_salt)) {
			session_unset();
			session_destroy();
			self::permission_denied();
		}

		$_SESSION['HTTP_USER_TOKEN'] = md5($_SERVER['HTTP_USER_AGENT'] . ':' . self::clientIP() . ':' . self::$hijacking_salt);
	}

	/**
	 * Secure Upload
	 * @param $file
	 * @param $path
	 * @return bool
	 */
	public static function secureUpload($file, $path) {
		if (!file_exists($path)) return false;
		if (!is_uploaded_file($_FILES[$file]["tmp_name"])) return false;
		if (!self::secureScanFile($_FILES[$file]["tmp_name"])) return false;
		if (move_uploaded_file($_FILES[$file]["tmp_name"], $path)) {
			return true;
		}
		return false;
	}

	/**
	 * Secure download
	 * @param $filename
	 */
	public static function secureDownload($filename) {
		ob_clean();
		header('Content-Type: application/x-octet-stream');
		header('Content-Transfer-Encoding: binary');
		header('Content-Disposition: attachment; filename="' . $filename . '";');
		echo file_get_contents($filename);
		ob_end_flush();
	}

	/**
	 * Crypt
	 * @param $action
	 * @param $string
	 * @return bool|string
	 */
	public static function crypt($action, $string) {
		$output = false;
		$encrypt_method = "AES-256-CBC";

		if (empty($_SESSION['HTTP_USER_KEY']))
			$_SESSION['HTTP_USER_KEY'] = md5(uniqid(mt_rand(1, mt_getrandmax()), true));

		$secret_key = $_SESSION['HTTP_USER_KEY'] . ':KEY';
		$secret_iv = $_SESSION['HTTP_USER_KEY'] . ':IV';

		$key = hash('sha512', $secret_key);
		$iv = substr(hash('sha512', $secret_iv), 0, 16);
		if ($action == 'encrypt') {
			$output = openssl_encrypt($string, $encrypt_method, $key, 0, $iv);
			$output = base64_encode($output);
		} else if ($action == 'decrypt') {
			$output = openssl_decrypt(base64_decode($string), $encrypt_method, $key, 0, $iv);
		}
		return $output;
	}

	/**
	 * Set Cookie
	 * @param $name
	 * @param $value
	 * @param int $expires
	 * @param string $path
	 * @param null $domain
	 * @param bool $secure
	 * @param bool $httponly
	 * @return bool
	 */
	public static function setCookie($name, $value, $expires = 2592000, $path = "/", $domain = null, $secure = false, $httponly = false) {
		if ($name != session_name()) {
			$newValue = self::crypt('encrypt', $value);
			if (!setcookie($name, $newValue, $expires, $path, $domain, $secure, $httponly)) return false;
			$_COOKIE[$name] = $value;
			return true;
		}
		return false;
	}

	/**
	 * Unset Cookie
	 * @param $name
	 * @return null
	 */
	public static function unsetCookie($name) {
		if (isset($_COOKIE[$name])) {
			unset($_COOKIE[$name]);
			setcookie($name, null, -1, '/');
		}
		return null;
	}

	/**
	 * Get Cookie
	 * @param $name
	 * @return null
	 */
	public static function getCookie($name) {
		if (isset($_COOKIE[$name])) {
			$cookie = self::crypt('decrypt', $_COOKIE[$name]);
			return $cookie;
		}
		return null;
	}

	/**
	 * Error 403
	 */
	private static function permission_denied($message = "") {
		ob_clean();
		http_response_code(403);
		die("Access Denied!<br>$message");
	}

	/**
	 * Error 404
	 */
	private static function not_found() {
		ob_clean();
		http_response_code(404);
		die("Not found!");
	}

	public static $SCAN_DEF = array("functions" =>
		array(
			"il_exec",
			"shell_exec",/*
				"eval",
				"exec",
				"create_function",
				"assert",
				"system",*/
			"syslog",
			"passthru",/*
				"dl",
				"define_syslog_variables",
				"debugger_off",
				"debugger_on",
				"stream_select",
				"parse_ini_file",*/
			"show_source",/*
				"symlink",
				"popen",*
				"posix_getpwuid",*/
			"posix_kill",/*
				"posix_mkfifo",
				"posix_setpgid",
				"posix_setsid",
				"posix_setuid",
				"posix_uname",*/
			"proc_close",/*
				"proc_get_status",
				"proc_nice",*/
			"proc_open",
			"proc_terminate",/*
				"ini_alter",
				"ini_get_all",
				"ini_restore",
				"parse_ini_file",*/
			"inject_code",
			"apache_child_terminate",/*
				"apache_setenv",
				"apache_note",
				"define_syslog_variables",
				"escapeshellarg",
				"escapeshellcmd",
				"ob_start",*/
		),
		"exploits" => array(
			"eval_chr" => "/chr\s*\(\s*101\s*\)\s*\.\s*chr\s*\(\s*118\s*\)\s*\.\s*chr\s*\(\s*97\s*\)\s*\.\s*chr\s*\(\s*108\s*\)/i",
			//"eval_preg" => "/(preg_replace(_callback)?|mb_ereg_replace|preg_filter)\s*\(.+(\/|\\x2f)(e|\\x65)['\"]/i",
			"align" => "/(\\\$\w+=[^;]*)*;\\\$\w+=@?\\\$\w+\(/i",
			"b374k" => "/'ev'\.'al'\.'\(\"\?>/i",  // b374k shell
			"weevely3" => "/\\\$\w=\\\$[a-zA-Z]\('',\\\$\w\);\\\$\w\(\);/i",  // weevely3 launcher
			"c99_launcher" => "/;\\\$\w+\(\\\$\w+(,\s?\\\$\w+)+\);/i",  // http://bartblaze.blogspot.fr/2015/03/c99shell-not-dead.html
			//"too_many_chr" => "/(chr\([\d]+\)\.){8}/i",  // concatenation of more than eight `chr()`
			//"concat" => "/(\\\$[^\n\r]+\.){5}/i",  // concatenation of more than 5 words
			//"concat_with_spaces" => "/(\\\$[^\\n\\r]+\. ){5}/i",  // concatenation of more than 5 words, with spaces
			//"var_as_func" => "/\\\$_(GET|POST|COOKIE|REQUEST|SERVER)\s*\[[^\]]+\]\s*\(/i",
			"escaped_path" => "/(\\x[0-9abcdef]{2}[a-z0-9.-\/]{1,4}){4,}/i",
			//"infected_comment" => "/\/\*[a-z0-9]{5}\*\//i", // usually used to detect if a file is infected yet
			"hex_char" => "/\\[Xx](5[Ff])/i",
			"download_remote_code" => "/echo\s+file_get_contents\s*\(\s*base64_url_decode\s*\(\s*@*\\\$_(GET|POST|SERVER|COOKIE|REQUEST)/i",
			"globals_concat" => "/\\\$GLOBALS\[\\\$GLOBALS['[a-z0-9]{4,}'\]\[\d+\]\.\\\$GLOBALS\['[a-z-0-9]{4,}'\]\[\d+\]./i",
			"globals_assign" => "/\\\$GLOBALS\['[a-z0-9]{5,}'\] = \\\$[a-z]+\d+\[\d+\]\.\\\$[a-z]+\d+\[\d+\]\.\\\$[a-z]+\d+\[\d+\]\.\\\$[a-z]+\d+\[\d+\]\./i",
			"php_inline_long" => "/^.*<\?php.{1000,}\?>.*$/i",
			"base64_long" => "/['\"][A-Za-z0-9+\/]{260,}={0,3}['\"]/",
			"clever_include" => "/include\s*\(\s*[^\.]+\.(png|jpe?g|gif|bmp)/i",
			"basedir_bypass" => "/curl_init\s*\(\s*[\"']file:\/\//i",
			"basedir_bypass2" => "/file\:file\:\/\//i", // https://www.intelligentexploit.com/view-details.html?id=8719
			"non_printable" => "/(function|return|base64_decode).{,256}[^\\x00-\\x1F\\x7F-\\xFF]{3}/i",
			"double_var" => "/\\\${\s*\\\${/i",
			"double_var2" => "/\${\$[0-9a-zA-z]+}/i",
			"hex_var" => "/\\\$\{\\\"\\\\x/i", // check for ${"\xFF"}, IonCube use this method ${"\x
			"register_function" => "/register_[a-z]+_function\s*\(\s*['\\\"]\s*(eval|assert|passthru|exec|include|system|shell_exec|`)/i",  // https://github.com/nbs-system/php-malware-finder/issues/41
			"safemode_bypass" => "/\\x00\/\.\.\/|LD_PRELOAD/i",
			"ioncube_loader" => "/IonCube\_loader/i"
		)
	);

	/**
	 * File scanner
	 * @param $pattern
	 * @return boolean
	 */
	public static function secureScanFile($file) {

		$contents = file_get_contents($file);

		if (empty($file) || !file_exists($file))
			return false;

		foreach (self::$scanner_whitelist as $value) {
			$value = trim(realpath($value));
			if (!empty($value) && (preg_match('#' . preg_quote($value) . '#i', realpath(dirname($file)))
					|| preg_match('#' . preg_quote($value) . '#i', realpath($file))))
				return true;
		}

		foreach (self::$SCAN_DEF["exploits"] as $pattern) {
			if (@preg_match($pattern, $contents))
				return false;
		}

		$contents = preg_replace("/<\?php(.*?)(?!\B\"[^\"]*)\?>(?![^\"]*\"\B)/si", "$1", $contents); // Only php code
		$contents = preg_replace("/\/\*.*?\*\/|\/\/.*?\n|\#.*?\n/i", "", $contents); // Remove comments
		$contents = preg_replace("/('|\")[\s\r\n]*\.[\s\r\n]*('|\")/i", "", $contents); // Remove "ev"."al"
		if (preg_match("/^text/i", mime_content_type($file))) {
			foreach (self::$SCAN_DEF["functions"] as $pattern) {
				if (@preg_match("/(" . $pattern . ")[\s\r\n]*()/i", $contents))
					return false;
				if (@preg_match("/(" . preg_quote(base64_encode($pattern)) . ")/i", $contents))
					return false;
				$field = bin2hex($pattern);
				$field = chunk_split($field, 2, "\\x");
				$field = "\\x" . substr($field, 0, -2);
				if (@preg_match("/(" . $field . ")/i", $contents))
					return false;
				//return array($pattern,realpath($file));
			}
		}
		return true;
	}

	/**
	 * Directory scanner
	 * @param $pattern
	 * @return array
	 */
	public static function secureScanPath($path) {
		$potentially_infected = array();
		if (empty($path) || !glob($path))
			return array();
		$files = self::recursiveGlob($path);
		foreach ($files as $file) {
			if (!self::secureScanFile($file))
				$potentially_infected[] = $file;
		}
		return $potentially_infected;
	}

	/**
	 * Scan and rename bad files
	 * @param $pattern
	 */
	public static function secureScan($path) {
		$files = self::secureScanPath($path);
		foreach ($files as $file) {
			rename($file, $file . ".bad");
		}
	}

	/**
	 * Glob recursive
	 * @param $pattern
	 * @param int $flags
	 * @return array
	 */
	private static function recursiveGlob($pattern, $flags = 0) {
		$files = glob($pattern, $flags);
		foreach (glob(dirname($pattern) . '/*', GLOB_ONLYDIR | GLOB_NOSORT) as $dir) {
			$files = array_merge($files, self::recursiveGlob($dir . '/' . basename($pattern), $flags));
		}
		return $files;
	}

	/**
	 * Check if the request is HTTPS
	 */
	private static function checkHTTPS() {
		if ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || $_SERVER['SERVER_PORT'] == 443) {
			return true;
		}
		return false;
	}

	/**
	 * Write on htaccess the DOS Attempts
	 * @param $ip
	 * @param $content
	 */
	private static function secureDOSWriteAttempts($ip, $file_attempts) {
		$ip_quote = preg_quote($ip);
		$content = @file_get_contents($file_attempts);
		if (preg_match("/### BEGIN: DOS Attempts ###[\S\s.]*# $ip_quote => ([0-9]+):([0-9]+):([0-9]+):([0-9]+)[\S\s.]*### END: DOS Attempts ###/i", $content, $attemps)) {
			$row_replace = "# $ip => " . $_SESSION['DOSAttemptsTimer'] . ":" . $_SESSION['DOSAttempts'] . ":" . $_SESSION['DOSCounter'] . ":" . $_SESSION['DOSTimer'];
			$content = preg_replace("/(### BEGIN: DOS Attempts ###[\S\s.]*)(# $ip_quote => [0-9]+:[0-9]+:[0-9]+:[0-9]+)([\S\s.]*### END: DOS Attempts ###)/i",
				"$1$row_replace$3", $content);
		} else if (preg_match("/### BEGIN: DOS Attempts ###([\S\s.]*)### END: DOS Attempts ###/i", $content)) {
			$row = "# $ip => " . $_SESSION['DOSAttemptsTimer'] . ":" . $_SESSION['DOSAttempts'] . ":" . $_SESSION['DOSCounter'] . ":" . $_SESSION['DOSTimer'];
			$content = preg_replace("/(### BEGIN: DOS Attempts ###)([\S\s.]*)([\r\n]+### END: DOS Attempts ###)/i",
				"$1$2$row$3", $content);
		} else {
			$content .= "### BEGIN: DOS Attempts ###";
			$content .= "\r\n# $ip => " . $_SESSION['DOSAttemptsTimer'] . ":" . $_SESSION['DOSAttempts'] . ":" . $_SESSION['DOSCounter'] . ":" . $_SESSION['DOSTimer'];
			$content .= "\r\n### END: DOS Attempts ###";
		}
		file_put_contents($file_attempts, $content);
	}

	/**
	 * Remove from htaccess the DOS Attempts
	 * @param $ip
	 * @param $content
	 */
	private static function secureDOSRemoveAttempts($ip, $file_attempts) {
		$ip_quote = preg_quote($ip);
		$content = @file_get_contents($file_attempts);
		if (preg_match("/### BEGIN: DOS Attempts ###[\S\s.]*[\r\n]+# $ip_quote => ([0-9]+):([0-9]+):([0-9]+):([0-9]+)[\S\s.]*### END: DOS Attempts ###/i", $content, $attemps)) {
			$content = preg_replace("/(### BEGIN: DOS Attempts ###[\S\s.]*)([\r\n]+# $ip_quote => [0-9]+:[0-9]+:[0-9]+:[0-9]+)([\S\s.]*### END: DOS Attempts ###)/i", "$1$3", $content);
		}
		file_put_contents($file_attempts, $content);
	}

	/**
	 * Remove from htaccess the DOS Attempts
	 * @param $ip
	 * @param $content
	 */
	private static function secureDOSRemoveOldAttempts($time_expire, $file_attempts) {
		$time = $_SERVER['REQUEST_TIME'];
		$pattern = "/# ((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])) => ([0-9]+):([0-9]+):([0-9]+):([0-9]+)[\r\n]+/i";
		$content = @file_get_contents($file_attempts);
		if (preg_match_all($pattern, $content, $attemps)) {
			foreach ($attemps as $attemp) {
				preg_match($pattern, $attemp[0], $attemp);
				$ip_quote = preg_quote($attemp[1]);
				if ($time > $attemp[5] + $time_expire || $time > $attemp[8] + $time_expire)
					$content = preg_replace("/(### BEGIN: DOS Attempts ###[\S\s.]*)([\r\n]+# $ip_quote => [0-9]+:[0-9]+:[0-9]+:[0-9]+)([\S\s.]*### END: DOS Attempts ###)/i", "$1$3", $content);
			}
		}
		file_put_contents($file_attempts, $content);
	}

	/**
	 * Read from htaccess the DOS Attempts
	 * @param $ip
	 * @param $content
	 */
	private static function secureDOSReadAttempts($ip, $content) {
		$ip_quote = preg_quote($ip);
		if (preg_match("/### BEGIN: DOS Attempts ###[\S\s.]*[\r\n]+# $ip_quote => ([0-9]+):([0-9]+):([0-9]+):([0-9]+)[\S\s.]*### END: DOS Attempts ###/i", $content, $attemps)) {
			$_SESSION['DOSAttemptsTimer'] = $attemps[1];
			$_SESSION['DOSAttempts'] = $attemps[2];
			$_SESSION['DOSCounter'] = $attemps[3];
			$_SESSION['DOSTimer'] = $attemps[4];
		}
	}

	/**
	 * Block DOS Attacks
	 */
	public static function secureDOS() {

		$time_counter = 2;
		$time_waiting = 10;
		$time_expire = 3600;

		$time = $_SERVER['REQUEST_TIME'];
		$ip = self::clientIP();
		$htaccess = realpath(self::$basedir . "/.htaccess");
		$file_attempts = realpath(self::$basedir) . "/.ddos";
		$content = @file_get_contents($file_attempts);
		self::secureDOSRemoveOldAttempts($time_expire, $file_attempts);

		if (!isset($_SESSION['DOSCounter']) || !isset($_SESSION['DOSAttempts']) || empty($_SESSION['DOSAttemptsTimer']) || empty($_SESSION['DOSTimer'])) {
			self::secureDOSReadAttempts($ip, $file_attempts);
			$_SESSION['DOSCounter'] = 0;
			$_SESSION['DOSAttempts'] = 0;
			$_SESSION['DOSAttemptsTimer'] = $time;
			$_SESSION['DOSTimer'] = $time;
			self::secureDOSWriteAttempts($ip, $file_attempts);
		} else if ($_SESSION['DOSTimer'] != $time) {

			if ($time > $_SESSION['DOSTimer'] + $time_expire)
				$_SESSION['DOSAttempts'] = 0;

			if ($_SESSION['DOSCounter'] >= 10 && $_SESSION['DOSAttempts'] < 2) {
				if ($time > $_SESSION['DOSTimer'] + $time_waiting) {
					$_SESSION['DOSAttempts'] = $_SESSION['DOSAttempts'] + 1;
					$_SESSION['DOSAttemptsTimer'] = $time;
					$_SESSION['DOSTimer'] = $time;
					$_SESSION['DOSCounter'] = 0;
				} else {
					$url = (isset($_SERVER['HTTPS']) ? "https" : "http") . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
					$seconds = round(($_SESSION['DOSTimer'] + $time_waiting) - time());
					if ($seconds < 1) header("Location: {$url}");
					header("Refresh: {$seconds}; url={$url}");

					self::permission_denied('You must wait ' . $seconds . ' seconds...');
				}
				self::secureDOSWriteAttempts($ip, $file_attempts);
			} else if ($_SESSION['DOSCounter'] >= 10 && $_SESSION['DOSAttempts'] > 1) {
				$htaccess_content = file_get_contents($htaccess);
				if (preg_match("/### BEGIN: BANNED IPs ###\n/i", $content)) {
					$htaccess_content = preg_replace("/(### BEGIN: BANNED IPs ###[\r\n]+)([\S\s.]*?)([\r\n]+### END: BANNED IPs ###)/i", "$1$2\r\nDeny from $ip$3", $htaccess_content);
				} else {
					$htaccess_content .= "\r\n\r\n### BEGIN: BANNED IPs ###\r\n";
					$htaccess_content .= "Order Allow,Deny\r\n";
					$htaccess_content .= "Deny from $ip\r\n";
					$htaccess_content .= "### END: BANNED IPs ###";
				}
				file_put_contents($htaccess, $htaccess_content);
				self::secureDOSRemoveAttempts($ip, $file_attempts);
			} else {
				if ($_SESSION['DOSTimer'] > ($time - $time_counter)) {
					$_SESSION['DOSCounter'] = $_SESSION['DOSCounter'] + 1;
				} else {
					$_SESSION['DOSCounter'] = 0;
				}
				$_SESSION['DOSTimer'] = $time;
				self::secureDOSWriteAttempts($ip, $file_attempts);
			}
		}
	}

	/**
	 * Generate strong password
	 * @param int $length
	 * @param bool $add_dashes
	 * @param string $available_sets
	 * @return bool|string
	 */
	function generatePassword($length = 8, $add_dashes = false, $available_sets = 'luns') {
		$sets = array();
		// lowercase
		if (strpos($available_sets, 'l') !== false)
			$sets[] = 'abcdefghjkmnpqrstuvwxyz';
		// uppercase
		if (strpos($available_sets, 'u') !== false)
			$sets[] = 'ABCDEFGHJKMNPQRSTUVWXYZ';
		// numbers
		if (strpos($available_sets, 'n') !== false)
			$sets[] = '0123456789';
		// special chars
		if (strpos($available_sets, 's') !== false)
			$sets[] = '!@#$%&*?';
		$all = '';
		$password = '';
		foreach ($sets as $set) {
			$password .= $set[array_rand(str_split($set))];
			$all .= $set;
		}
		$all = str_split($all);
		for ($i = 0; $i < $length - count($sets); $i++)
			$password .= $all[array_rand($all)];
		$password = str_shuffle($password);
		if (!$add_dashes)
			return $password;
		$dash_len = floor(sqrt($length));
		$dash_str = '';
		while (strlen($password) > $dash_len) {
			$dash_str .= substr($password, 0, $dash_len) . '-';
			$password = substr($password, $dash_len);
		}
		$dash_str .= $password;
		return $dash_str;
	}
}
