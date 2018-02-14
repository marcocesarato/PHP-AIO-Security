<?php
/**
 * Security Class
 * @category  Security
 * @author    Marco Cesarato <cesarato.developer@gmail.com>
 * @copyright Copyright (c) 2015-2018
 * @license   http://opensource.org/licenses/gpl-3.0.html GNU Public License
 * @version   0.1.1
 */
class Security
{
	private static $csrf_session = "enicsrf_token";
	private static $csrf_formtoken = "eniform_token";
	private static $hijacking_salt = "ENI";
	private static $headers_cache_days = 30;
	private static $escape_string = true; // If you use PDO I recommend to set this to false
	/**
	 * Security constructor.
	 */
	function __construct() {
		self::putInSafety();
	}
	/**
	 * Secure initialization
	 */
	public static function putInSafety() {
		$_GET = self::clean($_GET, false, false);
		$_REQUEST = array_diff($_REQUEST, $_COOKIE);
		$_REQUEST = self::clean($_REQUEST);
		self::secureHijacking();
		self::headers();
		self::headersCache();
		self::secureCookies();
	}
	/**
	 * Clean all input globals received
	 * ### BE CAREFUL THIS METHOD COULD COMPROMISE HTML DATA ###
	 */
	public static function cleanGlobals() {
		$_COOKIE = self::clean($_COOKIE);
		$_GET = self::clean($_GET, false, false);
		$_POST = self::clean($_POST);
		$_REQUEST = array_merge($_GET,$_POST);
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
		}
		$buffer = self::secureCSRFPrint($buffer);
		header('Content-Length: ' . strlen($buffer)); // For cache header
		return $buffer;
	}
	/**
	 * Security Headers
	 */
	public static function headers() {
		// Headers
		@header("Accept-Encoding: gzip, deflate");
		@header("Strict-Transport-Security: max-age=16070400; includeSubDomains");
		@header("X-UA-Compatible: IE=edge,chrome=1"); // MIE
		@header("X-XSS-Protection: 1; mode=block");
		@header("X-Frame-Options: sameorigin");
		@header("X-Content-Type-Options: nosniff");
		@header("X-Permitted-Cross-Domain-Policies: master-only");
		@header("Referer-Policy: origin");
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
			$value = self::clean($value, false, false);
			$_COOKIE[$key] = $value;
			setcookie($key, $value, 0, '/; SameSite=Strict');
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
		if (!$html) $data = self::recursiveStripTagsContent($data);
		$data = self::cleanXSS($data);
		if($escape && self::$escape_string) {
			$data = self::recursiveStripslashes($data);
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
	 * Strip tags and contents recursive
	 * @param $data
	 * @return mixed
	 */
	public static function recursiveStripTagsContent($data, $tags = '', $invert = false) {
		if (is_array($data)) {
			foreach ($data as $k => $v) {
				$data[$k] = self::recursiveStripTagsContent($v, $tags, $invert);
			}
		} else {
			$data = trim(self::stripTagsContent($data, $tags, $invert));
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
	private static function stripTagsContent($text, $tags = '', $invert = false) {
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
		$data = str_replace('&', '&amp;', $data);
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
	public static function recursiveStripslashes($data) {
		if (is_array($data)) {
			foreach ($data as $k => $v) {
				$data[$k] = self::recursiveStripslashes($v);
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
			if (!self::secureCSRFCompare()) {
				http_response_code(403);
				die("Permission denied!");
			}
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
			return true;
		} else {
			return false;
		}
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
	 * Print CSRF token as hidden input
	 * @param $output
	 * @return mixed
	 */
	private static function secureCSRFPrint($output) {
		$token = $_SESSION[self::$csrf_session];
		$input = '<input type="hidden" name="' . self::$csrf_formtoken . '" value="' . self::stringEscape($token) . '">';
		$output = preg_replace("/(<([^>]*)\/form([^>]*)>)/i", $input . "$1", $output);
		return $output;
	}
	/**
	 * Get Real IP Address
	 * @return string
	 */
	public static function clientIP() {
		if ($_SERVER['HTTP_CLIENT_IP'])
			$ipaddress = $_SERVER['HTTP_CLIENT_IP'];
		else if ($_SERVER['HTTP_X_FORWARDED_FOR'])
			$ipaddress = $_SERVER['HTTP_X_FORWARDED_FOR'];
		else if ($_SERVER['HTTP_X_FORWARDED'])
			$ipaddress = $_SERVER['HTTP_X_FORWARDED'];
		else if ($_SERVER['HTTP_FORWARDED_FOR'])
			$ipaddress = $_SERVER['HTTP_FORWARDED_FOR'];
		else if ($_SERVER['HTTP_FORWARDED'])
			$ipaddress = $_SERVER['HTTP_FORWARDED'];
		else if ($_SERVER['REMOTE_ADDR'])
			$ipaddress = $_SERVER['REMOTE_ADDR'];
		else
			$ipaddress = '0.0.0.0';
		return $ipaddress;
	}
	/**
	 * Hijacking prevention
	 */
	private static function secureHijacking() {
		if (!empty($_SESSION['HTTP_USER_TOKEN']) && $_SESSION['HTTP_USER_TOKEN'] != md5($_SERVER['HTTP_USER_TOKEN'] . ':' . self::clientIP() . ':' . self::$hijacking_salt)) {
			http_response_code(403);
			die("Permission denied!");
		}
		$_SESSION['HTTP_USER_TOKEN'] = md5($_SERVER['HTTP_USER_TOKEN'] . ':' . self::clientIP() . ':' . self::$hijacking_salt);
	}
	/**
	 * Secure Upload
	 * @param $file
	 * @param $path
	 * @return bool
	 */
	public static function secureUpload($file, $path) {
		if (!file_exists($file)) return false;
		if (!is_uploaded_file($_FILES[$file]["tmp_name"])) return false;
		if (move_uploaded_file($_FILES[$file]["tmp_name"], $path)) {
			return true;
		} else {
			return false;
		}
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
	public static function setCookie($name, $value, $expires = 2592000, $path = "/", $domain = null, $secure = false, $httponly = true) {
		$newValue = self::crypt('encrypt', $value);
		if (!setcookie($name, $newValue, $expires, $path, $domain, $secure, $httponly)) return false;
		return true;
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
		} else {
			return NULL;
		}
	}
}
