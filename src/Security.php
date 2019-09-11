<?php

/**
 * AIO Security Class
 * @category  Security
 * @author    Marco Cesarato <cesarato.developer@gmail.com>
 * @copyright Copyright (c) 2014-2019
 * @license   http://opensource.org/licenses/gpl-3.0.html GNU Public License
 * @link      https://github.com/marcocesarato/PHP-AIO-Security-Class
 * @version   0.2.8.179
 */

namespace marcocesarato\security {

	/**
	 * Class Security
	 * @package marcocesarato\security
	 */
	class Security {

		/*********************************************
		 *             Security settings
		 *  Change these settings based on your needs
		 *********************************************/

		public static $basedir = __DIR__; // Project basedir where is located .htaccess
		public static $salt = "_SALT"; // Salt for crypt
		public static $session_name = "XSESSID"; // Session cookie name
		public static $session_lifetime = 288000; // Session lifetime | default = 8 hours
		public static $session_regenerate_id = false; // Regenerate session id
		public static $session_database = false; // Store sessions on database
		public static $csrf_session = "_CSRFTOKEN"; // CSRF session token name
		public static $csrf_formtoken = "_FORMTOKEN"; // CSRF form token input name
		public static $cookies_encrypted = false; // Encrypt cookies (need Security::setCookie for encrypt) [PHP 5.3+]
		public static $cookies_enc_prefix = 'SEC_'; // Cookies encrypted prefix
		public static $headers_cache = false; // Enable header cache (CARE SOME HOST DON'T PERMIT IT)
		public static $headers_cache_days = 30; // Cache on NO HTML response (set 0 to disable)
		public static $escape_string = true; // If you use \PDO I recommend to set this to false
		public static $clean_post_xss = true; // Remove XSS on post global
		public static $compress_output = true; // Compress output
		public static $force_https = false; // Force HTTPS
		public static $hide_errors = true; // Hide php errors (useful for hide vulnerabilities)
		public static $database = null; // \PDO instance

		// Autostart
		public static $auto_session_manager = true; // Run session at start
		public static $auto_cookies_decrypt = false; // Auto encrypt cookies [PHP 5.3+]

		public static $auto_block_tor = true; // If you want block TOR clients
		public static $auto_clean_global = false; // Global clean at start
		public static $auto_antidos = true; // Block the client ip when there are too many requests

		// Error Template
		public static $error_callback = null; // Set a callback on errors
		public static $error_template = '<html><head><title>${ERROR_TITLE}</title></head><body>${ERROR_BODY}</body></html>';

		/*******************************************/

		// Protected
		protected static $_salt_encoded = null;

		// Private
		private static $_saved_unsafe_glob = false;
		private static $_UNSAFE_GLOB = array();

		/**
		 * Security constructor.
		 * @param bool $API
		 */
		function __construct($API = false) {
			self::putInSafety($API);
		}

		/**
		 * Set \PDO database instance
		 * @param $db
		 */
		public static function setDatabase($db) {
			self::$database = $db;
		}

		/**
		 * Secure initialization
		 * @param bool $API
		 */
		public static function putInSafety($API = false) {

			@ob_start();

			if(self::$hide_errors) {
				ini_set('display_errors', 0);
				ini_set('display_startup_errors', 0);
				error_reporting(0);
			}

			if(self::$force_https && !self::checkHTTPS()) {
				$redirect = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
				header('HTTP/1.1 301 Moved Permanently');
				header('Location: ' . $redirect);
				die();
			}

			if(self::$auto_session_manager) {
				self::secureSession();
			}

			if(!$API) {
				if(self::$auto_cookies_decrypt) {
					self::secureCookies();
				}
				self::secureFormRequest();
				self::secureCSRF();
			}

			if(self::$auto_antidos) {
				self::secureDOS();
			}

			self::secureRequest();
			self::secureBlockBots();

			if(self::$auto_block_tor) {
				self::secureBlockTor();
			}

			self::saveUnsafeGlobals();
			if(self::$auto_clean_global) {
				self::cleanGlobals();
			}

			self::secureHijacking();
			self::headers($API);

		}

		/**
		 * Get Salt
		 * @return bool|string
		 */
		protected static function getSalt() {
			if(empty(self::$_salt_encoded)) {
				$required_salt_len   = 22;
				$base64_digits       = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
				$bcrypt64_digits     = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
				$base64_string       = base64_encode(self::$salt);
				$salt                = strtr(rtrim($base64_string, '='), $base64_digits, $bcrypt64_digits);
				$salt                = substr($salt, 0, $required_salt_len);
				self::$_salt_encoded = $salt;
			}

			return self::$_salt_encoded;
		}

		/**
		 * Custom session name for prevent fast identification of php
		 */
		public static function secureSession() {
			self::unsetCookie('PHPSESSID');

			$session_hash = "sha512";

			ini_set('session.use_cookies', 1);
			ini_set('session.use_only_cookies', 1);
			ini_set("session.cookie_httponly", 1);
			ini_set("session.use_trans_sid", 0);
			ini_set("session.cookie_secure", self::checkHTTPS() ? 1 : 0);
			ini_set("session.gc_maxlifetime", self::$session_lifetime);
			if(in_array($session_hash, hash_algos())) {
				ini_set("session.hash_function", $session_hash);
			}
			ini_set("session.hash_bits_per_character", 8);

			session_name(self::$session_name);

			if(self::$session_database && self::$database) {
				// Set handler to override SESSION
				session_set_save_handler(
					array(__CLASS__, "_session_open"),
					array(__CLASS__, "_session_close"),
					array(__CLASS__, "_session_read"),
					array(__CLASS__, "_session_write"),
					array(__CLASS__, "_session_destroy"),
					array(__CLASS__, "_session_gc")
				);

				if(!in_array('sessions', self::$database->getTables())) {
					self::$database->query('CREATE TABLE sessions (
								id VARCHAR(128) NOT NULL,
								access INT(10) UNSIGNED,
								data TEXT NULL DEFAULT NULL,
								client_ip VARCHAR(15) NULL DEFAULT NULL,
								PRIMARY KEY (id)
							);'
					);
				}
			}

			// Start the session
			session_start();

			if(self::$session_regenerate_id) {
				session_regenerate_id(true);
			}

		}

		/**
		 * Fix some elements on output buffer (to use with ob_start)
		 * @param $buffer
		 * @param string $type
		 * @param null $cache_days
		 * @param bool $compress
		 * @return string
		 */
		public static function output($buffer, $type = 'html', $cache_days = null, $compress = true) {

			if(self::$headers_cache) {
				self::headersCache($cache_days);
			}

			$compress_output = (self::$compress_output && $compress);

			if($type == 'html' && self::isHTML($buffer)) {
				header("Content-Type: text/html");
				$buffer = self::secureHTML($buffer);
				if($compress_output) {
					$buffer = self::compressHTML($buffer);
				}
			} elseif($type == 'css') {
				header("Content-type: text/css");
				if($compress_output) {
					$buffer = self::compressCSS($buffer);
				}
			} elseif($type == 'csv') {
				header("Content-type: text/csv");
				header("Content-Disposition: attachment; filename=file.csv");
				if($compress_output) {
					$buffer = self::compressOutput($buffer);
				}
			} elseif($type == 'js' || $type == 'javascript') {
				header('Content-Type: application/javascript');
				if($compress_output) {
					$buffer = self::compressJS($buffer);
				}
			} elseif($type == 'json' && json_decode($buffer) != false) {
				header('Content-Type: application/json');
				if($compress_output) {
					$buffer = self::compressOutput($buffer);
				}
			} elseif($type == 'xml') {
				header('Content-Type: text/xml');
				if($compress_output) {
					$buffer = self::compressHTML($buffer);
				}
			} elseif($type == 'text' || $type == 'txt') {
				header("Content-Type: text/plain");
				if($compress_output) {
					$buffer = self::compressOutput($buffer);
				}
			} else {
				if($compress_output) {
					$buffer = self::compressOutput($buffer);
				}
			}

			if(self::$headers_cache) {
				@header('Content-Length: ' . strlen($buffer));
			} // For cache header

			return $buffer;
		}

		/**
		 * Security Headers
		 * @param bool $API
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
			if(!$API) {
				@header("Access-Control-Allow-Methods: GET, POST");
			} else {
				@header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE");
			}

			header_remove("X-Powered-By");
			header_remove("Server");

			// Php settings
			ini_set('expose_php', 0);
			ini_set('allow_url_fopen', 0);
			ini_set('magic_quotes_gpc', 0);
			ini_set('register_globals', 0);
		}

		/**
		 * Cache Headers
		 * @param null $cache_days
		 */
		public static function headersCache($cache_days = null) {
			// Cache Headers
			$days_to_cache = (($cache_days == null) ? self::$headers_cache_days : $cache_days) * (60 * 60 * 24);
			$ts            = gmdate("D, d M Y H:i:s", time() + $days_to_cache) . " GMT";
			@header("Expires: $ts");
			@header("Pragma" . ($days_to_cache > 0) ? "cache" : "no-cache");
			@header("Cache-Control: max-age=$days_to_cache, must-revalidate");
		}

		/**
		 * Security Cookies
		 */
		public static function secureCookies() {
			foreach($_COOKIE as $key => $value) {
				if($key != self::$session_name && self::isBase64($value)) {
					$value         = self::getCookie($key);
					$_COOKIE[$key] = $value;
				}
			}
		}

		/**
		 * Check if the request is secure
		 */
		public static function secureRequest() {

			// Disable methods
			if(preg_match("/^(HEAD|TRACE|TRACK|DEBUG|OPTIONS)/i", $_SERVER['REQUEST_METHOD'])) {
				self::error(403, 'Permission denied!');
			}

			// Check REQUEST_URI
			$_REQUEST_URI = urldecode($_SERVER['REQUEST_URI']);
			if(preg_match("/(<|%3C)([^s]*s)+cript.*(>|%3E)/i", $_REQUEST_URI) ||
			   preg_match("/(<|%3C)([^e]*e)+mbed.*(>|%3E)/i", $_REQUEST_URI) ||
			   preg_match("/(<|%3C)([^o]*o)+bject.*(>|%3E)/i", $_REQUEST_URI) ||
			   preg_match("/(<|%3C)([^i]*i)+frame.*(>|%3E)/i", $_REQUEST_URI) ||
			   preg_match("/(<|%3C)([^o]*o)+bject.*(>|%3E)/i", $_REQUEST_URI) ||
			   preg_match("/base64_(en|de)code[^(]*\([^)]*\)/i", $_REQUEST_URI) ||
			   preg_match("/(%0A|%0D|\\r|\\n)/", $_REQUEST_URI) ||
			   preg_match("/union([^a]*a)+ll([^s]*s)+elect/i", $_REQUEST_URI)) {
				self::error(403, 'Permission denied!');
			}

			// Check QUERY_STRING
			$_QUERY_STRING = urldecode($_SERVER['QUERY_STRING']);
			if(preg_match("/(<|%3C)([^s]*s)+cript.*(>|%3E)/i", $_QUERY_STRING) ||
			   preg_match("/(<|%3C)([^e]*e)+mbed.*(>|%3E)/i", $_QUERY_STRING) ||
			   preg_match("/(<|%3C)([^o]*o)+bject.*(>|%3E)/i", $_QUERY_STRING) ||
			   preg_match("/(<|%3C)([^i]*i)+frame.*(>|%3E)/i", $_QUERY_STRING) ||
			   preg_match("/(<|%3C)([^o]*o)+bject.*(>|%3E)/i", $_QUERY_STRING) ||
			   preg_match("/base64_(en|de)code[^(]*\([^)]*\)/i", $_QUERY_STRING) ||
			   preg_match("/(%0A|%0D|\\r|\\n)/i", $_QUERY_STRING) ||
			   preg_match("/(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|%2e%2e%5c)/i", $_QUERY_STRING) ||
			   preg_match("/(;|<|>|'|\"|\)|%0A|%0D|%22|%27|%3C|%3E|%00).*(\*|union|select|insert|cast|set|declare|drop|update|md5|benchmark).*/i", $_QUERY_STRING) ||
			   preg_match("/union([^a]*a)+ll([^s]*s)+elect/i", $_QUERY_STRING)) {
				self::error(403, 'Permission denied!');
			}
		}


		/**
		 * Secure Form Request check if the referer is equal to the origin
		 */
		public static function secureFormRequest() {
			if($_SERVER["REQUEST_METHOD"] == "POST") {
				$referer = $_SERVER["HTTP_REFERER"];
				if(!isset($referer) || strpos($_SERVER["SERVER_NAME"], $referer) != 0) {
					self::error(403, 'Permission denied!');
				}
			}
		}

		/**
		 * Compress generic output
		 * @param $buffer
		 * @return string
		 */
		public static function compressOutput($buffer) {
			if(ini_get('zlib.output_compression')) {
				ini_set("zlib.output_compression", 1);
				ini_set("zlib.output_compression_level", "9");
			}

			return preg_replace(array('/\s+/u'), array(' '), str_replace(array("\n", "\r", "\t"), '', $buffer));
		}

		/**
		 * Compress HTML
		 * @param $buffer
		 * @return null|string|string[]
		 */
		public static function compressHTML($buffer) {
			if(ini_get('zlib.output_compression')) {
				ini_set("zlib.output_compression", 1);
				ini_set("zlib.output_compression_level", "9");
			}
			$min    = new Minifier();
			$buffer = $min->minifyHTML($buffer);

			return $buffer;
		}

		/**
		 * Compress CSS
		 * @param $buffer
		 * @return string
		 */
		public static function compressCSS($buffer) {
			if(ini_get('zlib.output_compression')) {
				ini_set("zlib.output_compression", 1);
				ini_set("zlib.output_compression_level", "9");
			}
			$min    = new Minifier();
			$buffer = $min->minifyCSS($buffer);

			return $buffer;
		}

		/**
		 * Compress Javascript
		 * @param $buffer
		 * @return string
		 */
		public static function compressJS($buffer) {
			if(ini_get('zlib.output_compression')) {
				ini_set("zlib.output_compression", 1);
				ini_set("zlib.output_compression_level", "9");
			}
			$min    = new Minifier();
			$buffer = $min->minifyJS($buffer);

			return $buffer;
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
		 * Check if string is base64
		 * @param $string
		 * @return bool
		 */
		public static function isBase64($string) {
			$charset_base64 = (bool) preg_match('#^[a-zA-Z0-9+/]+={0,2}$#', $string);
			if(base64_encode(base64_decode($string, true)) === $string && $charset_base64) {
				return true;
			}

			return false;
		}

		/**
		 * Repair security issue on template
		 * @param $buffer
		 * @return string
		 */
		public static function secureHTML($buffer) {

			$buffer = preg_replace("/<script(?!.*(src\\=))[^>]*>/", "<script type=\"text/javascript\">", $buffer);

			libxml_use_internal_errors(true);

			$doc                     = new \DOMDocument();
			$doc->formatOutput       = true;
			$doc->preserveWhiteSpace = false;
			$doc->loadHTML($buffer);

			$days_to_cache = self::$headers_cache_days * (60 * 60 * 24);
			$ts            = gmdate("D, d M Y H:i:s", time() + $days_to_cache) . " GMT";
			$tags          = $doc->getElementsByTagName('head');

			foreach($tags as $tag) {
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

				$item = $doc->createElement("script", "
			(function() {
			    var _z = console;
				Object.defineProperty( window, \"console\", {
					get : function(){
					    if( _z._commandLineAPI ){
						throw \"Sorry, Can't execute scripts!\";
					          }
					    return _z;
					},
					set : function(val){
					    _z = val;
					}
				});
			});");
				$item->setAttribute("type", "text/javascript");
				$tag->appendChild($item);
			}

			$tags = $doc->getElementsByTagName('input');
			foreach($tags as $tag) {
				$type = array(
					"text",
					"search",
					"password",
					"datetime",
					"date",
					"month",
					"week",
					"time",
					"datetime-local",
					"number",
					"range",
					"email",
					"color"
				);
				if(in_array($tag->getAttribute('type'), $type)) {
					$tag->setAttribute("autocomplete", "off");
				}
			}

			$tags = $doc->getElementsByTagName('form');
			foreach($tags as $tag) {
				$tag->setAttribute("autocomplete", "off");
				if($tags->hasAttribute("method") && strtolower($tags->getAttribute("method")) != 'get') {
					// CSRF
					$token = $_SESSION[self::$csrf_session];
					$item  = $doc->createElement("input");
					$item->setAttribute("name", self::$csrf_formtoken);
					$item->setAttribute("type", "hidden");
					$item->setAttribute("value", self::escapeSQL($token));
					$tag->appendChild($item);
				}
			}

			// Prevent Phishing by Navigating Browser Tabs
			$tags = $doc->getElementsByTagName('a');
			foreach($tags as $tag) {
				$tag->setAttribute("rel", $tag->getAttribute("rel") . " noopener noreferrer");
			}

			$output = $doc->saveHTML();

			return $output;
		}

		/**
		 * Clean all input globals received
		 * BE CAREFUL THIS METHOD COULD COMPROMISE HTML DATA IF SENT WITH INLINE JS
		 * (send with htmlentities could be a solution if you want send inline js and clean globals at the same time)
		 */
		public static function cleanGlobals() {
			self::saveUnsafeGlobals();
			$_SERVER  = self::clean($_SERVER, false, false);
			$_COOKIE  = self::clean($_COOKIE, false);
			$_GET     = self::clean($_GET, false, false);
			$_POST    = self::clean($_POST, true, true, true, self::$clean_post_xss);
			$_REQUEST = array_unique(array_merge($_GET, $_POST, array_diff_assoc($_REQUEST, $_COOKIE)));
		}

		/**
		 * Save uncleaned globals
		 */
		private static function saveUnsafeGlobals() {
			if(!self::$_saved_unsafe_glob) {
				self::$_UNSAFE_GLOB['UNSAFE_SERVER']  = $_SERVER;
				self::$_UNSAFE_GLOB['UNSAFE_COOKIE']  = $_COOKIE;
				self::$_UNSAFE_GLOB['UNSAFE_GET']     = $_GET;
				self::$_UNSAFE_GLOB['UNSAFE_POST']    = $_POST;
				self::$_UNSAFE_GLOB['UNSAFE_REQUEST'] = $_REQUEST;
				foreach(self::$_UNSAFE_GLOB as $key => $value) {
					$GLOBALS[$key] = $value;
				}
				self::$_saved_unsafe_glob = true;
			}
		}

		/**
		 * Restore unsafe globals
		 */
		public static function restoreGlobals() {
			foreach(self::$_UNSAFE_GLOB as $key => $value) {
				$key     = str_replace('UNSAFE_', '', $key);
				$_{$key} = $value;
			}
		}

		/**
		 * Useful to compare unsafe globals with safe globals
		 * @return array
		 */
		public static function debugGlobals() {
			$compare = array();
			// SERVER
			$compare['SERVER']['current'] = $_SERVER;
			$compare['SERVER']['unsafe']  = self::$_UNSAFE_GLOB['UNSAFE_SERVER'];
			$compare['SERVER']['safe']    = self::clean(self::$_UNSAFE_GLOB['UNSAFE_SERVER'], false, false);
			// COOKIE
			$compare['COOKIE']['current'] = $_COOKIE;
			$compare['COOKIE']['unsafe']  = self::$_UNSAFE_GLOB['UNSAFE_COOKIE'];
			$compare['COOKIE']['safe']    = self::clean(self::$_UNSAFE_GLOB['UNSAFE_COOKIE'], false);
			// GET
			$compare['GET']['current'] = $_GET;
			$compare['GET']['unsafe']  = self::$_UNSAFE_GLOB['UNSAFE_GET'];
			$compare['GET']['safe']    = self::clean(self::$_UNSAFE_GLOB['UNSAFE_GET'], false, false);
			// POST
			$compare['POST']['current'] = $_POST;
			$compare['POST']['unsafe']  = self::$_UNSAFE_GLOB['UNSAFE_POST'];
			$compare['POST']['safe']    = self::clean(self::$_UNSAFE_GLOB['UNSAFE_POST']);
			// REQUEST
			$compare['REQUEST']['current'] = $_REQUEST;
			$compare['REQUEST']['unsafe']  = self::$_UNSAFE_GLOB['UNSAFE_REQUEST'];
			$compare['REQUEST']['safe']    = array_merge($compare['POST']['safe'], $compare['GET']['safe'], array_diff_assoc(self::$_UNSAFE_GLOB['UNSAFE_REQUEST'], self::$_UNSAFE_GLOB['UNSAFE_COOKIE']));

			return $compare;
		}

		/**
		 *  Clean variables (recursive)
		 * @param $data
		 * @param bool $html
		 * @param bool $quotes
		 * @param bool $escape
		 * @param bool $xss
		 * @return array|mixed
		 */
		public static function clean($data, $html = true, $quotes = true, $escape = true, $xss = true) {
			if(is_array($data)) {
				foreach($data as $k => $v) {
					$data[$k] = self::clean($v, $html, $quotes, $escape, $xss);
				}
			} else {
				if(!$quotes) {
					$data = str_replace(array('\'', '"'), '', $data);
				}
				if(!$html) {
					$data = self::stripTagsContent($data);
				}
				if($xss) {
					$data = self::escapeXSS($data);
				}
				if($escape && self::$escape_string) {
					//$data = self::stripslashes($data);
					$data = self::escapeSQL($data);
				}
			}

			return $data;
		}

		/**
		 * String escape
		 * @param $data
		 * @return mixed
		 */
		public static function escapeSQL($data) {
			if(is_array($data)) {
				foreach($data as $k => $v) {
					$data[$k] = self::escapeSQL($v);
				}
			} else {
				if(!empty($data) && is_string($data)) {
					$search  = array("\\", "\x00", "\n", "\r", "'", '"', "\x1a");
					$replace = array("\\\\", "\\0", "\\n", "\\r", "\'", '\"', "\\Z");
					$data    = str_replace($search, $replace, $data);
				}
			}

			return $data;
		}

		/**
		 * Attribute escape
		 * @param $data
		 * @return mixed
		 */
		public static function escapeAttr($data) {
			if(is_array($data)) {
				foreach($data as $k => $v) {
					$data[$k] = self::escapeAttr($v);
				}
			} else {
				if(!empty($data) && is_string($data)) {
					$data = htmlentities($data, ENT_QUOTES, ini_get('default_charset'), false);
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
			if(is_array($data)) {
				foreach($data as $k => $v) {
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
			if(is_array($data)) {
				foreach($data as $k => $v) {
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
		 * @param string $tags
		 * @param bool $invert
		 * @return array|string
		 */
		public static function stripTagsContent($data, $tags = '', $invert = false) {
			if(is_array($data)) {
				foreach($data as $k => $v) {
					$data[$k] = self::stripTagsContent($v, $tags, $invert);
				}
			} else {
				preg_match_all('/<(.+?)[\s]*\/?[\s]*>/si', trim($tags), $tags);
				$tags = array_unique($tags[1]);
				if(is_array($tags) AND count($tags) > 0) {
					if($invert == false) {
						$data = preg_replace('@<(?!(?:' . implode('|', $tags) . ')\b)(\w+)\b.*?>.*?</\1>@si', '', $data);
					} else {
						$data = preg_replace('@<(' . implode('|', $tags) . ')\b.*?>.*?</\1>@si', '', $data);
					}
				} elseif($invert == false) {
					$data = preg_replace('@<(\w+)\b.*?>.*?</\1>@si', '', $data);
				}
			}

			return self::stripTags($data);
		}

		/**
		 * XSS escape
		 * @param $data
		 * @return mixed
		 */
		public static function escapeXSS($data) {
			if(is_array($data)) {
				foreach($data as $k => $v) {
					$data[$k] = self::escapeXSS($v);
				}
			} else {
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
					$data     = preg_replace("#</*(?:applet|b(?:ase|gsound|link)|embed|frame(?:set)?|i(?:frame|layer)|l(?:ayer|ink)|meta|object|s(?:cript|tyle)|title|xml|eval|svg|video|math|keygen)[^>]*+>#i", "", $data);
				} while($old_data !== $data);
				$data = str_replace(chr(0), '', $data);
				$data = preg_replace('%&\s*\{[^}]*(\}\s*;?|$)%', '', $data);
				//$data = str_replace('&', '&amp;', $data);
				$data = preg_replace('/&amp;#([0-9]+;)/', '&#\1', $data);
				$data = preg_replace('/&amp;#[Xx]0*((?:[0-9A-Fa-f]{2})+;)/', '&#x\1', $data);
				$data = preg_replace('/&amp;([A-Za-z][A-Za-z0-9]*;)/', '&\1', $data);
			}

			return $data;
		}

		/**
		 * Stripslashes recursive
		 * @param $data
		 * @return mixed
		 */
		public static function stripslashes($data) {
			if(is_array($data)) {
				foreach($data as $k => $v) {
					$data[$k] = self::stripslashes($v);
				}
			} else {
				if(get_magic_quotes_gpc()) {
					$data = stripslashes($data);
				}
			}

			return $data;
		}

		/**
		 * CSRF token compare only on POST REQUEST
		 */
		public static function secureCSRF() {
			if($_SERVER["REQUEST_METHOD"] == "POST") {
				if(!self::secureCSRFCompare()) {
					$_POST = array();
				}
			}
			if(!isset($_SESSION[self::$csrf_session])) {
				self::secureCSRFGenerate();
			}
		}

		/**
		 * CSRF token compare
		 * @param string $csrf_key
		 * @param null $formtoken
		 * @return bool
		 */
		public static function secureCSRFCompare($csrf_key = "", $formtoken = null) {
			$referer = $_SERVER["HTTP_REFERER"];
			if(!isset($referer)) {
				return false;
			}
			if(strpos($_SERVER["SERVER_NAME"], $referer) != 0) {
				return false;
			}

			$GLOBALS[self::$csrf_session . $csrf_key] = $_SESSION[self::$csrf_session . $csrf_key];
			$token                                    = $GLOBALS[self::$csrf_session . $csrf_key];

			if(!empty($token) && $_POST[empty($formtoken) ? self::$csrf_formtoken : $formtoken] == $token) {
				return true;
			} else {
				return false;
			}
		}

		/**
		 * Generate CSRF Token
		 * @param string $csrf_key
		 */
		public static function secureCSRFGenerate($csrf_key = "") {
			$random                                   = uniqid(mt_rand(1, mt_getrandmax()));
			$GLOBALS[self::$csrf_session . $csrf_key] = md5($random . time() . ":" . session_id());

			return $GLOBALS[self::$csrf_session . $csrf_key];
		}

		/**
		 * Get CSRF Token
		 * @param string $csrf_key
		 * @return mixed
		 */
		public static function secureCSRFToken($csrf_key = "") {
			$token = $_SESSION[self::$csrf_session . $csrf_key];

			return $token;
		}

		/**
		 * Check if clients use Tor
		 * @return bool
		 */
		public static function clientIsTor() {

			$ips       = self::clientIPs();
			$ip_server = gethostbyname($_SERVER['SERVER_NAME']);

			foreach($ips as $ip) {

				$query = array(
					implode('.', array_reverse(explode('.', $ip))),
					$_SERVER["SERVER_PORT"],
					implode('.', array_reverse(explode('.', $ip_server))),
					'ip-port.exitlist.torproject.org'
				);

				$torExitNode = implode('.', $query);

				$dns = dns_get_record($torExitNode, DNS_A);

				if(array_key_exists(0, $dns) && array_key_exists('ip', $dns[0])) {
					if($dns[0]['ip'] == '127.0.0.2') {
						return true;
					}
				}

			}

			return false;
		}

		/**
		 * Block Tor clients
		 */
		public static function secureBlockTor() {
			if(self::clientIsTor()) {
				self::error(403, 'Permission denied!');
			}
		}

		/**
		 * Get all client IP Address
		 * @return array
		 */
		public static function clientIPs() {
			$ips = array();
			foreach(
				array(
					'GD_PHP_HANDLER',
					'HTTP_AKAMAI_ORIGIN_HOP',
					'HTTP_CF_CONNECTING_IP',
					'HTTP_CLIENT_IP',
					'HTTP_FASTLY_CLIENT_IP',
					'HTTP_FORWARDED',
					'HTTP_FORWARDED_FOR',
					'HTTP_INCAP_CLIENT_IP',
					'HTTP_TRUE_CLIENT_IP',
					'HTTP_X_CLIENTIP',
					'HTTP_X_CLUSTER_CLIENT_IP',
					'HTTP_X_FORWARDED',
					'HTTP_X_FORWARDED_FOR',
					'HTTP_X_IP_TRAIL',
					'HTTP_X_REAL_IP',
					'HTTP_X_VARNISH',
					'HTTP_VIA',
					'REMOTE_ADDR'
				) as $key
			) {
				if(array_key_exists($key, $_SERVER) === true) {
					foreach(explode(',', $_SERVER[$key]) as $ip) {
						$ip = trim($ip);
						// Check for IPv4 IP cast as IPv6
						if(preg_match('/^::ffff:(\d+\.\d+\.\d+\.\d+)$/', $ip, $matches)) {
							$ip = $matches[1];
						}
						if($ip == "::1") {
							$ips[] = "127.0.0.1";
						} else if(self::validateIPAddress($ip)) {
							$ips[] = $ip;
						}
					}
				}
			}
			if(empty($ips)) {
				$ips = array('0.0.0.0');
			}
			$ips = array_unique($ips);

			return $ips;
		}

		/**
		 * Get Real IP Address
		 * @return string
		 */
		public static function clientIP() {
			foreach(
				array(
					'HTTP_CLIENT_IP',
					'HTTP_CF_CONNECTING_IP',
					'HTTP_X_FORWARDED_FOR',
					'HTTP_X_FORWARDED',
					'HTTP_X_CLUSTER_CLIENT_IP',
					'HTTP_FORWARDED_FOR',
					'HTTP_FORWARDED',
					'HTTP_VIA',
					'REMOTE_ADDR'
				) as $key
			) {
				if(array_key_exists($key, $_SERVER) === true) {
					foreach(explode(',', $_SERVER[$key]) as $ip) {

						$ip = trim($ip);
						// Check for IPv4 IP cast as IPv6
						if(preg_match('/^::ffff:(\d+\.\d+\.\d+\.\d+)$/', $ip, $matches)) {
							$ip = $matches[1];
						}
						if($ip == "::1") {
							$ip = "127.0.0.1";
						}
						if($ip == '127.0.0.1' || self::isPrivateIP($ip)) {
							$ip = $_SERVER['REMOTE_ADDR'];
							if($ip == "::1") {
								$ip = "127.0.0.1";
							}

							return $ip;
						}
						if(self::validateIPAddress($ip)) {
							return $ip;
						}
					}
				}
			}

			return "0.0.0.0";
		}

		/**
		 * Detect if is private IP
		 * @param $ip
		 * @return bool
		 */
		private static function isPrivateIP($ip) {

			// Dealing with ipv6, so we can simply rely on filter_var
			if(false === strpos($ip, '.')) {
				return !@filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
			}

			$long_ip = ip2long($ip);
			// Dealing with ipv4
			$private_ip4_addresses = array(
				'10.0.0.0|10.255.255.255',     // single class A network
				'172.16.0.0|172.31.255.255',   // 16 contiguous class B network
				'192.168.0.0|192.168.255.255', // 256 contiguous class C network
				'169.254.0.0|169.254.255.255', // Link-local address also referred to as Automatic Private IP Addressing
				'127.0.0.0|127.255.255.255'    // localhost
			);
			if(- 1 != $long_ip) {
				foreach($private_ip4_addresses as $pri_addr) {
					list ($start, $end) = explode('|', $pri_addr);
					if($long_ip >= ip2long($start) && $long_ip <= ip2long($end)) {
						return true;
					}
				}
			}

			return false;
		}

		/**
		 * Ensures an ip address is both a valid IP and does not fall within
		 * a private network range.
		 * @param $ip
		 * @return bool
		 */
		private static function validateIPAddress($ip) {
			if(strtolower($ip) === 'unknown') {
				return false;
			}

			// generate ipv4 network address
			$ip = ip2long($ip);

			// if the ip is set and not equivalent to 255.255.255.255
			if($ip !== false && $ip !== - 1) {
				// make sure to get unsigned long representation of ip
				// due to discrepancies between 32 and 64 bit OSes and
				// signed numbers (ints default to signed in PHP)
				$ip = sprintf('%u', $ip);
				// do private network range checking
				if($ip >= 0 && $ip <= 50331647) {
					return false;
				}
				if($ip >= 167772160 && $ip <= 184549375) {
					return false;
				}
				if($ip >= 2130706432 && $ip <= 2147483647) {
					return false;
				}
				if($ip >= 2851995648 && $ip <= 2852061183) {
					return false;
				}
				if($ip >= 2886729728 && $ip <= 2887778303) {
					return false;
				}
				if($ip >= 3221225984 && $ip <= 3221226239) {
					return false;
				}
				if($ip >= 3232235520 && $ip <= 3232301055) {
					return false;
				}
				if($ip >= 4294967040) {
					return false;
				}
			}

			return true;
		}

		/**
		 * Prevent bad bots
		 */
		public static function secureBlockBots() {
			// Block bots
			if(preg_match("/(spider|crawler|slurp|teoma|archive|track|snoopy|lwp|client|libwww)/i", $_SERVER['HTTP_USER_AGENT']) ||
			   preg_match("/(havij|libwww-perl|wget|python|nikto|curl|scan|java|winhttp|clshttp|loader)/i", $_SERVER['HTTP_USER_AGENT']) ||
			   preg_match("/(%0A|%0D|%27|%3C|%3E|%00)/i", $_SERVER['HTTP_USER_AGENT']) ||
			   preg_match("/(;|<|>|'|\"|\)|\(|%0A|%0D|%22|%27|%28|%3C|%3E|%00).*(libwww-perl|wget|python|nikto|curl|scan|java|winhttp|HTTrack|clshttp|archiver|loader|email|harvest|extract|grab|miner)/i", $_SERVER['HTTP_USER_AGENT'])) {
				self::error(403, 'Permission denied!');
			}
			// Block Fake google bot
			self::blockFakeGoogleBots();
		}

		/**
		 * Prevent Fake Google Bots
		 */
		protected static function blockFakeGoogleBots() {
			$user_agent = (isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '');
			if(preg_match('/googlebot/i', $user_agent, $matches)) {
				$ip      = self::clientIP();
				$name    = gethostbyaddr($ip);
				$host_ip = gethostbyname($name);
				if(preg_match('/googlebot/i', $name, $matches)) {
					if($host_ip != $ip) {
						self::error(403, 'Permission denied!');
					}
				} else {
					self::error(403, 'Permission denied!');
				}
			}
		}

		/**
		 * Generate captcha image
		 * @param bool $base64
		 * @return string
		 */
		public static function captcha($base64 = false) {

			$md5_hash      = md5(rand(0, 9999));
			$security_code = substr($md5_hash, rand(0, 15), 5);

			$spook = ': : : : : : : : : : :';

			$_SESSION["CAPTCHA_CODE"] = $security_code;

			$width  = 100;
			$height = 25;

			$image = imagecreate($width, $height);

			$background_color = imagecolorallocate($image, 0, 0, 0);
			$text_color       = imagecolorallocate($image, 233, 233, 233);
			$strange1_color   = imagecolorallocate($image, rand(100, 255), rand(100, 255), rand(100, 255));
			$strange2_color   = imagecolorallocate($image, rand(100, 255), rand(100, 255), rand(100, 255));
			$shape1_color     = imagecolorallocate($image, rand(100, 255), rand(100, 255), rand(100, 255));
			$shape2_color     = imagecolorallocate($image, rand(100, 255), rand(100, 255), rand(100, 255));

			imagefill($image, 0, 0, $background_color);

			imagestring($image, 5, 30, 4, $security_code, $text_color);

			imagestring($image, 0, rand(0, $width / 2), rand(0, $height), $spook, $strange1_color);
			imagestring($image, 0, rand(0, $width / 2), rand(0, $height), $spook, $strange2_color);
			imageellipse($image, 0, 0, rand($width / 2, $width * 2), rand($height, $height * 2), $shape1_color);
			imageellipse($image, 0, 0, rand($width / 2, $width * 2), rand($height, $height * 2), $shape2_color);

			if($base64) {
				$path = tempnam(sys_get_temp_dir(), 'captcha_');
				imagepng($image, $path);
				$png = base64_encode(file_get_contents($path));
				unlink($path);
				imagedestroy($image);

				return $png;
			} else {
				header("Content-Type: image/png");
				ob_clean();
				imagepng($image);
				imagedestroy($image);
				die();
			}
		}

		/**
		 * Return the captcha input code
		 * @param string $class
		 * @param string $input_name
		 * @return string
		 */
		public static function captchaPrint($class = '', $input_name = 'captcha') {
			$img     = self::captcha(true);
			$captcha = '<img class="' . $class . '" src="data:image/png;base64,' . $img . '" alt="Captcha" />';
			$captcha .= '<input type="text" class="' . $class . '" name="' . $input_name . '">';

			return $captcha;
		}

		/**
		 * Return captcha
		 * @return mixed
		 */
		public static function captchaCode() {
			return $_SESSION["CAPTCHA_CODE"];
		}

		/**
		 * Validate captcha
		 * @param $input_name
		 * @return bool
		 */
		public static function captchaVerify($input_name = 'captcha') {
			if($_SERVER["REQUEST_METHOD"] == "POST") {
				if(strtolower($_POST[$input_name]) == strtolower($_SESSION["CAPTCHA_CODE"]) && !empty($_SESSION["CAPTCHA_CODE"])) {
					return true;
				}

				return false;
			}

			return true;
		}

		/**
		 * Hijacking prevention
		 */
		public static function secureHijacking() {
			if(!empty($_SESSION['HTTP_USER_TOKEN']) && $_SESSION['HTTP_USER_TOKEN'] != md5($_SERVER['HTTP_USER_AGENT'] . ':' . self::clientIP() . ':' . self::getSalt())) {
				session_unset();
				session_destroy();
				$_POST    = array();
				$_REQUEST = array();
			}

			$_SESSION['HTTP_USER_TOKEN'] = md5($_SERVER['HTTP_USER_AGENT'] . ':' . self::clientIP() . ':' . self::getSalt());
		}

		/**
		 * Exploits
		 * @package MWScan
		 * @version 0.4.0.61b
		 */
		public static $SCAN_EXPLOITS = array(
			"eval_chr"                => '/chr[\s\r\n]*\([\s\r\n]*101[\s\r\n]*\)[\s\r\n]*\.[\s\r\n]*chr[\s\r\n]*\([\s\r\n]*118[\s\r\n]*\)[\s\r\n]*\.[\s\r\n]*chr[\s\r\n]*\([\s\r\n]*97[\s\r\n]*\)[\s\r\n]*\.[\s\r\n]*chr[\s\r\n]*\([\s\r\n]*108[\s\r\n]*\)/i',
			"eval_preg"               => '/(preg_replace(_callback)?|mb_ereg_replace|preg_filter)[\s\r\n]*\(.+(\/|\\\\x2f)(e|\\\\x65)[\\\'\"].*?(?=\))\)/i',
			"eval_base64"             => '/eval[\s\r\n]*\([\s\r\n]*base64_decode[\s\r\n]*\((?<=\().*?(?=\))\)/i',
			"eval_comment"            => '/(eval|preg_replace|system|assert|passthru|(pcntl_)?exec|shell_exec|call_user_func(_array)?)\/\*[^\*]*\*\/\((?<=\().*?(?=\))\)/',
			"eval_execution"          => '/(eval\(\$[a-z0-9_]+\((?<=\()@?\$_(GET|POST|SERVER|COOKIE|REQUEST).*?(?=\))\)/si',
			"align"                   => '/(\$\w+=[^;]*)*;\$\w+=@?\$\w+\((?<=\().*?(?=\))\)/si',
			"b374k"                   => '/(\\\'|\")ev(\\\'|\")\.(\\\'|\")al(\\\'|\")\.(\\\'|\")\(\"\?>/i',
			// b374k shell
			"weevely3"                => '/\$\w=\$[a-zA-Z]\(\'\',\$\w\);\$\w\(\);/i',
			// weevely3 launcher
			"c99_launcher"            => '/;\$\w+\(\$\w+(,\s?\$\w+)+\);/i',
			// http://bartblaze.blogspot.fr/2015/03/c99shell-not-dead.html
			"too_many_chr"            => '/(chr\([\d]+\)\.){8}/i',
			// concatenation of more than eight `chr()`
			"concat"                  => '/(\$[\w\[\]\\\'\"]+\\.[\n\r]*){10}/i',
			// concatenation of vars array
			"concat_vars_with_spaces" => '/(\$([a-zA-Z0-9]+)[\s\r\n]*\.[\s\r\n]*){6}/',
			// concatenation of more than 6 words, with spaces
			"concat_vars_array"       => '/(\$([a-zA-Z0-9]+)(\{|\[)([0-9]+)(\}|\])[\s\r\n]*\.[\s\r\n]*){6}.*?(?=\})\}/i',
			// concatenation of more than 6 words, with spaces
			"var_as_func"             => '/\$_(GET|POST|COOKIE|REQUEST|SERVER)[\s\r\n]*\[[^\]]+\][\s\r\n]*\((?<=\().*?(?=\))\)/i',
			"global_var_string"       => '/\$\{[\s\r\n]*(\\\'|\")_(GET|POST|COOKIE|REQUEST|SERVER)(\\\'|\")[\s\r\n]*\}/i',
			"extract_global"          => '/extract\([\s\r\n]*\$_(GET|POST|COOKIE|REQUEST|SERVER).*?(?=\))\)/i',
			"escaped_path"            => '/(\\\\x[0-9abcdef]{2}[a-z0-9.-\/]{1,4}){4,}/i',
			"include_icon"            => '/@?include[\s\r\n]*(\([\s\r\n]*)?("|\\\')([^"\\\']*)(\.|\\\\056\\\\046\\\\2E)(\i|\\\\151|\\\\x69|\\\\105)(c|\\\\143\\\\099\\\\x63)(o|\\\\157\\\\111|\\\\x6f)(\"|\\\')((?=\))\))?/mi',
			// Icon inclusion
			"backdoor_code"           => '/eva1fYlbakBcVSir/i',
			"infected_comment"        => '/\/\*[a-z0-9]{5}\*\//i',
			// usually used to detect if a file is infected yet
			"hex_char"                => '/\\\\[Xx](5[Ff])/i',
			"hacked_by"               => '/hacked[\s\r\n]*by/i',
			"killall"                 => '/killall[\s\r\n]*\-9/i',
			"globals_concat"          => '/\$GLOBALS\[[\s\r\n]*\$GLOBALS[\\\'[a-z0-9]{4,}\\\'\]/i',
			"globals_assign"          => '/\$GLOBALS\[\\\'[a-z0-9]{5,}\\\'\][\s\r\n]*=[\s\r\n]*\$[a-z]+\d+\[\d+\]\.\$[a-z]+\d+\[\d+\]\.\$[a-z]+\d+\[\d+\]\.\$[a-z]+\d+\[\d+\]\./i',
			"base64_long"             => '/[\\\'\"][A-Za-z0-9+\/]{260,}={0,3}[\\\'\"]/',
			"base64_inclusion"        => '/@?include[\s\r\n]*(\([\s\r\n]*)?("|\\\')data\:text/plain;base64[\s\r\n]*\,[\s\r\n]*\$_GET\[[^\]]+\](\\\'|")[\s\r\n]*((?=\))\))?/si',
			"clever_include"          => '/@?include[\s\r\n]*(\([\s\r\n]*)?("|\\\')[\s\r\n]*[^\.]+\.(png|jpe?g|gif|bmp|ico).*?("|\\\')[\s\r\n]*((?=\))\))?/i',
			"basedir_bypass"          => '/curl_init[\s\r\n]*\([\s\r\n]*[\"\\\']file:\/\/.*?(?=\))\)/i',
			"basedir_bypass2"         => '/file\:file\:\/\//i',
			// https://www.intelligentexploit.com/view-details.html?id=8719
			"non_printable"           => '/(function|return|base64_decode).{,256}[^\\x00-\\x1F\\x7F-\\xFF]{3}/i',
			"double_var"              => '/\${[\s\r\n]*\${.*?}(.*)?}/i',
			"double_var2"             => '/\${\$[0-9a-zA-z]+}/i',
			"global_save"             => '/\[\s\r\n]*=[\s\r\n]*\$GLOBALS[\s\r\n]*\;[\s\r\n]*\$[\s\r\n]*\{/i',
			"hex_var"                 => '/\$\{[\s\r\n]*(\\\'|\")\\\\x.*?(?=\})\}/i',
			// check for ${"\xFF"}, IonCube use this method ${"\x
			"register_function"       => '/register_[a-z]+_function[\s\r\n]*\([\s\r\n]*[\\\'\"][\s\r\n]*(eval|assert|passthru|exec|include|system|shell_exec|`).*?(?=\))\)/i',
			// https://github.com/nbs-system/php-malware-finder/issues/41
			"safemode_bypass"         => '/\x00\/\.\.\/|LD_PRELOAD/i',
			"ioncube_loader"          => '/IonCube\_loader/i',
			"nano"                    => '/\$[a-z0-9-_]+\[[^]]+\]\((?<=\().*?(?=\))\)/',
			//https://github.com/UltimateHackers/nano
			"ninja"                   => '/base64_decode[^;]+getallheaders/',
			"execution"               => '/\b(eval|assert|passthru|exec|include|system|pcntl_exec|shell_exec|base64_decode|`|array_map|ob_start|call_user_func(_array)?)[\s\r\n]*\([\s\r\n]*(base64_decode|php:\/\/input|str_rot13|gz(inflate|uncompress)|getenv|pack|\\\\?@?\$_(GET|REQUEST|POST|COOKIE|SERVER)).*?(?=\))\)/',
			// function that takes a callback as 1st parameter
			"execution2"              => '/\b(array_filter|array_reduce|array_walk(_recursive)?|array_walk|assert_options|uasort|uksort|usort|preg_replace_callback|iterator_apply)[\s\r\n]*\([\s\r\n]*[^,]+,[\s\r\n]*(base64_decode|php:\/\/input|str_rot13|gz(inflate|uncompress)|getenv|pack|\\\\?@?\$_(GET|REQUEST|POST|COOKIE|SERVER)).*?(?=\))\)/',
			// functions that takes a callback as 2nd parameter
			"execution3"              => '/\b(array_(diff|intersect)_u(key|assoc)|array_udiff)[\s\r\n]*\([\s\r\n]*([^,]+[\s\r\n]*,?)+[\s\r\n]*(base64_decode|php:\/\/input|str_rot13|gz(inflate|uncompress)|getenv|pack|\\\\?@?\$_(GET|REQUEST|POST|COOKIE|SERVER))[\s\r\n]*\[[^]]+\][\s\r\n]*\)+[\s\r\n]*;/',
			// functions that takes a callback as 2nd parameter
			"shellshock"              => '/\(\)[\s\r\n]*{[\s\r\n]*[a-z:][\s\r\n]*;[\s\r\n]*}[\s\r\n]*;/',
			"silenced_eval"           => '/@eval[\s\r\n]*\((?<=\().*?(?=\))\)/',
			"silence_inclusion"       => '/@(include|include_once|require|require_once)[\s\r\n]+([\s\r\n]*\()?("|\\\')([^"\\\']*)(\\\\x[0-9a-f]{2,}.*?){2,}([^"\\\']*)("|\\\')[\s\r\n]*((?=\))\))?/si',
			"silence_inclusion2"      => '/@(include|include_once|require|require_once)[\s\r\n]+([\s\r\n]*\()?("|\\\')([^"\\\']*)(\\[0-9]{3,}.*?){2,}([^"\\\']*)("|\\\')[\s\r\n]*((?=\))\))?/si',
			"ssi_exec"                => '/\<\!\-\-\#exec[\s\r\n]*cmd\=/i',
			//http://www.w3.org/Jigsaw/Doc/User/SSI.html#exec
			"htaccess_handler"        => '/SetHandler[\s\r\n]*application\/x\-httpd\-php/i',
			"htaccess_type"           => '/AddType\s+application\/x-httpd-(php|cgi)/i',
			"file_prepend"            => '/php_value[\s\r\n]*auto_prepend_file/i',
			"iis_com"                 => '/IIS\:\/\/localhost\/w3svc/i',
			"reversed"                => '/(noitcnuf\_etaerc|metsys|urhtssap|edulcni|etucexe\_llehs|ecalper\_rts|ecalper_rts)/i',
			"rawurlendcode_rot13"     => '/rawurldecode[\s\r\n]*\(str_rot13[\s\r\n]*\((?<=\().*?(?=\))\)/i',
			"serialize_phpversion"    => '/\@serialize[\s\r\n]*\([\s\r\n]*(Array\(|\[)(\\\'|\")php(\\\'|\")[\s\r\n]*\=\>[\s\r\n]*\@phpversion[\s\r\n]*\((?<=\().*?(?=\))\)/si',
			"md5_create_function"     => '/\$md5[\s\r\n]*=[\s\r\n]*.*create_function[\s\r\n]*\(.*?\);[\s\r\n]*\$.*?\)[\s\r\n]*;/si',
			"god_mode"                => '/\/\*god_mode_on\*\/eval\(base64_decode\([\"\\\'][^\"\\\']{255,}[\"\\\']\)\);[\s\r\n]*\/\*god_mode_off\*\//si',
			"wordpress_filter"        => '/\$md5[\s\r\n]*=[\s\r\n]*[\"|\\\']\w+[\"|\\\'];[\s\r\n]*\$wp_salt[\s\r\n]*=[\s\r\n]*[\w\(\),\"\\\'\;$]+[\s\r\n]*\$wp_add_filter[\s\r\n]*=[\s\r\n]*create_function\(.*?\);[\s\r\n]*\$wp_add_filter\(.*?\);/si',
			"password_protection_md5" => '/md5[\s\r\n]*\([\s\r\n]*@?\$_(GET|REQUEST|POST|COOKIE|SERVER)[^)]+\)[\s\r\n]*===?[\s\r\n]*[\\\'\"][0-9a-f]{32}[\\\'\"]/si',
			"password_protection_sha" => '/sha1[\s\r\n]*\([\s\r\n]*@?\$_(GET|REQUEST|POST|COOKIE|SERVER)[^)]+\)[\s\r\n]*===?[\s\r\n]*[\\\'\"][0-9a-f]{40}[\\\'\"]/si',
			"custom_math"             => '/%\(\d+\-\d+\+\d+\)==\(\-\d+\+\d+\+\d+\)/si',
			"custom_math2"            => '/\(\$[a-zA-Z0-9]+%\d==\(\d+\-\d+\+\d+\)/si',
			"uncommon_function"       => 'function\s+_[0-9]{8,}\((?<=\().*?(?=\))\)',
			"download_remote_code"    => '/file_get_contents[\s\r\n]*\([\s\r\n]*base64_url_decode[\s\r\n]*\([\s\r\n]*@*\$_(GET|POST|SERVER|COOKIE|REQUEST).*?(?=\))\)/i',
			"download_remote_code2"   => '/fwrite[\s\r\n]*(\(\w+\((?<=\().*?(?=\))\))?[^\)]*\$_(GET|POST|SERVER|COOKIE|REQUEST).*?(?=\))\)/si',
			"download_remote_code3"   => '/(file_get_contents|fwrite)[\s\r\n]*\([\s\r\n]*@?*\$_(GET|POST|SERVER|COOKIE|REQUEST).*?(?=\))\)/si',
			"php_uname"               => '/php_uname\(["\'asrvm]+\)/si',
			"etc_passwd"              => '/(\/)*etc\/+passwd\/*/si',
			"etc_shadow"              => '/(\/)*etc\/+shadow\/*/si',
			"explode_chr"             => '/explode[\s\r\n]*\(chr[\s\r\n]*\([\s\r\n]*\(?\d{3}([\s\r\n]*-[\s\r\n]*\d{3})?[\s\r\n]*\).*?(?=\))\)/si',
		);

		/**
		 * Detect infected favicon
		 * @package AMWScan
		 * @version 0.4.0.61b
		 * @param $file
		 * @return bool
		 */
		public static function isInfectedFavicon($file) {
			$info = pathinfo($file);
			$filename  = $info['filename'];
			$extension = $info['extension'];
			// Case favicon_[random chars].ico
			return (((strpos($filename, 'favicon_') === 0) && ($extension === 'ico') && (strlen($filename) > 12)) || preg_match('/^\.[\w]+\.ico/i', trim($filename)));
		}

		/**
		 * File Scan
		 * @param $file
		 * @return bool
		 */
		public static function isInfectedFile($file) {
			$fc = php_strip_whitespace($file);

			if(self::isInfectedFavicon($file)) {
				return true;
			}

			$mime_type = 'text';
			if(function_exists('mime_content_type')) {
				$mime_type = mime_content_type($file);
			} elseif(function_exists('finfo_open')) {
				$finfo     = finfo_open(FILEINFO_MIME);
				$mime_type = finfo_file($finfo, $file);
				finfo_close($finfo);
			}

			if(preg_match("/^text/i", $mime_type)) {
				foreach(self::$SCAN_EXPLOITS as $key => $pattern) {
					if(preg_match($pattern, $fc, $match, PREG_OFFSET_CAPTURE)) {
						return true;
					}
				}
			}

			return false;
		}

		/**
		 * Secure Upload
		 * @param $file
		 * @param $path
		 * @return bool
		 */
		public static function secureUpload($file, $path) {

			if(!is_uploaded_file($_FILES[$file]["tmp_name"]) || self::isInfectedFile($_FILES[$file]["tmp_name"])) {
				return false;
			}

			if(is_dir($path)) {
				$path = $path . '/' . basename($file);
			}

			$dest_file = basename($path);

			$info          = pathinfo($dest_file);
			$filename      = $info['filename'];
			$extension     = $info['extension'];
			$original_name = $filename;

			$dest_dir = dirname($path);

			$i = 1;
			while(file_exists($dest_dir . '/' . $filename . "." . $extension)) {
				$filename = (string) $original_name . '-' . $i;
				$path     = $dest_dir . '/' . $filename . "." . $extension;
				$i ++;
			}
			if(move_uploaded_file($_FILES[$file]["tmp_name"], $path)) {
				return true;
			}

			return false;
		}

		/**
		 * Secure download
		 * @param $filename
		 * @param $name
		 * @return bool
		 */
		public static function secureDownload($filename, $name = null) {
			if(!file_exists($filename)) {
				return false;
			}

			$filename   = realpath($filename);
			$path_parts = pathinfo($filename);

			if(in_array($path_parts['extension'], array('php', 'php5', 'php7', 'htaccess', 'config'))) {
				return false;
			}

			ob_clean();

			$name = (!empty($name)) ? $name : $path_parts['filename'];

			header('Content-Type: application/x-octet-stream');
			header('Content-Transfer-Encoding: binary');
			header('Content-Disposition: attachment; filename="' . $name . '"');

			die(file_get_contents($filename));
		}

		/**
		 * Crypt
		 * @param $string
		 * @param $key
		 * @param $action
		 * @return bool|string
		 */
		protected static function crypt($string, $key = null, $action = 'encrypt') {

			if(!function_exists('crypt') || !function_exists('hash') || !function_exists('openssl_encrypt')) {
				return false;
			}

			$encrypt_method = "AES-256-CBC";

			if(empty($key) && empty($_SESSION['HTTP_USER_KEY'])) {
				$_SESSION['HTTP_USER_KEY'] = md5(self::generateGUID());
			}

			$secret_key = (empty($key) ? $_SESSION['HTTP_USER_KEY'] : $key) . ':KEY' . self::getSalt();
			$secret_iv  = (empty($key) ? $_SESSION['HTTP_USER_KEY'] : $key) . ':IV' . self::getSalt();

			$key = hash('sha512', $secret_key);
			$iv  = substr(hash('sha512', $secret_iv), 0, 16);
			switch($action) {
				case 'decrypt':
					if(self::isBase64($string)) {
						$string = base64_decode($string);
						$output = openssl_decrypt($string, $encrypt_method, $key, 0, $iv);
					} else {
						$output = $string;
					}
					break;
				case 'encrypt':
				default:
					$output = openssl_encrypt($string, $encrypt_method, $key, 0, $iv);
					$output = base64_encode($output);
					break;
			}

			return $output;
		}

		/**
		 * Decrypt
		 * @param $string
		 * @param $key
		 * @return bool|string
		 */
		public static function decrypt($string, $key = null) {
			return self::crypt($string, $key, 'decrypt');
		}

		/**
		 * Encrypt
		 * @param $string
		 * @param $key
		 * @return bool|string
		 */
		public static function encrypt($string, $key = null) {
			return self::crypt($string, $key, 'encrypt');
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
		public static function setCookie($name, $value, $expires = 2592000, $path = "/", $domain = "", $secure = null, $httponly = false) {

			if(self::$cookies_encrypted) {
				$name = self::$cookies_enc_prefix . $name;
			}

			if($secure == null) {
				$secure = self::checkHTTPS();
			}

			if($name != self::$session_name) {

				$cookie_encrypted = false;
				if(self::$cookies_encrypted) {
					$cookie_encrypted = self::encrypt($value);
				}

				$cookie_value = (self::$cookies_encrypted && $cookie_encrypted != false) ? $cookie_encrypted : $value;

				if(!setcookie($name, $cookie_value, array(
					'expires'  => time() + $expires,
					'path'     => $path,
					'domain'   => $domain,
					'secure'   => $secure,
					'httponly' => $httponly,
					'samesite' => 'Strict',
				))) {
					return false;
				}

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
			if(isset($_COOKIE[$name])) {
				unset($_COOKIE[$name]);
				setcookie($name, null, - 1);
			}

			return null;
		}

		/**
		 * Get Cookie
		 * @param $name
		 * @return null
		 */
		public static function getCookie($name) {

			if(self::$cookies_encrypted) {
				$name = self::$cookies_enc_prefix . $name;
			}

			$cookie_decrypted = false;
			if(self::$cookies_encrypted) {
				$cookie_decrypted = self::decrypt($_COOKIE[$name]);
			}

			if(isset($_COOKIE[$name])) {
				$cookie = (self::$cookies_encrypted && $cookie_decrypted != false) ? $cookie_decrypted : $_COOKIE[$name];

				return $cookie;
			}

			return null;
		}

		/**
		 * Custom Error
		 * @param integer $code
		 * @param string $message
		 * @param string $title
		 * @return bool
		 */
		public static function error($code = 404, $message = "Not found!", $title = 'Error') {
			if(empty(self::$error_callback)) {
				ob_clean();
				http_response_code($code);
				$output = str_replace('${ERROR_TITLE}', $title, self::$error_template);
				$output = str_replace('${ERROR_BODY}', $message, $output);
				die($output);
			}
			call_user_func(self::$error_callback, $code, $message, $title);

			return true;
		}

		/**
		 * Prevent malicious callbacks from being used in JSONP requests.
		 * @param $json
		 * @param $callback
		 * @return string
		 */
		public function secureJSONP($json, $callback) {
			if(preg_match('/[^0-9a-zA-Z\$_]|^(abstract|boolean|break|byte|case|catch|char|class|const|continue|debugger|default|delete|do|double|else|enum|export|extends|false|final|finally|float|for|function|goto|if|implements|import|in|instanceof|int|interface|long|native|new|null|package|private|protected|public|return|short|static|super|switch|synchronized|this|throw|throws|transient|true|try|typeof|var|volatile|void|while|with|NaN|Infinity|undefined)$/', $callback)) {
				return false;
			}

			return "{$callback}($json);";

		}

		/**
		 * Check if the request is HTTPS
		 */
		public static function checkHTTPS() {
			if(isset($_SERVER['HTTP_HOST'])) {
				if(((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || $_SERVER['SERVER_PORT'] == 443)
				   || !empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] == 'https' || !empty($_SERVER['HTTP_X_FORWARDED_SSL']) && $_SERVER['HTTP_X_FORWARDED_SSL'] == 'on') {
					return true;
				}

				return false;
			}

			return false;
		}

		/**
		 * Write on htaccess the DOS Attempts
		 * @param $ip
		 * @param $file_attempts
		 */
		protected static function secureDOSWriteAttempts($ip, $file_attempts) {
			$ip_quote = preg_quote($ip);
			$content  = @file_get_contents($file_attempts);
			if(preg_match("/### BEGIN: DOS Attempts ###[\S\s.]*# $ip_quote => ([0-9]+):([0-9]+):([0-9]+):([0-9]+)[\S\s.]*### END: DOS Attempts ###/i", $content, $attemps)) {
				$row_replace = "# $ip => " . $_SESSION['DOS_ATTEMPTS_TIMER'] . ":" . $_SESSION['DOS_ATTEMPTS'] . ":" . $_SESSION['DOS_COUNTER'] . ":" . $_SESSION['DOS_TIMER'];
				$content     = preg_replace("/(### BEGIN: DOS Attempts ###[\S\s.]*)(# $ip_quote => [0-9]+:[0-9]+:[0-9]+:[0-9]+)([\S\s.]*### END: DOS Attempts ###)/i",
					"$1$row_replace$3", $content);
			} else if(preg_match("/### BEGIN: DOS Attempts ###([\S\s.]*)### END: DOS Attempts ###/i", $content)) {
				$row     = "# $ip => " . $_SESSION['DOS_ATTEMPTS_TIMER'] . ":" . $_SESSION['DOS_ATTEMPTS'] . ":" . $_SESSION['DOS_COUNTER'] . ":" . $_SESSION['DOS_TIMER'];
				$content = preg_replace("/(### BEGIN: DOS Attempts ###)([\S\s.]*)([\r\n]+### END: DOS Attempts ###)/i",
					"$1$2$row$3", $content);
			} else {
				$content .= "### BEGIN: DOS Attempts ###";
				$content .= "\r\n# $ip => " . $_SESSION['DOS_ATTEMPTS_TIMER'] . ":" . $_SESSION['DOS_ATTEMPTS'] . ":" . $_SESSION['DOS_COUNTER'] . ":" . $_SESSION['DOS_TIMER'];
				$content .= "\r\n### END: DOS Attempts ###";
			}
			file_put_contents($file_attempts, $content);
		}

		/**
		 * Remove from htaccess the DOS Attempts
		 * @param $ip
		 * @param $file_attempts
		 */
		protected static function secureDOSRemoveAttempts($ip, $file_attempts) {
			$ip_quote = preg_quote($ip);
			$content  = @file_get_contents($file_attempts);
			if(preg_match("/### BEGIN: DOS Attempts ###[\S\s.]*[\r\n]+# $ip_quote => ([0-9]+):([0-9]+):([0-9]+):([0-9]+)[\S\s.]*### END: DOS Attempts ###/i", $content, $attemps)) {
				$content = preg_replace("/(### BEGIN: DOS Attempts ###[\S\s.]*)([\r\n]+# $ip_quote => [0-9]+:[0-9]+:[0-9]+:[0-9]+)([\S\s.]*### END: DOS Attempts ###)/i", "$1$3", $content);
			}
			file_put_contents($file_attempts, $content);
		}

		/**
		 * Remove from htaccess the DOS Attempts
		 * @param $time_expire
		 * @param $file_attempts
		 */
		protected static function secureDOSRemoveOldAttempts($time_expire, $file_attempts) {
			$time    = $_SERVER['REQUEST_TIME'];
			$pattern = "/# ((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])) => ([0-9]+):([0-9]+):([0-9]+):([0-9]+)[\r\n]+/i";
			$content = @file_get_contents($file_attempts);
			if(preg_match_all($pattern, $content, $attemps)) {
				foreach($attemps as $attemp) {
					if(!empty($attemp[0])) {
						preg_match($pattern, $attemp[0], $attemp);
						if(!empty($attemp)) {
							$ip_quote = preg_quote($attemp[1]);
							if($time > $attemp[5] + $time_expire || $time > $attemp[8] + $time_expire) {
								$content = preg_replace("/(### BEGIN: DOS Attempts ###[\S\s.]*)([\r\n]+# $ip_quote => [0-9]+:[0-9]+:[0-9]+:[0-9]+)([\S\s.]*### END: DOS Attempts ###)/i", "$1$3", $content);
							}
						}
					}
				}
			}
			file_put_contents($file_attempts, $content);
		}

		/**
		 * Read from htaccess the DOS Attempts
		 * @param $ip
		 * @param $content
		 */
		protected static function secureDOSReadAttempts($ip, $content) {
			$ip_quote = preg_quote($ip);
			if(preg_match("/### BEGIN: DOS Attempts ###[\S\s.]*[\r\n]+# $ip_quote => ([0-9]+):([0-9]+):([0-9]+):([0-9]+)[\S\s.]*### END: DOS Attempts ###/i", $content, $attemps)) {
				$_SESSION['DOS_ATTEMPTS_TIMER'] = $attemps[1];
				$_SESSION['DOS_ATTEMPTS']       = $attemps[2];
				$_SESSION['DOS_COUNTER']        = $attemps[3];
				$_SESSION['DOS_TIMER']          = $attemps[4];
			}
		}

		/**
		 * Block DOS Attacks
		 */
		public static function secureDOS() {

			$time_safe    = 1.5; // Time safe from counter to wait (for css/js requests if not set $isAPI)
			$time_counter = 3; // Time within counter (now + ($time_counter - $time_safe))

			$time_waiting = 10; // Time to wait after reach 10 requests
			$time_expire  = 3600; // Time to reset attempts

			$time          = $_SERVER['REQUEST_TIME'];
			$ip            = self::clientIP();
			$htaccess      = realpath(self::$basedir . "/.htaccess");
			$file_attempts = realpath(self::$basedir) . "/.ddos";
			$content       = @file_get_contents($file_attempts);
			self::secureDOSRemoveOldAttempts($time_expire, $file_attempts);

			if(!isset($_SESSION['DOS_COUNTER']) || !isset($_SESSION['DOS_ATTEMPTS']) || empty($_SESSION['DOS_ATTEMPTS_TIMER']) || empty($_SESSION['DOS_TIMER'])) {
				self::secureDOSReadAttempts($ip, $file_attempts);
				$_SESSION['DOS_COUNTER']        = 0;
				$_SESSION['DOS_ATTEMPTS']       = 0;
				$_SESSION['DOS_ATTEMPTS_TIMER'] = $time;
				$_SESSION['DOS_TIMER']          = $time;
				self::secureDOSWriteAttempts($ip, $file_attempts);
			} else if($_SESSION['DOS_TIMER'] != $time) {

				if($time > $_SESSION['DOS_TIMER'] + $time_expire) {
					$_SESSION['DOS_ATTEMPTS'] = 0;
				}

				if($_SESSION['DOS_COUNTER'] >= 10 && $_SESSION['DOS_ATTEMPTS'] < 2) {
					if($time > $_SESSION['DOS_TIMER'] + $time_waiting) {
						$_SESSION['DOS_ATTEMPTS']       = $_SESSION['DOS_ATTEMPTS'] + 1;
						$_SESSION['DOS_ATTEMPTS_TIMER'] = $time;
						$_SESSION['DOS_TIMER']          = $time;
						$_SESSION['DOS_COUNTER']        = 0;
					} else {
						$url     = (isset($_SERVER['HTTPS']) ? "https" : "http") . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
						$seconds = round(($_SESSION['DOS_TIMER'] + $time_waiting) - time());
						if($seconds < 1) {
							header("Location: {$url}");
						}
						header("Refresh: {$seconds}; url={$url}");

						self::error(403, 'Permission Denied!<br>You must wait ' . $seconds . ' seconds...');
					}
					self::secureDOSWriteAttempts($ip, $file_attempts);
				} else if($_SESSION['DOS_COUNTER'] >= 10 && $_SESSION['DOS_ATTEMPTS'] > 1) {
					$htaccess_content = file_get_contents($htaccess);
					if(preg_match("/### BEGIN: BANNED IPs ###\n/i", $content)) {
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
					if($_SESSION['DOS_TIMER'] < ($time - $time_safe)) {
						if($_SESSION['DOS_TIMER'] > ($time - $time_counter)) {
							$_SESSION['DOS_COUNTER'] = $_SESSION['DOS_COUNTER'] + 1;
						} else {
							$_SESSION['DOS_COUNTER'] = 0;
						}
						$_SESSION['DOS_TIMER'] = $time;
						self::secureDOSWriteAttempts($ip, $file_attempts);
					}
				}
			}
		}

		/**
		 * Generate strong password
		 * @param int $length
		 * @param string $available_sets
		 * @return bool|string
		 */
		public static function generatePassword($length = 8, $available_sets = 'luns') {
			$sets = array();
			// lowercase
			if(strpos($available_sets, 'l') !== false) {
				$sets[] = 'abcdefghjkmnpqrstuvwxyz';
			}
			// uppercase
			if(strpos($available_sets, 'u') !== false) {
				$sets[] = 'ABCDEFGHJKMNPQRSTUVWXYZ';
			}
			// numbers
			if(strpos($available_sets, 'n') !== false) {
				$sets[] = '0123456789';
			}
			// special chars
			if(strpos($available_sets, 's') !== false) {
				$sets[] = '_-=+!@#$%&*?/';
			}
			$all      = '';
			$password = '';
			foreach($sets as $set) {
				$password .= $set[array_rand(str_split($set))];
				$all      .= $set;
			}
			$all = str_split($all);
			for($i = 0; $i < $length - count($sets); $i ++) {
				$password .= $all[array_rand($all)];
			}
			$password = str_shuffle($password);

			return $password;
		}

		/**
		 * Generate user friendly password
		 * @param $string
		 * @param $strong_lv (0-2)
		 * @return mixed|string
		 * @example generateFriendlyPassword("Marco Cesarato 1996"); // RANDOM OUTPUT: Ce$Ar4t0_m4RCo_1996
		 */
		public static function generateFriendlyPassword($string, $strong_lv = 1) {
			$alpha_replace   = array(
				'A' => '4',
				'B' => '8',
				'E' => '3',
				'S' => '$',
				'I' => '1',
				'O' => '0',
				'T' => '7',
				'L' => '2',
				'G' => '6',
			);
			$numeric_replace = array(
				'0' => 'O',
				'1' => '!',
				'4' => 'A',
				'5' => 'S',
				'6' => 'G',
				'7' => 'T',
				'8' => 'B',
			);
			$special         = '_=-+#@%&*!?;:.,\\/';
			$string          = strtolower($string);

			$estr = explode(' ', $string);

			foreach($estr as &$str) {

				$astr     = str_split($str);
				$new_astr = array();

				foreach($astr as $i => $char) {
					$char = rand(0, 100) > 50 ? strtoupper($char) : $char;
					if($strong_lv > 0 &&
					   (!empty($astr[$i - 1]) && ($new_astr[$i - 1] == $astr[$i - 1] || $astr[$i] == $astr[$i - 1]) ||
					    !empty($astr[$i + 1]) && $astr[$i] == $astr[$i + 1])) {
						if($strong_lv > 1) {
							$char = str_replace(array_keys($numeric_replace), $numeric_replace, $char);
						}
						if(strtolower($astr[$i]) == strtolower($char)) {
							$char = str_replace(array_keys($alpha_replace), $alpha_replace, strtoupper($char));
						}
					}
					$new_astr[] = $char;
				}
				$str = implode('', $new_astr);
			}

			shuffle($estr);
			$string = implode(' ', $estr);
			$string = str_replace(' ', $special[rand(0, strlen($special) - 1)], $string);

			return $string;
		}

		/**
		 * Return password strength score from 0 to 10 (under 6 is a bad score)
		 * @param $password
		 * @return int
		 */
		function passwordStrength($password) {

			$score     = 0;
			$max_score = 10;

			$uppercase = preg_match('/[A-Z]/', $password);
			$lowercase = preg_match('/[a-z]/', $password);
			$number    = preg_match('/[0-9]/', $password);
			$special_1 = preg_match('/[\-\_\=\+\&\!\?\;\.\,]/', $password);
			$special_2 = preg_match('/[\#\%\@\*\\\'\>\>\\\\\/\$\[\]\(\)\{\}\|]/', $password);
			$special_3 = preg_match('/[\^\`\~\±\§]/', $password);

			// Length
			if(strlen($password) >= 6) {
				$score ++;
			}
			if(strlen($password) >= 8) {
				$score ++;
			}
			if(strlen($password) >= 10) {
				$score ++;
			}
			if(strlen($password) >= 12) {
				$score ++;
			}

			// Chars
			if(strlen(count_chars($password, 3)) == strlen($password)) {
				$score += 2;
			} else if(strlen(count_chars($password, 3)) > (strlen($password) / 1.5)) {
				$score += 1;
			}
			if(strlen(count_chars($password, 3)) == 1) {
				$score = 1;
			}

			// Chars case and type
			if($uppercase) {
				$score ++;
			} else if($score > 3) {
				$score -= 2;
			} else if($score > 2) {
				$score --;
			}
			if($lowercase) {
				$score ++;
			} else if($score > 3) {
				$score -= 2;
			} else if($score > 2) {
				$score --;
			}
			if($number) {
				$score ++;
			} else if($score > 3) {
				$score -= 2;
			} else if($score > 2) {
				$score --;
			}
			if($special_2) {
				$score += 2;
			} else if($special_1) {
				$score ++;
			}
			if($special_3) {
				$score += 3;
			}

			// Special cases
			if($score > 6 && strlen($password) < 4) {
				return 2;
			} else if($score > 6 && strlen($password) < 5) {
				return 3;
			} else if($score > 6 && strlen($password) < 6) {
				return 5;
			} else if($score > $max_score) {
				return $max_score;
			}
			if($score < 0) {
				return 0;
			}

			return $score;
		}

		/**
		 * Hash password
		 * @param $password
		 * @param $cost (4-30)
		 * @return bool|null|string
		 */
		public static function passwordHash($password, $cost = 10) {
			if(!function_exists('crypt')) {
				return false;
			}

			if(is_null($password) || is_int($password)) {
				$password = (string) $password;
			}
			if($cost < 4 || $cost > 31) {
				trigger_error(sprintf("Invalid bcrypt cost parameter specified: %d", $cost), E_USER_WARNING);

				return null;
			}
			$hash_format  = sprintf("$2y$%02d$", $cost);
			$resultLength = 60;
			$salt         = self::getSalt();
			$hash         = $hash_format . $salt;
			$ret          = crypt($password, $hash);
			if(!is_string($ret) || strlen($ret) != $resultLength) {
				return false;
			}

			return $ret;
		}

		/**
		 * Verify password
		 * @param $password
		 * @param $hash
		 * @return bool
		 */
		public static function passwordVerify($password, $hash) {
			if(!function_exists('crypt')) {
				return false;
			}
			$ret = crypt($password, $hash);
			if(!is_string($ret) || strlen($ret) != strlen($hash) || strlen($ret) <= 13) {
				return false;
			}
			$status = 0;
			for($i = 0; $i < strlen($ret); $i ++) {
				$status |= (ord($ret[$i]) ^ ord($hash[$i]));
			}

			return ($status === 0);
		}

		/**
		 * Create a GUID
		 * @return string
		 */
		public static function generateGUID() {

			$microtime = microtime();
			list($dec, $sec) = explode(' ', $microtime);
			$dec_hex = dechex($dec * 1000000);
			$sec_hex = dechex($sec);
			$dec_hex = (strlen($dec_hex) <= 5) ? str_pad($dec_hex, 5, '0') : substr($dec_hex, 0, 5);
			$sec_hex = (strlen($sec_hex) <= 6) ? str_pad($sec_hex, 6, '0') : substr($sec_hex, 0, 6);

			// Section 1 (length 8)
			$guid = $dec_hex;
			for($i = 0; $i < 3; ++ $i) {
				$guid .= dechex(mt_rand(0, 15));
			}
			$guid .= '-';
			// Section 2 (length 4)
			for($i = 0; $i < 4; ++ $i) {
				$guid .= dechex(mt_rand(0, 15));
			}
			$guid .= '-';
			// Section 3 (length 4)
			for($i = 0; $i < 4; ++ $i) {
				$guid .= dechex(mt_rand(0, 15));
			}
			$guid .= '-';
			// Section 4 (length 4)
			for($i = 0; $i < 4; ++ $i) {
				$guid .= dechex(mt_rand(0, 15));
			}
			$guid .= '-';
			// Section 5 (length 12)
			$guid .= $sec_hex;
			for($i = 0; $i < 6; ++ $i) {
				$guid .= dechex(mt_rand(0, 15));
			}

			return $guid;
		}

		/**
		 * Check environment configuration
		 * @return array
		 */
		public function environmentCheck() {
			return array(
				array(
					"current"     => ini_get("allow_url_fopen"),
					"recommended" => 1,
					"name"        => "allow_url_fopen",
				),
				array(
					"current"     => ini_get("allow_url_include"),
					"recommended" => 0,
					"name"        => "allow_url_include",
				),
				array(
					"current"     => ini_get("register_globals"),
					"recommended" => 0,
					"name"        => "register_globals",
				),
				array(
					"current"     => ini_get("expose_php"),
					"recommended" => 0,
					"name"        => "expose_php",
				),
				array(
					"current"     => ini_get("display_errors"),
					"recommended" => 0,
					"name"        => "display_error",
				),
				array(
					"current"     => ini_get("magic_quotes_gpc"),
					"recommended" => 0,
					"name"        => "magic_quotes_gpc",
				),
				array(
					"current"     => ini_get("magic_quotes_runtime"),
					"recommended" => 0,
					"name"        => "magic_quotes_runtime",
				),
				array(
					"current"     => ini_get("magic_quotes_sybase"),
					"recommended" => 0,
					"name"        => "magic_quotes_sybase",
				),
				array(
					"current"     => ini_get("file_uploads"),
					"recommended" => 1,
					"name"        => "file_uploads",
				),
				array(
					"current"     => ini_get("upload_max_filesize"),
					"recommended" => 10485760,
					"name"        => "upload_max_filesize",
				),
				array(
					"current"     => ini_get("post_max_size"),
					"recommended" => 10485760,
					"name"        => "post_max_size",
				),
				array(
					"current"     => ini_get("memory_limit"),
					"recommended" => 134217728,
					"name"        => "memory_limit",
				),
				array(
					"current"     => ini_get("max_execution_time"),
					"recommended" => 30,
					"name"        => "max_execution_time",
				),
				array(
					"current"     => ini_get("max_input_time"),
					"recommended" => 120,
					"name"        => "max_input_time",
				),
				array(
					"current"     => ini_get("safe_mode"),
					"recommended" => 1,
					"name"        => "safe_mode",
				),
				array(
					"current"     => ini_get("sql.safe_mode"),
					"recommended" => 1,
					"name"        => "sql.safe_mode",
				),
				array(
					"current"     => ini_get("zlib.output_compression"),
					"recommended" => 1,
					"name"        => "zlib.output_compression",
				),
				array(
					"current"     => ini_get("zlib.output_compression_level"),
					"recommended" => 6,
					"name"        => "zlib.output_compression_level",
				)
			);
		}

		/**
		 * Open session
		 * @return bool
		 */
		public static function _session_open() {
			// If successful
			if(self::$database) {
				// Return True
				return true;
			}

			// Return False
			return false;
		}

		/**
		 * Close session
		 * @return bool
		 */
		public static function _session_close() {
			return true;
		}

		/**
		 * Read session
		 * @param $id
		 * @return string
		 */
		public static function _session_read($id) {
			// Set query
			$stmt = self::$database->prepare('SELECT `data` FROM sessions WHERE id = :id');
			if($stmt) {
				// Bind the Id
				$stmt->bindParam(':id', $id);
				// Attempt execution
				// If successful
				if($stmt->execute()) {
					// Save returned row
					$row = $stmt->fetch(\PDO::FETCH_ASSOC);

					// Return the data
					return base64_decode($row['data']);
				} else {
					// Return an empty string
					return '';
				}
			}
		}

		/**
		 * Write session
		 * @param $id
		 * @param $data
		 * @return bool
		 */
		public static function _session_write($id, $data) {
			// Create time stamp
			$access = time();
			// Set query
			$stmt = self::$database->prepare('REPLACE INTO sessions VALUES (:id, :access, :data, :client_ip)');
			// Bind data
			if($stmt) {
				$data = base64_encode($data);
				$ip   = self::clientIP();
				$stmt->bindParam(':id', $id);
				$stmt->bindParam(':access', $access);
				$stmt->bindParam(':data', $data);
				$stmt->bindParam(':client_ip', $ip);
				// Attempt Execution
				// If successful
				if($stmt->execute()) {
					// Return True
					return true;
				}
			}

			// Return False
			return false;
		}

		/**
		 * Destroy session
		 * @param $id
		 * @return bool
		 */
		public static function _session_destroy($id) {
			// Set query
			$stmt = self::$database->prepare('DELETE FROM sessions WHERE id = :id');
			if($stmt) {
				// Bind data
				$stmt->bindParam(':id', $id);
				// Attempt execution
				// If successful
				if($stmt->execute()) {
					// Return True
					return true;
				}
			}

			// Return False
			return false;
		}

		/**
		 * GC
		 * @param $max
		 * @return bool
		 */
		public static function _session_gc($max) {
			// Calculate what is to be deemed old
			$old = time() - $max;
			// Set query
			$stmt = self::$database->prepare('DELETE FROM sessions WHERE access < :old');
			if($stmt) {
				// Bind data
				$stmt->bindParam(':old', $old);
				// Attempt execution
				if($stmt->execute()) {
					// Return True
					return true;
				}
			}

			// Return False
			return false;
		}
	}

	/**
	 * Class Minifier
	 * @package marcocesarato\security
	 */
	class Minifier {

		private $minificationStore = array();
		private $singleQuoteSequenceFinder;
		private $doubleQuoteSequenceFinder;
		private $blockCommentFinder;
		private $lineCommentFinder;

		/**
		 * Minifier constructor.
		 */
		public function __construct() {
			$this->singleQuoteSequenceFinder = new MinifierQuoteSequenceFinder('\'');
			$this->doubleQuoteSequenceFinder = new MinifierQuoteSequenceFinder('"');
			$this->blockCommentFinder        = new MinifierStringSequenceFinder('/*', '*/');
			$this->lineCommentFinder         = new MinifierStringSequenceFinder('//', "\n");
		}

		/**
		 * Minify Javascript
		 * @param $javascript
		 * @return string
		 */
		public function minifyJS($javascript){			$this->minificationStore = array();
			return self::minifyJSRecursive($javascript);
		}

		/**
		 * Minify Javascript Recursive Function
		 * @param $javascript
		 * @return string
		 */
		private function minifyJSRecursive($javascript) {

			$java_special_chars = array(
				$this->blockCommentFinder,// JavaScript Block Comment
				$this->lineCommentFinder,// JavaScript Line Comment
				$this->singleQuoteSequenceFinder,// single quote escape, e.g. :before{ content: '-';}
				$this->doubleQuoteSequenceFinder,// double quote
				new MinifierRegexSequenceFinder('regex', "/\(\h*(\/[\k\S]+\/)/") // JavaScript regex expression
			);
			// pull out everything that needs to be pulled out and saved
			while($sequence = $this->getNextSpecialSequence($javascript, $java_special_chars)) {
				switch($sequence->type) {
					case '/*':
					case '//':// remove comments
						$javascript = substr($javascript, 0, $sequence->start_idx) . substr($javascript, $sequence->end_idx);
						break;
					default: // quoted strings or regex that need to be preservered
						$start_idx                             = ($sequence->type == 'regex' ? $sequence->sub_start_idx : $sequence->start_idx);
						$end_idx                               = ($sequence->type == 'regex' ? $sequence->sub_start_idx + strlen($sequence->sub_match) : $sequence->end_idx);
						$placeholder                           = $this->getNextMinificationPlaceholder();
						$this->minificationStore[$placeholder] = substr($javascript, $start_idx, $end_idx - $start_idx);
						$javascript                            = substr($javascript, 0, $start_idx) . $placeholder . substr($javascript, $end_idx);
				}
			}
			// special case where the + indicates treating variable as numeric, e.g. a = b + +c
			$javascript = preg_replace('/([-\+])\s+\+([^\s;]*)/', '$1 (+$2)', $javascript);
			// condense spaces
			$javascript = preg_replace("/\s*\n\s*/", "\n", $javascript); // spaces around newlines
			$javascript = preg_replace("/\h+/", " ", $javascript); // \h+ horizontal white space
			// remove unnecessary horizontal spaces around non variables (alphanumerics, underscore, dollarsign)
			$javascript = preg_replace("/\h([^A-Za-z0-9\_\$])/", '$1', $javascript);
			$javascript = preg_replace("/([^A-Za-z0-9\_\$])\h/", '$1', $javascript);
			// remove unnecessary spaces around brackets and parantheses
			$javascript = preg_replace("/\s?([\(\[{])\s?/", '$1', $javascript);
			$javascript = preg_replace("/\s([\)\]}])/", '$1', $javascript);
			// remove unnecessary spaces around operators that don't need any spaces (specifically newlines)
			$javascript = preg_replace("/\s?([\.=:\-+,])\s?/", '$1', $javascript);
			// unnecessary characters
			$javascript = preg_replace("/;\n/", ";", $javascript); // semicolon before newline
			$javascript = preg_replace('/;}/', '}', $javascript); // semicolon before end bracket
			// put back the preserved strings
			foreach($this->minificationStore as $placeholder => $original) {
				$javascript = str_replace($placeholder, $original, $javascript);
			}

			return trim($javascript);
		}

		/**
		 * Minify CSS
		 * @param $css
		 * @return string
		 */
		public function minifyCSS($css) {
			$this->minificationStore = array();
			return self::minifyCSSRecursive($css);
		}

		/**
		 * Minify CSS Recursive Function
		 * @param $css
		 * @return string
		 */
		private function minifyCSSRecursive($css) {

			$css_special_chars = array(
				$this->blockCommentFinder,// CSS Comment
				$this->singleQuoteSequenceFinder,// single quote escape, e.g. :before{ content: '-';}
				$this->doubleQuoteSequenceFinder
			); // double quote
			// pull out everything that needs to be pulled out and saved
			while($sequence = $this->getNextSpecialSequence($css, $css_special_chars)) {
				switch($sequence->type) {
					case '/*':// remove comments
						$css = substr($css, 0, $sequence->start_idx) . substr($css, $sequence->end_idx);
						break;
					default: // strings that need to be preservered
						$placeholder                           = $this->getNextMinificationPlaceholder();
						$this->minificationStore[$placeholder] = substr($css, $sequence->start_idx, $sequence->end_idx - $sequence->start_idx);
						$css                                   = substr($css, 0, $sequence->start_idx) . $placeholder . substr($css, $sequence->end_idx);
				}
			}
			// minimize the string
			$css = preg_replace('/\s{2,}/s', ' ', $css);
			$css = preg_replace('/\s*([:;{}])\s*/', '$1', $css);
			$css = preg_replace('/;}/', '}', $css);
			// put back the preserved strings
			foreach($this->minificationStore as $placeholder => $original) {
				$css = str_replace($placeholder, $original, $css);
			}

			return trim($css);
		}

		/**
		 * Minify HTML
		 * @param $html
		 * @return string
		 */
		public function minifyHTML($html) {
			$this->minificationStore = array();
			return self::minifyHTMLRecursive($html);
		}

		/**
		 * Minify HTML Recursive Function
		 * @param $html
		 * @return string
		 */
		private function minifyHTMLRecursive($html) {

			$html_special_chars = array(
				new MinifierRegexSequenceFinder('javascript', "/<\s*script(?:[^>]*)>(.*?)<\s*\/script\s*>/si"),
				// javascript, can have type attribute
				new MinifierRegexSequenceFinder('css', "/<\s*style(?:[^>]*)>(.*?)<\s*\/style\s*>/si"),
				// css, can have type/media attribute
				new MinifierRegexSequenceFinder('pre', "/<\s*pre(?:[^>]*)>(.*?)<\s*\/pre\s*>/si")
				// pre
			);
			// pull out everything that needs to be pulled out and saved
			while($sequence = $this->getNextSpecialSequence($html, $html_special_chars)) {
				$placeholder = $this->getNextMinificationPlaceholder();
				$quote       = substr($html, $sequence->start_idx, $sequence->end_idx - $sequence->start_idx);
				// subsequence (css/javascript/pre) needs special handeling, tags can still be minimized using minifyPHP
				$sub_start = $sequence->sub_start_idx - $sequence->start_idx;
				$sub_end   = $sub_start + strlen($sequence->sub_match);
				switch($sequence->type){
					case 'javascript':
						$quote = $this->minifyHTMLRecursive(substr($quote, 0, $sub_start)) . $this->minifyJSRecursive($sequence->sub_match) . $this->minifyHTMLRecursive(substr($quote, $sub_end));
						break;
					case 'css':
						$quote = $this->minifyHTMLRecursive(substr($quote, 0, $sub_start)) . $this->minifyCSSRecursive($sequence->sub_match) . $this->minifyHTMLRecursive(substr($quote, $sub_end));
						break;
					default: // strings that need to be preserved, e.g. between <pre> tags
						$quote = $this->minifyHTMLRecursive(substr($quote, 0, $sub_start)) . $sequence->sub_match . $this->minifyHTMLRecursive(substr($quote, $sub_end));
				}
				$this->minificationStore[$placeholder] = $quote;
				$html = substr($html, 0, $sequence->start_idx) . $placeholder . substr($html, $sequence->end_idx);
			}
			// condense white space
			$html = preg_replace(
				array('/\s+/u', '/<\s+/u', '/\s+>/u'),
				array(' ', '<', '>'),
				$html);
			// remove comments
			$html = preg_replace('/<!--[^\[](.*)[^\]]-->/Uuis', '', $html);
			// put back the preserved strings
			foreach($this->minificationStore as $placeholder => $original) {
				$html = str_replace($placeholder, $original, $html);
			}

			return trim($html);
		}

		/**
		 * Get next minification placeholder
		 * @return string
		 */
		private function getNextMinificationPlaceholder() {
			return '<-!!-' . sizeof($this->minificationStore) . '-!!->';
		}

		/**
		 * Get next special sequence
		 * @param $string
		 * @param $sequences
		 * @return bool|mixed
		 */
		private function getNextSpecialSequence($string, $sequences) {
			$special_idx = array();
			foreach($sequences as $finder) {
				$finder->findFirstValue($string);
				if($finder->isValid()) {
					$special_idx[$finder->start_idx] = $finder;
				}
			}
			if(count($special_idx) == 0) {
				return false;
			}
			asort($special_idx);

			return $special_idx[min(array_keys($special_idx))];
		}
	}

	/**
	 * Class MinificationSequenceFinder
	 * @package marcocesarato\security
	 */
	abstract class MinifierSequenceFinder {
		public $start_idx;
		public $end_idx;
		public $type;

		abstract protected function findFirstValue($string);

		public function isValid() {
			return $this->start_idx !== false;
		}
	}

	/**
	 * Class RegexSequenceFinder
	 * @package marcocesarato\security
	 */
	class MinifierRegexSequenceFinder extends MinifierSequenceFinder {
		protected $regex;
		public $full_match;
		public $sub_match;
		public $sub_start_idx;

		function __construct($type, $regex) {
			$this->type  = $type;
			$this->regex = $regex;
		}

		public function findFirstValue($string) {
			$this->start_idx = false; // reset
			preg_match($this->regex, $string, $matches, PREG_OFFSET_CAPTURE);
			if(count($matches) > 0) {
				$this->full_match = $matches[0][0];
				$this->start_idx  = $matches[0][1];
				if(count($matches) > 1) {
					$this->sub_match     = $matches[1][0];
					$this->sub_start_idx = $matches[1][1];
				}
				$this->end_idx = $this->start_idx + strlen($this->full_match);
			}
		}
	}

	/**
	 * Class QuoteSequenceFinder
	 * @package marcocesarato\security
	 */
	class MinifierQuoteSequenceFinder extends MinifierSequenceFinder {
		function __construct($type) {
			$this->type = $type;
		}

		public function findFirstValue($string) {
			$this->start_idx = strpos($string, $this->type);
			if($this->isValid()) {
				// look for first non escaped endquote
				$this->end_idx = $this->start_idx + 1;
				while($this->end_idx < strlen($string)) {
					// find number of escapes before endquote
					if(preg_match('/(\\\\*)(' . preg_quote($this->type) . ')/', $string, $match, PREG_OFFSET_CAPTURE, $this->end_idx)) {
						$this->end_idx = $match[2][1] + 1;
						// if odd number of escapes before endquote, endquote is escaped. Keep going
						if(!isset($match[1][0]) || strlen($match[1][0]) % 2 == 0) {
							return;
						}
					} else {// no match, not well formed
						$this->end_idx = strlen($string);

						return;
					}
				}
			}
		}
	}

	/**
	 * Class StringSequenceFinder
	 * @package marcocesarato\security
	 */
	class MinifierStringSequenceFinder extends MinifierSequenceFinder {
		protected $start_delimiter;
		protected $end_delimiter;

		function __construct($start_delimiter, $end_delimiter) {
			$this->type            = $start_delimiter;
			$this->start_delimiter = $start_delimiter;
			$this->end_delimiter   = $end_delimiter;
		}

		public function findFirstValue($string) {
			$this->start_idx = strpos($string, $this->start_delimiter);
			if($this->isValid()) {
				$this->end_idx = strpos($string, $this->end_delimiter, $this->start_idx + 1);
				// sanity check for non well formed lines
				$this->end_idx = ($this->end_idx === false ? strlen($string) : $this->end_idx + strlen($this->end_delimiter));
			}
		}
	}
}