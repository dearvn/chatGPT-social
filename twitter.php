<?php

declare(strict_types=1);

/**
 * Twitter for PHP - library for sending messages to Twitter and receiving status updates.
 *
 * Copyright (c) 2008 David Grudl (https://davidgrudl.com)
 * This software is licensed under the New BSD License.
 *
 * Homepage:    https://phpfashion.com/twitter-for-php
 * Twitter API: https://dev.twitter.com/rest/public
 * Version:     4.1
 */


/**
 * Twitter API.
 */
class Twitter
{
	public const ME = 1;
	public const ME_AND_FRIENDS = 2;
	public const REPLIES = 3;
	public const RETWEETS = 128; // include retweets?

	private const API_URL = 'https://api.twitter.com/1.1/';

	/** @var int */
	public static $cacheExpire = '30 minutes';

	/** @var string */
	public static $cacheDir;

	/** @var array */
	public $httpOptions = [
		CURLOPT_TIMEOUT => 20,
		CURLOPT_SSL_VERIFYPEER => 0,
		CURLOPT_USERAGENT => 'Twitter for PHP',
	];

	/** @var Consumer */
	private $consumer;

	/** @var Token */
	private $token;


	/**
	 * Creates object using consumer and access keys.
	 * @throws Exception when CURL extension is not loaded
	 */
	public function __construct(
		string $consumerKey,
		string $consumerSecret,
		string $accessToken = null,
		string $accessTokenSecret = null
	) {
		if (!extension_loaded('curl')) {
			throw new \Exception('PHP extension CURL is not loaded.');
		}

		$this->consumer = new Consumer($consumerKey, $consumerSecret);
		if ($accessToken && $accessTokenSecret) {
			$this->token = new Token($accessToken, $accessTokenSecret);
		}
	}


	/**
	 * Tests if user credentials are valid.
	 * @throws Exception
	 */
	public function authenticate(): bool
	{
		try {
			$res = $this->request('account/verify_credentials', 'GET');
			return !empty($res->id);

		} catch (\Exception $e) {
			if ($e->getCode() === 401) {
				return false;
			}
			throw $e;
		}
	}


	/**
	 * Sends message to the Twitter.
	 * https://dev.twitter.com/rest/reference/post/statuses/update
	 * @param  string|array  $mediaPath  path to local media file to be uploaded
	 * @throws Exception
	 */
	public function send(string $message, $mediaPath = null, array $options = []): stdClass
	{
		$mediaIds = [];
		foreach ((array) $mediaPath as $item) {
			$res = $this->request(
				'https://upload.twitter.com/1.1/media/upload.json',
				'POST',
				[],
				['media' => $item]
			);
			$mediaIds[] = $res->media_id_string;
		}
		return $this->request(
			'statuses/update',
			'POST',
			$options + ['status' => $message, 'media_ids' => implode(',', $mediaIds) ?: null]
		);
	}


	/**
	 * Sends a direct message to the specified user.
	 * https://dev.twitter.com/rest/reference/post/direct_messages/new
	 * @throws Exception
	 */
	public function sendDirectMessage(string $username, string $message): stdClass
	{
		return $this->request(
			'direct_messages/events/new',
			'JSONPOST',
			['event' => [
				'type' => 'message_create',
				'message_create' => [
					'target' => ['recipient_id' => $this->loadUserInfo($username)->id_str],
					'message_data' => ['text' => $message],
				],
			]]
		);
	}


	/**
	 * Follows a user on Twitter.
	 * https://dev.twitter.com/rest/reference/post/friendships/create
	 * @throws Exception
	 */
	public function follow(string $username): stdClass
	{
		return $this->request('friendships/create', 'POST', ['screen_name' => $username]);
	}


	/**
	 * Returns the most recent statuses.
	 * https://dev.twitter.com/rest/reference/get/statuses/user_timeline
	 * @param  int  $flags  timeline (ME | ME_AND_FRIENDS | REPLIES) and optional (RETWEETS)
	 * @return stdClass[]
	 * @throws Exception
	 */
	public function load(int $flags = self::ME, int $count = 20, array $data = null): array
	{
		static $timelines = [
			self::ME => 'user_timeline',
			self::ME_AND_FRIENDS => 'home_timeline',
			self::REPLIES => 'mentions_timeline',
		];
		if (!isset($timelines[$flags & 3])) {
			throw new \InvalidArgumentException;
		}

		return $this->cachedRequest('statuses/' . $timelines[$flags & 3], (array) $data + [
			'count' => $count,
			'include_rts' => $flags & self::RETWEETS ? 1 : 0,
		]);
	}


	/**
	 * Returns information of a given user.
	 * https://dev.twitter.com/rest/reference/get/users/show
	 * @throws Exception
	 */
	public function loadUserInfo(string $username): stdClass
	{
		return $this->cachedRequest('users/show', ['screen_name' => $username]);
	}


	/**
	 * Returns information of a given user by id.
	 * https://dev.twitter.com/rest/reference/get/users/show
	 * @throws Exception
	 */
	public function loadUserInfoById(string $id): stdClass
	{
		return $this->cachedRequest('users/show', ['user_id' => $id]);
	}


	/**
	 * Returns IDs of followers of a given user.
	 * https://dev.twitter.com/rest/reference/get/followers/ids
	 * @throws \Exception
	 */
	public function loadUserFollowers(
		string $username,
		int $count = 5000,
		int $cursor = -1,
		$cacheExpiry = null
	): stdClass
	{
		return $this->cachedRequest('followers/ids', [
			'screen_name' => $username,
			'count' => $count,
			'cursor' => $cursor,
		], $cacheExpiry);
	}


	/**
	 * Returns list of followers of a given user.
	 * https://dev.twitter.com/rest/reference/get/followers/list
	 * @throws Exception
	 */
	public function loadUserFollowersList(
		string $username,
		int $count = 200,
		int $cursor = -1,
		$cacheExpiry = null
	): stdClass
	{
		return $this->cachedRequest('followers/list', [
			'screen_name' => $username,
			'count' => $count,
			'cursor' => $cursor,
		], $cacheExpiry);
	}


	/**
	 * Destroys status.
	 * @param  int|string  $id  status to be destroyed
	 * @throws Exception
	 */
	public function destroy($id)
	{
		$res = $this->request("statuses/destroy/$id", 'POST', ['id' => $id]);
		return $res->id ?: false;
	}


	/**
	 * Retrieves a single status.
	 * @param  int|string  $id  status to be retrieved
	 * @throws Exception
	 */
	public function get($id)
	{
		$res = $this->request("statuses/show/$id", 'GET');
		return $res;
	}


	/**
	 * Returns tweets that match a specified query.
	 * https://dev.twitter.com/rest/reference/get/search/tweets
	 * @param  string|array
	 * @throws Exception
	 * @return stdClass|stdClass[]
	 */
	public function search($query, bool $full = false)
	{
		$res = $this->request('search/tweets', 'GET', is_array($query) ? $query : ['q' => $query]);
		return $full ? $res : $res->statuses;
	}


	/**
	 * Retrieves the top 50 trending topics for a specific WOEID.
	 * @param  int|string  $WOEID  Where On Earth IDentifier
	 */
	public function getTrends(int $WOEID): array
	{
		return $this->request("trends/place.json?id=$WOEID", 'GET');
	}


	/**
	 * Process HTTP request.
	 * @param  string  $method  GET|POST|JSONPOST|DELETE
	 * @return mixed
	 * @throws Exception
	 */
	public function request(string $resource, string $method, array $data = [], array $files = [])
	{
		if (!strpos($resource, '://')) {
			if (!strpos($resource, '.')) {
				$resource .= '.json';
			}
			$resource = self::API_URL . $resource;
		}

		foreach ($data as $key => $val) {
			if ($val === null) {
				unset($data[$key]);
			}
		}

		foreach ($files as $key => $file) {
			if (!is_file($file)) {
				throw new \Exception("Cannot read the file $file. Check if file exists on disk and check its permissions.");
			}
			$data[$key] = new \CURLFile($file);
		}

		$headers = ['Expect:'];

		if ($method === 'JSONPOST') {
			$method = 'POST';
			$data = json_encode($data);
			$headers[] = 'Content-Type: application/json';

		} elseif (($method === 'GET' || $method === 'DELETE') && $data) {
			$resource .= '?' . http_build_query($data, '', '&');
		}

		$request = Request::from_consumer_and_token($this->consumer, $this->token, $method, $resource);
		$request->sign_request(new SignatureMethod_HMAC_SHA1, $this->consumer, $this->token);
		$headers[] = $request->to_header();

		$options = [
			CURLOPT_URL => $resource,
			CURLOPT_HEADER => false,
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_HTTPHEADER => $headers,
		] + $this->httpOptions;

		if ($method === 'POST') {
			$options += [
				CURLOPT_POST => true,
				CURLOPT_POSTFIELDS => $data,
				CURLOPT_SAFE_UPLOAD => true,
			];
		} elseif ($method === 'DELETE') {
			$options += [
				CURLOPT_CUSTOMREQUEST => 'DELETE',
			];
		}

		$curl = curl_init();
		curl_setopt_array($curl, $options);
		$result = curl_exec($curl);
		if (curl_errno($curl)) {
			throw new \Exception('Server error: ' . curl_error($curl));
		}

		if (strpos(curl_getinfo($curl, CURLINFO_CONTENT_TYPE), 'application/json') !== false) {
			$payload = @json_decode($result, false, 128, JSON_BIGINT_AS_STRING); // intentionally @
			if ($payload === false) {
				throw new \Exception('Invalid server response');
			}
		}

		$code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
		if ($code >= 400) {
			throw new \Exception(
				$payload->errors[0]->message ?? "Server error #$code with answer $result",
				$code
			);
		} elseif ($code === 204) {
			$payload = true;
		}

		return $payload;
	}


	/**
	 * Cached HTTP request.
	 * @return stdClass|stdClass[]
	 */
	public function cachedRequest(string $resource, array $data = [], $cacheExpire = null)
	{
		if (!self::$cacheDir) {
			return $this->request($resource, 'GET', $data);
		}
		if ($cacheExpire === null) {
			$cacheExpire = self::$cacheExpire;
		}

		$cacheFile = self::$cacheDir
			. '/twitter.'
			. md5($resource . json_encode($data) . serialize([$this->consumer, $this->token]))
			. '.json';

		$cache = @json_decode((string) @file_get_contents($cacheFile)); // intentionally @
		$expiration = is_string($cacheExpire)
			? strtotime($cacheExpire) - time()
			: $cacheExpire;
		if ($cache && @filemtime($cacheFile) + $expiration > time()) { // intentionally @
			return $cache;
		}

		try {
			$payload = $this->request($resource, 'GET', $data);
			file_put_contents($cacheFile, json_encode($payload));
			return $payload;

		} catch (\Exception $e) {
			if ($cache) {
				return $cache;
			}
			throw $e;
		}
	}


	/**
	 * Makes twitter links, @usernames and #hashtags clickable.
	 */
	public static function clickable(stdClass $status): string
	{
		$all = [];
		foreach ($status->entities->hashtags as $item) {
			$all[$item->indices[0]] = ["https://twitter.com/search?q=%23$item->text", "#$item->text", $item->indices[1]];
		}
		foreach ($status->entities->urls as $item) {
			if (!isset($item->expanded_url)) {
				$all[$item->indices[0]] = [$item->url, $item->url, $item->indices[1]];
			} else {
				$all[$item->indices[0]] = [$item->expanded_url, $item->display_url, $item->indices[1]];
			}
		}
		foreach ($status->entities->user_mentions as $item) {
			$all[$item->indices[0]] = ["https://twitter.com/$item->screen_name", "@$item->screen_name", $item->indices[1]];
		}
		if (isset($status->entities->media)) {
			foreach ($status->entities->media as $item) {
				$all[$item->indices[0]] = [$item->url, $item->display_url, $item->indices[1]];
			}
		}

		krsort($all);
		$s = $status->full_text ?? $status->text;
		foreach ($all as $pos => $item) {
			$s = iconv_substr($s, 0, $pos, 'UTF-8')
				. '<a href="' . htmlspecialchars($item[0]) . '">' . htmlspecialchars($item[1]) . '</a>'
				. iconv_substr($s, $item[2], iconv_strlen($s, 'UTF-8'), 'UTF-8');
		}
		return $s;
	}
}


class Consumer
{
	public $key;
	public $secret;


	public function __construct(string $key, string $secret)
	{
		$this->key = $key;
		$this->secret = $secret;
	}


	public function __toString(): string
	{
		return "OAuthConsumer[key=$this->key,secret=$this->secret]";
	}
}


class Token
{
	// access tokens and request tokens
	public $key;
	public $secret;


	/**
	 * key = the token
	 * secret = the token secret
	 */
	public function __construct(string $key, string $secret)
	{
		$this->key = $key;
		$this->secret = $secret;
	}


	/**
	 * generates the basic string serialization of a token that a server
	 * would respond to request_token and access_token calls with
	 */
	public function to_string(): string
	{
		return 'oauth_token=' .
			Util::urlencode_rfc3986($this->key) .
			'&oauth_token_secret=' .
			Util::urlencode_rfc3986($this->secret);
	}


	public function __toString(): string
	{
		return $this->to_string();
	}
}


/**
 * A class for implementing a Signature Method
 * See section 9 ("Signing Requests") in the spec
 */
abstract class SignatureMethod
{
	/**
	 * Needs to return the name of the Signature Method (ie HMAC-SHA1)
	 */
	abstract public function get_name(): string;


	/**
	 * Build up the signature
	 * NOTE: The output of this function MUST NOT be urlencoded.
	 * the encoding is handled in OAuthRequest when the final
	 * request is serialized
	 */
	abstract public function build_signature(Request $request, Consumer $consumer, ?Token $token): string;


	/**
	 * Verifies that a given signature is correct
	 */
	public function check_signature(Request $request, Consumer $consumer, Token $token, string $signature): bool
	{
		$built = $this->build_signature($request, $consumer, $token);
		return $built == $signature;
	}
}


/**
 * The HMAC-SHA1 signature method uses the HMAC-SHA1 signature algorithm as defined in [RFC2104]
 * where the Signature Base String is the text and the key is the concatenated values (each first
 * encoded per Parameter Encoding) of the Consumer Secret and Token Secret, separated by an '&'
 * character (ASCII code 38) even if empty.
 *   - Chapter 9.2 ("HMAC-SHA1")
 */
class SignatureMethod_HMAC_SHA1 extends SignatureMethod
{
	public function get_name(): string
	{
		return 'HMAC-SHA1';
	}


	public function build_signature(Request $request, Consumer $consumer, ?Token $token): string
	{
		$base_string = $request->get_signature_base_string();
		$request->base_string = $base_string;

		$key_parts = [
			$consumer->secret,
			$token ? $token->secret : '',
		];

		$key_parts = Util::urlencode_rfc3986($key_parts);
		$key = implode('&', $key_parts);

		return base64_encode(hash_hmac('sha1', $base_string, $key, true));
	}
}


/**
 * The PLAINTEXT method does not provide any security protection and SHOULD only be used
 * over a secure channel such as HTTPS. It does not use the Signature Base String.
 *   - Chapter 9.4 ("PLAINTEXT")
 */
class SignatureMethod_PLAINTEXT extends SignatureMethod
{
	public function get_name(): string
	{
		return 'PLAINTEXT';
	}


	/**
	 * oauth_signature is set to the concatenated encoded values of the Consumer Secret and
	 * Token Secret, separated by a '&' character (ASCII code 38), even if either secret is
	 * empty. The result MUST be encoded again.
	 *   - Chapter 9.4.1 ("Generating Signatures")
	 *
	 * Please note that the second encoding MUST NOT happen in the SignatureMethod, as
	 * OAuthRequest handles this!
	 */
	public function build_signature(Request $request, Consumer $consumer, ?Token $token): string
	{
		$key_parts = [
			$consumer->secret,
			$token ? $token->secret : '',
		];

		$key_parts = Util::urlencode_rfc3986($key_parts);
		$key = implode('&', $key_parts);
		$request->base_string = $key;

		return $key;
	}
}


/**
 * The RSA-SHA1 signature method uses the RSASSA-PKCS1-v1_5 signature algorithm as defined in
 * [RFC3447] section 8.2 (more simply known as PKCS#1), using SHA-1 as the hash function for
 * EMSA-PKCS1-v1_5. It is assumed that the Consumer has provided its RSA public key in a
 * verified way to the Service Provider, in a manner which is beyond the scope of this
 * specification.
 *   - Chapter 9.3 ("RSA-SHA1")
 */
abstract class SignatureMethod_RSA_SHA1 extends SignatureMethod
{
	public function get_name(): string
	{
		return 'RSA-SHA1';
	}


	/**
	 * Up to the SP to implement this lookup of keys. Possible ideas are:
	 * (1) do a lookup in a table of trusted certs keyed off of consumer
	 * (2) fetch via http using a url provided by the requester
	 * (3) some sort of specific discovery code based on request
	 *
	 * Either way should return a string representation of the certificate
	 */
	abstract protected function fetch_public_cert(&$request);


	/**
	 * Up to the SP to implement this lookup of keys. Possible ideas are:
	 * (1) do a lookup in a table of trusted certs keyed off of consumer
	 *
	 * Either way should return a string representation of the certificate
	 */
	abstract protected function fetch_private_cert(&$request);


	public function build_signature(Request $request, Consumer $consumer, ?Token $token): string
	{
		$base_string = $request->get_signature_base_string();
		$request->base_string = $base_string;

		// Fetch the private key cert based on the request
		$cert = $this->fetch_private_cert($request);

		// Pull the private key ID from the certificate
		$privatekeyid = openssl_get_privatekey($cert);

		// Sign using the key
		$ok = openssl_sign($base_string, $signature, $privatekeyid);

		// Release the key resource
		openssl_free_key($privatekeyid);

		return base64_encode($signature);
	}


	public function check_signature(Request $request, Consumer $consumer, Token $token, string $signature): bool
	{
		$decoded_sig = base64_decode($signature, true);

		$base_string = $request->get_signature_base_string();

		// Fetch the public key cert based on the request
		$cert = $this->fetch_public_cert($request);

		// Pull the public key ID from the certificate
		$publickeyid = openssl_get_publickey($cert);

		// Check the computed signature against the one passed in the query
		$ok = openssl_verify($base_string, $decoded_sig, $publickeyid);

		// Release the key resource
		openssl_free_key($publickeyid);

		return $ok == 1;
	}
}


class Request
{
	// for debug purposes
	public $base_string;
	public static $version = '1.0';
	public static $POST_INPUT = 'php://input';
	protected $parameters;
	protected $http_method;
	protected $http_url;


	public function __construct(string $http_method, string $http_url, array $parameters = null)
	{
		$parameters = $parameters ?: [];
		$parameters = array_merge(Util::parse_parameters((string) parse_url($http_url, PHP_URL_QUERY)), $parameters);
		$this->parameters = $parameters;
		$this->http_method = $http_method;
		$this->http_url = $http_url;
	}


	/**
	 * attempt to build up a request from what was passed to the server
	 */
	public static function from_request(
		string $http_method = null,
		string $http_url = null,
		array $parameters = null
	): self
	{
		$scheme = (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] != 'on')
			? 'http'
			: 'https';
		$http_url = ($http_url)
			? $http_url
			: $scheme .
			'://' . $_SERVER['HTTP_HOST'] .
			':' .
			$_SERVER['SERVER_PORT'] .
			$_SERVER['REQUEST_URI'];
		$http_method = ($http_method) ? $http_method : $_SERVER['REQUEST_METHOD'];

		// We weren't handed any parameters, so let's find the ones relevant to
		// this request.
		// If you run XML-RPC or similar you should use this to provide your own
		// parsed parameter-list
		if (!$parameters) {
			// Find request headers
			$request_headers = Util::get_headers();

			// Parse the query-string to find GET parameters
			$parameters = Util::parse_parameters($_SERVER['QUERY_STRING']);

			// It's a POST request of the proper content-type, so parse POST
			// parameters and add those overriding any duplicates from GET
			if ($http_method == 'POST'
				&& isset($request_headers['Content-Type'])
				&& strstr($request_headers['Content-Type'], 'application/x-www-form-urlencoded')
			) {
				$post_data = Util::parse_parameters(
					file_get_contents(self::$POST_INPUT)
				);
				$parameters = array_merge($parameters, $post_data);
			}

			// We have a Authorization-header with OAuth data. Parse the header
			// and add those overriding any duplicates from GET or POST
			if (
				isset($request_headers['Authorization'])
				&& substr($request_headers['Authorization'], 0, 6) == 'OAuth '
			) {
				$header_parameters = Util::split_header(
					$request_headers['Authorization']
				);
				$parameters = array_merge($parameters, $header_parameters);
			}
		}

		return new self($http_method, $http_url, $parameters);
	}


	/**
	 * pretty much a helper function to set up the request
	 */
	public static function from_consumer_and_token(
		Consumer $consumer,
		?Token $token,
		string $http_method,
		string $http_url,
		array $parameters = null
	): self
	{
		$parameters = $parameters ?: [];
		$defaults = [
			'oauth_version' => self::$version,
			'oauth_nonce' => self::generate_nonce(),
			'oauth_timestamp' => self::generate_timestamp(),
			'oauth_consumer_key' => $consumer->key,
		];
		if ($token) {
			$defaults['oauth_token'] = $token->key;
		}

		$parameters = array_merge($defaults, $parameters);

		return new self($http_method, $http_url, $parameters);
	}


	public function set_parameter(string $name, $value, bool $allow_duplicates = true): void
	{
		if ($allow_duplicates && isset($this->parameters[$name])) {
			// We have already added parameter(s) with this name, so add to the list
			if (is_scalar($this->parameters[$name])) {
				// This is the first duplicate, so transform scalar (string)
				// into an array so we can add the duplicates
				$this->parameters[$name] = [$this->parameters[$name]];
			}

			$this->parameters[$name][] = $value;
		} else {
			$this->parameters[$name] = $value;
		}
	}


	public function get_parameter(string $name)
	{
		return $this->parameters[$name] ?? null;
	}


	public function get_parameters(): array
	{
		return $this->parameters;
	}


	public function unset_parameter(string $name): void
	{
		unset($this->parameters[$name]);
	}


	/**
	 * The request parameters, sorted and concatenated into a normalized string.
	 */
	public function get_signable_parameters(): string
	{
		// Grab all parameters
		$params = $this->parameters;

		// Remove oauth_signature if present
		// Ref: Spec: 9.1.1 ("The oauth_signature parameter MUST be excluded.")
		if (isset($params['oauth_signature'])) {
			unset($params['oauth_signature']);
		}

		return Util::build_http_query($params);
	}


	/**
	 * Returns the base string of this request
	 *
	 * The base string defined as the method, the url
	 * and the parameters (normalized), each urlencoded
	 * and the concated with &.
	 */
	public function get_signature_base_string(): string
	{
		$parts = [
			$this->get_normalized_http_method(),
			$this->get_normalized_http_url(),
			$this->get_signable_parameters(),
		];

		$parts = Util::urlencode_rfc3986($parts);

		return implode('&', $parts);
	}


	/**
	 * just uppercases the http method
	 */
	public function get_normalized_http_method(): string
	{
		return strtoupper($this->http_method);
	}


	/**
	 * parses the url and rebuilds it to be
	 * scheme://host/path
	 */
	public function get_normalized_http_url(): string
	{
		$parts = parse_url($this->http_url);

		$scheme = (isset($parts['scheme'])) ? $parts['scheme'] : 'http';
		$port = (isset($parts['port']))
			? $parts['port']
			: (($scheme == 'https') ? '443' : '80');
		$host = (isset($parts['host'])) ? $parts['host'] : '';
		$path = (isset($parts['path'])) ? $parts['path'] : '';

		if (($scheme == 'https' && $port != '443')
				|| ($scheme == 'http' && $port != '80')) {
			$host = "$host:$port";
		}
		return "$scheme://$host$path";
	}


	/**
	 * builds a url usable for a GET request
	 */
	public function to_url(): string
	{
		$post_data = $this->to_postdata();
		$out = $this->get_normalized_http_url();
		if ($post_data) {
			$out .= '?' . $post_data;
		}
		return $out;
	}


	/**
	 * builds the data one would send in a POST request
	 */
	public function to_postdata(): string
	{
		return Util::build_http_query($this->parameters);
	}


	/**
	 * builds the Authorization: header
	 */
	public function to_header(string $realm = null): string
	{
		$first = true;
		if ($realm) {
			$out = 'Authorization: OAuth realm="' . Util::urlencode_rfc3986($realm) . '"';
			$first = false;
		} else {
			$out = 'Authorization: OAuth';
		}

		$total = [];
		foreach ($this->parameters as $k => $v) {
			if (substr($k, 0, 5) != 'oauth') {
				continue;
			}
			if (is_array($v)) {
				throw new \Exception('Arrays not supported in headers');
			}
			$out .= $first ? ' ' : ',';
			$out .= Util::urlencode_rfc3986($k) . '="' . Util::urlencode_rfc3986($v) . '"';
			$first = false;
		}
		return $out;
	}


	public function __toString(): string
	{
		return $this->to_url();
	}


	public function sign_request(SignatureMethod $signature_method, Consumer $consumer, ?Token $token)
	{
		$this->set_parameter(
			'oauth_signature_method',
			$signature_method->get_name(),
			false
		);
		$signature = $this->build_signature($signature_method, $consumer, $token);
		$this->set_parameter('oauth_signature', $signature, false);
	}


	public function build_signature(SignatureMethod $signature_method, Consumer $consumer, ?Token $token)
	{
		$signature = $signature_method->build_signature($this, $consumer, $token);
		return $signature;
	}


	/**
	 * util function: current timestamp
	 */
	private static function generate_timestamp(): int
	{
		return time();
	}


	/**
	 * util function: current nonce
	 */
	private static function generate_nonce(): string
	{
		$mt = microtime();
		$rand = mt_rand();

		return md5($mt . $rand); // md5s look nicer than numbers
	}
}


class Util
{
	public static function urlencode_rfc3986($input)
	{
		if (is_array($input)) {
			return array_map([self::class, 'urlencode_rfc3986'], $input);
		} elseif (is_scalar($input)) {
			return str_replace('+', ' ', str_replace('%7E', '~', rawurlencode((string) $input)));
		} else {
			return '';
		}
	}


	/**
	 * This decode function isn't taking into consideration the above
	 * modifications to the encoding process. However, this method doesn't
	 * seem to be used anywhere so leaving it as is.
	 */
	public static function urldecode_rfc3986(string $string): string
	{
		return urldecode($string);
	}


	/**
	 * Utility function for turning the Authorization: header into
	 * parameters, has to do some unescaping
	 * Can filter out any non-oauth parameters if needed (default behaviour)
	 */
	public static function split_header(string $header, bool $only_allow_oauth_parameters = true): array
	{
		$params = [];
		if (preg_match_all('/(' . ($only_allow_oauth_parameters ? 'oauth_' : '') . '[a-z_-]*)=(:?"([^"]*)"|([^,]*))/', $header, $matches)) {
			foreach ($matches[1] as $i => $h) {
				$params[$h] = self::urldecode_rfc3986(empty($matches[3][$i]) ? $matches[4][$i] : $matches[3][$i]);
			}
			if (isset($params['realm'])) {
				unset($params['realm']);
			}
		}
		return $params;
	}


	/**
	 * helper to try to sort out headers for people who aren't running apache
	 */
	public static function get_headers(): array
	{
		if (function_exists('apache_request_headers')) {
			// we need this to get the actual Authorization: header
			// because apache tends to tell us it doesn't exist
			$headers = apache_request_headers();

			// sanitize the output of apache_request_headers because
			// we always want the keys to be Cased-Like-This and arh()
			// returns the headers in the same case as they are in the
			// request
			$out = [];
			foreach ($headers as $key => $value) {
				$key = str_replace(
					' ',
					'-',
					ucwords(strtolower(str_replace('-', ' ', $key)))
				);
				$out[$key] = $value;
			}
		} else {
			// otherwise we don't have apache and are just going to have to hope
			// that $_SERVER actually contains what we need
			$out = [];
			if (isset($_SERVER['CONTENT_TYPE'])) {
				$out['Content-Type'] = $_SERVER['CONTENT_TYPE'];
			}
			if (isset($_ENV['CONTENT_TYPE'])) {
				$out['Content-Type'] = $_ENV['CONTENT_TYPE'];
			}

			foreach ($_SERVER as $key => $value) {
				if (substr($key, 0, 5) == 'HTTP_') {
					// this is chaos, basically it is just there to capitalize the first
					// letter of every word that is not an initial HTTP and strip HTTP
					// code from przemek
					$key = str_replace(
						' ',
						'-',
						ucwords(strtolower(str_replace('_', ' ', substr($key, 5))))
					);
					$out[$key] = $value;
				}
			}
		}
		return $out;
	}


	/**
	 * This function takes a input like a=b&a=c&d=e and returns the parsed parameters like this
	 * ['a' => array('b','c'), 'd' => 'e']
	 */
	public static function parse_parameters(string $input): array
	{
		if (!isset($input) || !$input) {
			return [];
		}

		$pairs = explode('&', $input);

		$parsed_parameters = [];
		foreach ($pairs as $pair) {
			$split = explode('=', $pair, 2);
			$parameter = self::urldecode_rfc3986($split[0]);
			$value = isset($split[1]) ? self::urldecode_rfc3986($split[1]) : '';

			if (isset($parsed_parameters[$parameter])) {
				// We have already recieved parameter(s) with this name, so add to the list
				// of parameters with this name

				if (is_scalar($parsed_parameters[$parameter])) {
					// This is the first duplicate, so transform scalar (string) into an array
					// so we can add the duplicates
					$parsed_parameters[$parameter] = [$parsed_parameters[$parameter]];
				}

				$parsed_parameters[$parameter][] = $value;
			} else {
				$parsed_parameters[$parameter] = $value;
			}
		}
		return $parsed_parameters;
	}


	public static function build_http_query(array $params): string
	{
		if (!$params) {
			return '';
		}

		// Urlencode both keys and values
		$keys = self::urlencode_rfc3986(array_keys($params));
		$values = self::urlencode_rfc3986(array_values($params));
		$params = array_combine($keys, $values);

		// Parameters are sorted by name, using lexicographical byte value ordering.
		// Ref: Spec: 9.1.1 (1)
		uksort($params, 'strcmp');

		$pairs = [];
		foreach ($params as $parameter => $value) {
			if (is_array($value)) {
				// If two or more parameters share the same name, they are sorted by their value
				// Ref: Spec: 9.1.1 (1)
				// June 12th, 2010 - changed to sort because of issue 164 by hidetaka
				sort($value, SORT_STRING);
				foreach ($value as $duplicate_value) {
					$pairs[] = $parameter . '=' . $duplicate_value;
				}
			} else {
				$pairs[] = $parameter . '=' . $value;
			}
		}
		// For each parameter, the name is separated from the corresponding value by an '=' character (ASCII code 61)
		// Each name-value pair is separated by an '&' character (ASCII code 38)
		return implode('&', $pairs);
	}
}



function substr_words($text, $maxchar) {
	if (strlen($text) > $maxchar || $text == '') {
		$words = preg_split('/\s/', $text);
		$output = '';
		$i      = 0;
		while (1) {
			$length = strlen($output)+strlen($words[$i]);
			if ($length > $maxchar) {
				break;
			}
			else {
				$output .= " " . $words[$i];
				++$i;
			}
		}
	}
	else {
		$output = $text;
	}
	return $output;
}

function post_chatGPT($text, $token) {
	try {
		$ch = curl_init();

		$payload = [
			"model" => "text-davinci-003",
			"prompt" => $text,
			"temperature" => 0.7,
			"max_tokens" => 2049, // max-limit = 2049
			"top_p" => 1,
			"best_of" => 1,
		];
		
		curl_setopt($ch, CURLOPT_HTTPHEADER, [
			"Content-Type: application/json; charset=utf-8",
			"Authorization: Bearer $token",
			"Accept-Charset: application/json; charset=utf-8"
		]);

		curl_setopt($ch, CURLOPT_URL,"https://api.openai.com/v1/completions");
		curl_setopt($ch, CURLOPT_POST, 1);
		curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));

		// Receive server response ...
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

		$output = curl_exec($ch);

		curl_close($ch);

		if (empty($output)) {
			return '';
		}

		$resp = json_decode($output);
		if (empty($resp) || empty($resp->choices)) {
			return '';
		}
		$items = (array)$resp->choices;
		return $items[0]->text;
	} catch (\Exception $e) {
		echo $e->getMessage();
	}
}

function file_get_contents_curl($url) {
	$ch = curl_init();

	curl_setopt($ch, CURLOPT_AUTOREFERER, TRUE);
	curl_setopt($ch, CURLOPT_HEADER, 0);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_URL, $url);
	curl_setopt($ch, CURLOPT_FOLLOWLOCATION, TRUE);       

	$data = curl_exec($ch);
	curl_close($ch);

	return $data;
}

$tokenGPT = '';

$consumerKey = '';
$consumerSecret = '';
$accessToken = '';
$accessTokenSecret = '';

$twitter = new Twitter($consumerKey, $consumerSecret, $accessToken, $accessTokenSecret);

try {
	$trends = $twitter->getTrends(2459115);

	foreach($trends[0]->trends as $item) {
		$text = "write funny content maximum 200 characters about {$item->url}";

		$content = post_chatGPT($text, $tokenGPT);

		if (empty($content)) {
			continue;
		}

		if (strlen($content) > 280) {
			$content = substr_words($content, 260);
		}
		echo $content.PHP_EOL;
		
		$twitter->send($content);

	}
            
} catch (\Exception $e) {
	echo 'Error: ' . $e->getMessage();
}
