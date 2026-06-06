<?php
/**
 * Blocking engine.
 *
 * @package NexiGuard
 */

defined( 'ABSPATH' ) || exit;

/**
 * Handles visitor detection, rule matching, responses, and logging.
 */
class NexiGuard_Blocker {

	/** @var NexiGuard */
	private $plugin;

	/** @var NexiGuard_Geo */
	private $geo;

	/** @var NexiGuard_Logger */
	private $logger;

	/**
	 * Constructor.
	 *
	 * @param NexiGuard        $plugin Plugin instance.
	 * @param NexiGuard_Geo    $geo Geo service.
	 * @param NexiGuard_Logger $logger Logger service.
	 */
	public function __construct( NexiGuard $plugin, NexiGuard_Geo $geo, NexiGuard_Logger $logger ) {
		$this->plugin = $plugin;
		$this->geo    = $geo;
		$this->logger = $logger;

		add_action( 'template_redirect', array( $this, 'maybe_block_frontend' ), 0 );
		add_action( 'login_init', array( $this, 'maybe_block_login' ), 0 );
		add_filter( 'rest_authentication_errors', array( $this, 'maybe_block_rest' ), 0 );
		add_filter( 'xmlrpc_enabled', array( $this, 'maybe_block_xmlrpc' ), 10, 1 );
	}

	/**
	 * Blocks frontend requests when configured.
	 *
	 * @return void
	 */
	public function maybe_block_frontend() {
		$settings = $this->plugin->get_settings();

		if ( empty( $settings['block_frontend'] ) ) {
			return;
		}

		$match = $this->get_block_match( 'frontend' );

		if ( $match['blocked'] ) {
			$this->logger->log( $match['ip'], $match['rule_type'], $this->get_request_path() );
			$this->send_blocked_response();
		}
	}

	/**
	 * Blocks login requests when configured.
	 *
	 * @return void
	 */
	public function maybe_block_login() {
		$settings = $this->plugin->get_settings();

		if ( empty( $settings['block_login'] ) ) {
			return;
		}

		$match = $this->get_block_match( 'login' );

		if ( $match['blocked'] ) {
			$this->logger->log( $match['ip'], $match['rule_type'], $this->get_request_path() );
			$this->send_blocked_response();
		}
	}

	/**
	 * Blocks REST API requests when configured.
	 *
	 * @param WP_Error|null|bool $result Existing authentication result.
	 * @return WP_Error|null|bool
	 */
	public function maybe_block_rest( $result ) {
		if ( is_wp_error( $result ) ) {
			return $result;
		}

		$settings = $this->plugin->get_settings();

		if ( empty( $settings['block_rest'] ) ) {
			return $result;
		}

		$match = $this->get_block_match( 'rest' );

		if ( ! $match['blocked'] ) {
			return $result;
		}

		$this->logger->log( $match['ip'], $match['rule_type'], $this->get_request_path() );

		return new WP_Error(
			'nexiguard_blocked',
			esc_html__( 'Permission denied.', 'nexiguard-ip-geo-access-control' ),
			array( 'status' => 403 )
		);
	}

	/**
	 * Blocks XML-RPC requests when configured.
	 *
	 * @param bool $enabled Whether XML-RPC is enabled.
	 * @return bool
	 */
	public function maybe_block_xmlrpc( $enabled ) {
		$settings = $this->plugin->get_settings();

		if ( empty( $settings['block_xmlrpc'] ) ) {
			return $enabled;
		}

		$match = $this->get_block_match( 'xmlrpc' );

		if ( ! $match['blocked'] ) {
			return $enabled;
		}

		$this->logger->log( $match['ip'], $match['rule_type'], $this->get_request_path() );

		return false;
	}

	/**
	 * Determines whether the current request is blocked.
	 *
	 * @param string $context Request context.
	 * @return array{blocked:bool,ip:string,rule_type:string}
	 */
	public function get_block_match( $context = 'frontend' ) {
		$empty_match = array(
			'blocked'   => false,
			'ip'        => '',
			'rule_type' => '',
		);

		if ( $this->should_bypass( $context ) ) {
			return $empty_match;
		}

		$ip_data = $this->get_client_ip_data();
		$ip      = $ip_data['ip'];

		if ( '' === $ip ) {
			return $empty_match;
		}

		$settings  = $this->plugin->get_settings();
		$mode      = isset( $settings['access_mode'] ) ? sanitize_key( $settings['access_mode'] ) : 'blocklist';
		$rule_type = $this->get_matching_rule_type( $ip );

		if ( 'allowlist' === $mode ) {
			if ( '' === $rule_type ) {
				return array(
					'blocked'   => true,
					'ip'        => $ip,
					'rule_type' => 'allow_list_miss',
				);
			}

			return $empty_match;
		}

		if ( '' !== $rule_type ) {
			return array(
				'blocked'   => true,
				'ip'        => $ip,
				'rule_type' => $rule_type,
			);
		}

		return $empty_match;
	}

	/**
	 * Returns the detected client IP address.
	 *
	 * @return string
	 */
	public function get_client_ip() {
		$ip_data = $this->get_client_ip_data();

		return $ip_data['ip'];
	}

	/**
	 * Returns detected visitor IP and source.
	 *
	 * @return array{ip:string,source:string}
	 */
	public function get_client_ip_data() {
		$settings = $this->plugin->get_settings();

		if ( ! empty( $settings['auto_detect_cloudflare'] ) ) {
			$cloudflare_ip = $this->get_server_value( 'HTTP_CF_CONNECTING_IP' );

			if ( $this->is_valid_ip( $cloudflare_ip ) ) {
				return array(
					'ip'     => $cloudflare_ip,
					'source' => 'HTTP_CF_CONNECTING_IP',
				);
			}
		}

		if ( ! empty( $settings['trust_proxy_headers'] ) ) {
			$forwarded_for = $this->get_server_value( 'HTTP_X_FORWARDED_FOR' );

			if ( '' !== $forwarded_for ) {
				$parts = explode( ',', $forwarded_for );

				foreach ( $parts as $part ) {
					$candidate = trim( $part );

					if ( $this->is_public_ip( $candidate ) ) {
						return array(
							'ip'     => $candidate,
							'source' => 'HTTP_X_FORWARDED_FOR',
						);
					}
				}
			}

			$real_ip = $this->get_server_value( 'HTTP_X_REAL_IP' );

			if ( $this->is_public_ip( $real_ip ) ) {
				return array(
					'ip'     => $real_ip,
					'source' => 'HTTP_X_REAL_IP',
				);
			}
		}

		$remote_addr = $this->get_server_value( 'REMOTE_ADDR' );

		if ( $this->is_valid_ip( $remote_addr ) ) {
			return array(
				'ip'     => $remote_addr,
				'source' => 'REMOTE_ADDR',
			);
		}

		return array(
			'ip'     => '',
			'source' => '',
		);
	}

	/**
	 * Checks whether an IP or CIDR rule matches an IP address.
	 *
	 * @param string $rule IP or CIDR rule.
	 * @param string $ip IP address.
	 * @return bool
	 */
	public function rule_matches_ip( $rule, $ip ) {
		$rule = trim( (string) $rule );
		$ip   = trim( (string) $ip );

		if ( false === strpos( $rule, '/' ) ) {
			return $this->is_valid_ip( $rule ) && $this->normalize_ip( $rule ) === $this->normalize_ip( $ip );
		}

		return $this->cidr_contains_ip( $rule, $ip );
	}

	/**
	 * Validates an IP rule.
	 *
	 * @param string $rule IP or CIDR rule.
	 * @return bool
	 */
	public function is_valid_ip_rule( $rule ) {
		$rule = trim( (string) $rule );

		if ( false === strpos( $rule, '/' ) ) {
			return $this->is_valid_ip( $rule );
		}

		return $this->is_valid_cidr( $rule );
	}

	/**
	 * Finds a rule type matching an IP address.
	 *
	 * @param string $ip IP address.
	 * @return string
	 */
	private function get_matching_rule_type( $ip ) {
		$blocked_ips = $this->plugin->get_list_option( NexiGuard::OPTION_BLOCKED_IPS );

		foreach ( $blocked_ips as $rule ) {
			if ( $this->rule_matches_ip( $rule, $ip ) ) {
				return false !== strpos( $rule, '/' ) ? 'cidr' : 'ip';
			}
		}

		if ( ! $this->geo->has_configured_provider() ) {
			return '';
		}

		$geo_data = $this->geo->lookup( $ip );

		if ( '' !== $geo_data['country'] ) {
			$blocked_countries = $this->plugin->get_list_option( NexiGuard::OPTION_BLOCKED_COUNTRIES );

			if ( in_array( $geo_data['country'], $blocked_countries, true ) ) {
				return 'country';
			}
		}

		if ( '' !== $geo_data['region'] ) {
			$blocked_regions = $this->plugin->get_list_option( NexiGuard::OPTION_BLOCKED_REGIONS );
			$region_matches  = array( $geo_data['region'] );

			if ( '' !== $geo_data['country'] ) {
				$region_matches[] = $geo_data['country'] . '-' . $geo_data['region'];
			}

			foreach ( $region_matches as $region_match ) {
				if ( in_array( $region_match, $blocked_regions, true ) ) {
					return 'region';
				}
			}
		}

		return '';
	}

	/**
	 * Reads a server value without trusting it.
	 *
	 * @param string $key Server key.
	 * @return string
	 */
	private function get_server_value( $key ) {
		if ( ! isset( $_SERVER[ $key ] ) || ! is_scalar( $_SERVER[ $key ] ) ) {
			return '';
		}

		return sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) );
	}

	/**
	 * Checks whether this request should bypass blocking.
	 *
	 * @param string $context Request context.
	 * @return bool
	 */
	private function should_bypass( $context ) {
		$settings = $this->plugin->get_settings();

		if ( defined( 'NEXIGUARD_DISABLE' ) && NEXIGUARD_DISABLE ) {
			return true;
		}

		if ( empty( $settings['enabled'] ) ) {
			return true;
		}

		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return true;
		}

		if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
			return true;
		}

		if ( ! empty( $settings['never_block_admin'] ) && is_user_logged_in() && current_user_can( 'manage_options' ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Sends the configured blocked response and exits.
	 *
	 * @return void
	 */
	private function send_blocked_response() {
		$settings      = $this->plugin->get_settings();
		$response_type = isset( $settings['response_type'] ) ? (string) $settings['response_type'] : '403';

		nocache_headers();

		if ( '404' === $response_type ) {
			$this->send_not_found_response();
		}

		if ( 'custom' === $response_type ) {
			$message = ! empty( $settings['custom_message'] ) ? wp_kses_post( (string) $settings['custom_message'] ) : esc_html__( 'Permission denied.', 'nexiguard-ip-geo-access-control' );
			status_header( 403 );
			wp_die(
				wp_kses_post( $message ),
				esc_html__( 'Permission denied', 'nexiguard-ip-geo-access-control' ),
				array( 'response' => 403 )
			);
		}

		status_header( 403 );
		wp_die(
			esc_html__( 'Permission denied.', 'nexiguard-ip-geo-access-control' ),
			esc_html__( 'Permission denied', 'nexiguard-ip-geo-access-control' ),
			array( 'response' => 403 )
		);
	}

	/**
	 * Sends a WordPress-style 404 response.
	 *
	 * @return void
	 */
	private function send_not_found_response() {
		global $wp_query;

		status_header( 404 );

		if ( $wp_query instanceof WP_Query ) {
			$wp_query->set_404();
		}

		$template = get_404_template();

		if ( '' !== $template ) {
			include $template;
			exit;
		}

		wp_die(
			esc_html__( 'Not found.', 'nexiguard-ip-geo-access-control' ),
			esc_html__( 'Not found', 'nexiguard-ip-geo-access-control' ),
			array( 'response' => 404 )
		);
	}

	/**
	 * Gets the request path for logs.
	 *
	 * @return string
	 */
	private function get_request_path() {
		$request_uri = $this->get_server_value( 'REQUEST_URI' );
		$path        = wp_parse_url( $request_uri, PHP_URL_PATH );

		if ( ! is_string( $path ) || '' === $path ) {
			return '/';
		}

		return $path;
	}

	/**
	 * Validates an IP address.
	 *
	 * @param string $ip IP address.
	 * @return bool
	 */
	private function is_valid_ip( $ip ) {
		return false !== filter_var( $ip, FILTER_VALIDATE_IP );
	}

	/**
	 * Validates a public IP address.
	 *
	 * @param string $ip IP address.
	 * @return bool
	 */
	private function is_public_ip( $ip ) {
		return false !== filter_var(
			$ip,
			FILTER_VALIDATE_IP,
			FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
		);
	}

	/**
	 * Normalizes an IP address for exact comparisons.
	 *
	 * @param string $ip IP address.
	 * @return string
	 */
	private function normalize_ip( $ip ) {
		$packed = inet_pton( $ip );

		if ( false === $packed ) {
			return '';
		}

		return inet_ntop( $packed );
	}

	/**
	 * Validates CIDR notation.
	 *
	 * @param string $cidr CIDR rule.
	 * @return bool
	 */
	private function is_valid_cidr( $cidr ) {
		$parts = explode( '/', $cidr );

		if ( 2 !== count( $parts ) || ! $this->is_valid_ip( $parts[0] ) || ! is_numeric( $parts[1] ) ) {
			return false;
		}

		$ip       = $parts[0];
		$prefix   = absint( $parts[1] );
		$max_bits = false !== filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ? 32 : 128;

		return (string) $prefix === (string) $parts[1] && $prefix <= $max_bits;
	}

	/**
	 * Checks if a CIDR range contains an IP.
	 *
	 * @param string $cidr CIDR rule.
	 * @param string $ip IP address.
	 * @return bool
	 */
	private function cidr_contains_ip( $cidr, $ip ) {
		if ( ! $this->is_valid_cidr( $cidr ) || ! $this->is_valid_ip( $ip ) ) {
			return false;
		}

		list( $range_ip, $prefix ) = explode( '/', $cidr, 2 );
		$range_bin                 = inet_pton( $range_ip );
		$ip_bin                    = inet_pton( $ip );

		if ( false === $range_bin || false === $ip_bin || strlen( $range_bin ) !== strlen( $ip_bin ) ) {
			return false;
		}

		$prefix        = absint( $prefix );
		$full_bytes    = intdiv( $prefix, 8 );
		$partial_bits  = $prefix % 8;
		$range_network = substr( $range_bin, 0, $full_bytes );
		$ip_network    = substr( $ip_bin, 0, $full_bytes );

		if ( $range_network !== $ip_network ) {
			return false;
		}

		if ( 0 === $partial_bits ) {
			return true;
		}

		$mask = ( 0xff << ( 8 - $partial_bits ) ) & 0xff;

		return ( ord( $range_bin[ $full_bytes ] ) & $mask ) === ( ord( $ip_bin[ $full_bytes ] ) & $mask );
	}
}
