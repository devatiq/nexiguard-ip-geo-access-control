<?php
/**
 * Geolocation helper.
 *
 * @package NexiGuard
 */

defined( 'ABSPATH' ) || exit;

/**
 * Resolves country and region data when explicitly configured.
 */
class NexiGuard_Geo {

	/** @var NexiGuard */
	private $plugin;

	/**
	 * Request-local API lookup cache.
	 *
	 * @var array<string,array{country:string,region:string}>
	 */
	private $api_request_cache = array();

	/**
	 * Constructor.
	 *
	 * @param NexiGuard $plugin Plugin instance.
	 */
	public function __construct( NexiGuard $plugin ) {
		$this->plugin = $plugin;
	}

	/**
	 * Looks up geolocation data for an IP address.
	 *
	 * @param string $ip IP address.
	 * @return array{country:string,region:string}
	 */
	public function lookup( $ip ) {
		if ( ! $this->is_valid_ip( $ip ) ) {
			return $this->empty_result();
		}

		$settings = $this->plugin->get_settings();
		$provider = isset( $settings['geo_provider'] ) ? sanitize_key( $settings['geo_provider'] ) : 'none';

		if ( 'maxmind' === $provider ) {
			return $this->lookup_maxmind( $ip, $settings );
		}

		if ( 'api' === $provider ) {
			return $this->lookup_api( $ip, $settings );
		}

		return $this->empty_result();
	}

	/**
	 * Returns whether a geo provider can currently produce lookups.
	 *
	 * @return bool
	 */
	public function has_configured_provider() {
		$settings = $this->plugin->get_settings();
		$provider = isset( $settings['geo_provider'] ) ? sanitize_key( $settings['geo_provider'] ) : 'none';

		if ( 'api' === $provider ) {
			return ! empty( $settings['api_endpoint'] );
		}

		if ( 'maxmind' === $provider ) {
			$db_path = isset( $settings['maxmind_db_path'] ) ? (string) $settings['maxmind_db_path'] : '';

			return '' !== $db_path && is_readable( $db_path );
		}

		return false;
	}

	/**
	 * Looks up data using an available MaxMind reader or integration filter.
	 *
	 * @param string              $ip IP address.
	 * @param array<string,mixed> $settings Plugin settings.
	 * @return array{country:string,region:string}
	 */
	private function lookup_maxmind( $ip, $settings ) {
		$db_path = isset( $settings['maxmind_db_path'] ) ? (string) $settings['maxmind_db_path'] : '';

		if ( '' === $db_path || ! is_readable( $db_path ) ) {
			return $this->empty_result();
		}

		/**
		 * Allows a site-specific MaxMind implementation without bundling dependencies.
		 *
		 * Expected return shape: array( 'country' => 'US', 'region' => 'CA' ).
		 *
		 * @param null|array $result  Lookup result.
		 * @param string     $ip      Visitor IP.
		 * @param string     $db_path Local database path.
		 */
		$filtered = apply_filters( 'nexiguard_geo_maxmind_lookup', null, $ip, $db_path );

		if ( is_array( $filtered ) ) {
			return $this->normalize_result( $filtered );
		}

		if ( ! class_exists( '\MaxMind\Db\Reader' ) ) {
			return $this->empty_result();
		}

		try {
			$reader = new \MaxMind\Db\Reader( $db_path );
			$record = $reader->get( $ip );
			$reader->close();
		} catch ( Exception $exception ) {
			return $this->empty_result();
		}

		if ( ! is_array( $record ) ) {
			return $this->empty_result();
		}

		return $this->normalize_result(
			array(
				'country' => $this->get_nested_value( $record, array( 'country.iso_code', 'registered_country.iso_code', 'represented_country.iso_code' ) ),
				'region'  => $this->get_nested_value( $record, array( 'subdivisions.0.iso_code', 'most_specific_subdivision.iso_code' ) ),
			)
		);
	}

	/**
	 * Looks up data using a configured API endpoint.
	 *
	 * @param string              $ip IP address.
	 * @param array<string,mixed> $settings Plugin settings.
	 * @return array{country:string,region:string}
	 */
	private function lookup_api( $ip, $settings ) {
		$endpoint = isset( $settings['api_endpoint'] ) ? esc_url_raw( (string) $settings['api_endpoint'] ) : '';

		if ( '' === $endpoint ) {
			return $this->empty_result();
		}

		$cache_key = $endpoint . '|' . $ip;
		$cached    = $this->get_request_cached_api_result( $cache_key );

		if ( is_array( $cached ) ) {
			return $this->normalize_result( $cached );
		}

		$request_url = str_replace( '{ip}', rawurlencode( $ip ), $endpoint );

		if ( false === strpos( $request_url, $ip ) && false === strpos( $endpoint, '{ip}' ) ) {
			$request_url = add_query_arg( 'ip', $ip, $request_url );
		}

		$args = array(
			'timeout'     => 3,
			'redirection' => 1,
			'headers'     => array(
				'Accept' => 'application/json',
			),
		);

		if ( ! empty( $settings['api_key'] ) ) {
			$args['headers']['Authorization'] = 'Bearer ' . (string) $settings['api_key'];
		}

		$response = wp_remote_get( $request_url, $args );

		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return $this->empty_result();
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( ! is_array( $body ) ) {
			return $this->empty_result();
		}

		$country_key = ! empty( $settings['api_country_key'] ) ? (string) $settings['api_country_key'] : 'country_code';
		$region_key  = ! empty( $settings['api_region_key'] ) ? (string) $settings['api_region_key'] : 'region_code';
		$result      = $this->normalize_result(
			array(
				'country' => $this->get_nested_value( $body, array( $country_key ) ),
				'region'  => $this->get_nested_value( $body, array( $region_key ) ),
			)
		);

		$this->set_request_cached_api_result( $cache_key, $result );

		return $result;
	}

	/**
	 * Returns a cached API result for the current request only.
	 *
	 * Persistent per-IP transients are intentionally avoided here because public
	 * traffic can create an unbounded number of visitor-specific database rows.
	 *
	 * @param string $cache_key Request cache key.
	 * @return null|array{country:string,region:string}
	 */
	private function get_request_cached_api_result( $cache_key ) {
		if ( isset( $this->api_request_cache[ $cache_key ] ) && is_array( $this->api_request_cache[ $cache_key ] ) ) {
			return $this->api_request_cache[ $cache_key ];
		}

		return null;
	}

	/**
	 * Stores an API result for reuse during the current request only.
	 *
	 * @param string              $cache_key Request cache key.
	 * @param array<string,mixed> $result    Lookup result.
	 * @return void
	 */
	private function set_request_cached_api_result( $cache_key, $result ) {
		$this->api_request_cache[ $cache_key ] = $this->normalize_result( $result );
	}

	/**
	 * Returns a nested array value from dot-notated paths.
	 *
	 * @param array<string,mixed> $data Data.
	 * @param array<int,string>   $paths Dot-notated paths.
	 * @return string
	 */
	private function get_nested_value( $data, $paths ) {
		foreach ( $paths as $path ) {
			$current = $data;
			$parts   = explode( '.', $path );

			foreach ( $parts as $part ) {
				if ( is_array( $current ) && array_key_exists( $part, $current ) ) {
					$current = $current[ $part ];
					continue;
				}

				$current = null;
				break;
			}

			if ( is_scalar( $current ) && '' !== (string) $current ) {
				return (string) $current;
			}
		}

		return '';
	}

	/**
	 * Normalizes a lookup result.
	 *
	 * @param array<string,mixed> $result Raw result.
	 * @return array{country:string,region:string}
	 */
	private function normalize_result( $result ) {
		$country = isset( $result['country'] ) ? strtoupper( sanitize_text_field( (string) $result['country'] ) ) : '';
		$region  = isset( $result['region'] ) ? strtoupper( sanitize_text_field( (string) $result['region'] ) ) : '';
		$country = preg_replace( '/[^A-Z]/', '', $country );
		$region  = preg_replace( '/[^A-Z0-9_-]/', '', $region );

		return array(
			'country' => is_string( $country ) ? $country : '',
			'region'  => is_string( $region ) ? $region : '',
		);
	}

	/**
	 * Returns an empty lookup result.
	 *
	 * @return array{country:string,region:string}
	 */
	private function empty_result() {
		return array(
			'country' => '',
			'region'  => '',
		);
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
}
