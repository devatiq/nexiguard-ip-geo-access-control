<?php
/**
 * Main plugin class.
 *
 * @package NexiGuard
 */

defined( 'ABSPATH' ) || exit;

/**
 * Coordinates plugin services and shared option access.
 */
class NexiGuard {

	const OPTION_SETTINGS          = 'nexiguard_settings';
	const OPTION_BLOCKED_IPS       = 'nexiguard_blocked_ips';
	const OPTION_BLOCKED_COUNTRIES = 'nexiguard_blocked_countries';
	const OPTION_BLOCKED_REGIONS   = 'nexiguard_blocked_regions';
	const OPTION_LOGS              = 'nexiguard_logs';

	/**
	 * Singleton instance.
	 *
	 * @var NexiGuard|null
	 */
	private static $instance = null;

	/** @var NexiGuard_Geo */
	private $geo;

	/** @var NexiGuard_Logger */
	private $logger;

	/** @var NexiGuard_Blocker */
	private $blocker;

	/** @var NexiGuard_Admin|null */
	private $admin = null;

	/**
	 * Returns the singleton instance.
	 *
	 * @return NexiGuard
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	/**
	 * Creates plugin services.
	 */
	private function __construct() {
		$this->includes();

		$this->geo     = new NexiGuard_Geo( $this );
		$this->logger  = new NexiGuard_Logger( $this );
		$this->blocker = new NexiGuard_Blocker( $this, $this->geo, $this->logger );

		if ( is_admin() ) {
			$this->admin = new NexiGuard_Admin( $this, $this->blocker, $this->geo, $this->logger );
		}
	}

	/**
	 * Loads class files.
	 *
	 * @return void
	 */
	private function includes() {
		require_once NEXIGUARD_PATH . 'includes/class-nexiguard-geo.php';
		require_once NEXIGUARD_PATH . 'includes/class-nexiguard-logger.php';
		require_once NEXIGUARD_PATH . 'includes/class-nexiguard-blocker.php';
		require_once NEXIGUARD_PATH . 'includes/class-nexiguard-admin.php';
	}

	/**
	 * Sets safe defaults on activation.
	 *
	 * @return void
	 */
	public static function activate() {
		$settings = get_option( self::OPTION_SETTINGS );

		if ( ! is_array( $settings ) ) {
			add_option( self::OPTION_SETTINGS, self::default_settings(), '', false );
		} else {
			update_option( self::OPTION_SETTINGS, wp_parse_args( $settings, self::default_settings() ), false );
		}

		foreach ( array( self::OPTION_BLOCKED_IPS, self::OPTION_BLOCKED_COUNTRIES, self::OPTION_BLOCKED_REGIONS, self::OPTION_LOGS ) as $option_name ) {
			if ( false === get_option( $option_name, false ) ) {
				add_option( $option_name, array(), '', false );
			}
		}
	}

	/**
	 * Deactivation keeps settings in place.
	 *
	 * @return void
	 */
	public static function deactivate() {
		// Intentionally empty. Site owners may reactivate with existing rules intact.
	}

	/**
	 * Returns default settings.
	 *
	 * @return array<string,mixed>
	 */
	public static function default_settings() {
		return array(
			'enabled'                   => 0,
			'access_mode'               => 'blocklist',
			'response_type'             => '403',
			'custom_message'            => 'Permission denied.',
			'block_frontend'            => 1,
			'block_login'               => 0,
			'block_rest'                => 0,
			'block_xmlrpc'              => 0,
			'never_block_admin'         => 1,
			'auto_detect_cloudflare'    => 0,
			'trust_proxy_headers'       => 0,
			'geo_provider'              => 'none',
			'api_key'                   => '',
			'api_endpoint'              => '',
			'api_country_key'           => 'country_code',
			'api_region_key'            => 'region_code',
			'maxmind_db_path'           => '',
			'logging_enabled'           => 0,
			'log_limit'                 => 200,
			'delete_data_on_uninstall'  => 0,
		);
	}

	/**
	 * Gets merged plugin settings.
	 *
	 * @return array<string,mixed>
	 */
	public function get_settings() {
		$settings = get_option( self::OPTION_SETTINGS, array() );

		if ( ! is_array( $settings ) ) {
			$settings = array();
		}

		return wp_parse_args( $settings, self::default_settings() );
	}

	/**
	 * Updates plugin settings.
	 *
	 * @param array<string,mixed> $settings Sanitized settings.
	 * @return bool
	 */
	public function update_settings( $settings ) {
		$settings = wp_parse_args( $settings, self::default_settings() );

		return update_option( self::OPTION_SETTINGS, $settings, false );
	}

	/**
	 * Reads a string list option.
	 *
	 * @param string $option_name Option name.
	 * @return array<int,string>
	 */
	public function get_list_option( $option_name ) {
		$items = get_option( $option_name, array() );

		if ( ! is_array( $items ) ) {
			return array();
		}

		$items = array_map( 'sanitize_text_field', wp_unslash( $items ) );
		$items = array_values( array_unique( array_filter( $items ) ) );

		return $items;
	}

	/**
	 * Stores a string list option.
	 *
	 * @param string            $option_name Option name.
	 * @param array<int,string> $items Items.
	 * @return bool
	 */
	public function update_list_option( $option_name, $items ) {
		$items = array_map( 'sanitize_text_field', wp_unslash( $items ) );
		$items = array_values( array_unique( array_filter( $items ) ) );

		return update_option( $option_name, $items, false );
	}

	/**
	 * Returns plugin URL for an asset.
	 *
	 * @param string $path Relative path.
	 * @return string
	 */
	public function asset_url( $path ) {
		return NEXIGUARD_URL . ltrim( $path, '/' );
	}

	/** @return NexiGuard_Blocker */
	public function blocker() {
		return $this->blocker;
	}

	/** @return NexiGuard_Geo */
	public function geo() {
		return $this->geo;
	}

	/** @return NexiGuard_Logger */
	public function logger() {
		return $this->logger;
	}
}
