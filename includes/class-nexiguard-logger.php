<?php
/**
 * Blocked-attempt logging.
 *
 * @package NexiGuard
 */

defined( 'ABSPATH' ) || exit;

/**
 * Stores minimal blocked-attempt logs when enabled.
 */
class NexiGuard_Logger {

	/** @var NexiGuard */
	private $plugin;

	/**
	 * Constructor.
	 *
	 * @param NexiGuard $plugin Plugin instance.
	 */
	public function __construct( NexiGuard $plugin ) {
		$this->plugin = $plugin;
	}

	/**
	 * Logs a blocked attempt when logging is enabled.
	 *
	 * @param string $ip IP address.
	 * @param string $rule_type Matched rule type.
	 * @param string $path Requested path.
	 * @return void
	 */
	public function log( $ip, $rule_type, $path ) {
		$settings = $this->plugin->get_settings();

		if ( empty( $settings['logging_enabled'] ) ) {
			return;
		}

		$logs   = $this->get_logs();
		$logs[] = array(
			'datetime'  => current_time( 'mysql', true ),
			'ip'        => sanitize_text_field( $ip ),
			'rule_type' => sanitize_key( $rule_type ),
			'path'      => sanitize_text_field( $path ),
		);

		$limit = isset( $settings['log_limit'] ) ? absint( $settings['log_limit'] ) : 200;
		$limit = max( 1, min( 1000, $limit ) );

		if ( count( $logs ) > $limit ) {
			$logs = array_slice( $logs, -1 * $limit );
		}

		update_option( NexiGuard::OPTION_LOGS, $logs, false );
	}

	/**
	 * Gets stored logs.
	 *
	 * @return array<int,array<string,string>>
	 */
	public function get_logs() {
		$logs = get_option( NexiGuard::OPTION_LOGS, array() );

		if ( ! is_array( $logs ) ) {
			return array();
		}

		return $logs;
	}

	/**
	 * Clears stored logs.
	 *
	 * @return bool
	 */
	public function clear_logs() {
		return update_option( NexiGuard::OPTION_LOGS, array(), false );
	}
}
