<?php
/**
 * Uninstall cleanup for NexiGuard.
 *
 * @package NexiGuard
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

$nexiguard_settings = get_option( 'nexiguard_settings', array() );

if ( is_array( $nexiguard_settings ) && ! empty( $nexiguard_settings['delete_data_on_uninstall'] ) ) {
	delete_option( 'nexiguard_settings' );
	delete_option( 'nexiguard_blocked_ips' );
	delete_option( 'nexiguard_blocked_countries' );
	delete_option( 'nexiguard_blocked_regions' );
	delete_option( 'nexiguard_logs' );
}
