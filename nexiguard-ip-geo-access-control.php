<?php
/**
 * Plugin Name: NexiGuard – IP & Geo Access Control
 * Plugin URI: https://nexiby.com
 * Description: Restrict website access by IP address, CIDR ranges, countries, and regions.
 * Version: 1.0.0
 * Requires at least: 6.0
 * Requires PHP: 7.4
 * Author: Nexiby LLC
 * Author URI: https://nexiby.com
 * Text Domain: nexiguard-ip-geo-access-control
 * Domain Path: /languages
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 *
 * @package NexiGuard
 */

defined( 'ABSPATH' ) || exit;

define( 'NEXIGUARD_VERSION', '1.0.0' );
define( 'NEXIGUARD_FILE', __FILE__ );
define( 'NEXIGUARD_PATH', plugin_dir_path( __FILE__ ) );
define( 'NEXIGUARD_URL', plugin_dir_url( __FILE__ ) );

require_once NEXIGUARD_PATH . 'includes/class-nexiguard.php';

register_activation_hook( __FILE__, array( 'NexiGuard', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'NexiGuard', 'deactivate' ) );

/**
 * Returns the plugin singleton.
 *
 * @return NexiGuard
 */
function nexiguard() {
	return NexiGuard::instance();
}

nexiguard();
