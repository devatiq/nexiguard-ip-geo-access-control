<?php
/**
 * Admin UI and form handlers.
 *
 * @package NexiGuard
 */

defined( 'ABSPATH' ) || exit;

/**
 * Builds the NexiGuard admin area.
 */
class NexiGuard_Admin {

	const MENU_SLUG = 'nexiguard-ip-geo-access-control';

	/** @var NexiGuard */
	private $plugin;

	/** @var NexiGuard_Blocker */
	private $blocker;

	/** @var NexiGuard_Geo */
	private $geo;

	/** @var NexiGuard_Logger */
	private $logger;

	/** @var string */
	private $page_hook = '';

	/**
	 * Constructor.
	 *
	 * @param NexiGuard         $plugin Plugin instance.
	 * @param NexiGuard_Blocker $blocker Blocker service.
	 * @param NexiGuard_Geo     $geo Geo service.
	 * @param NexiGuard_Logger  $logger Logger service.
	 */
	public function __construct( NexiGuard $plugin, NexiGuard_Blocker $blocker, NexiGuard_Geo $geo, NexiGuard_Logger $logger ) {
		$this->plugin  = $plugin;
		$this->blocker = $blocker;
		$this->geo     = $geo;
		$this->logger  = $logger;

		add_action( 'admin_menu', array( $this, 'add_menu' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
		add_action( 'admin_notices', array( $this, 'render_notices' ) );

		add_action( 'admin_post_nexiguard_add_ip', array( $this, 'handle_add_ip' ) );
		add_action( 'admin_post_nexiguard_bulk_import_ips', array( $this, 'handle_bulk_import_ips' ) );
		add_action( 'admin_post_nexiguard_remove_ip', array( $this, 'handle_remove_ip' ) );
		add_action( 'admin_post_nexiguard_add_country', array( $this, 'handle_add_country' ) );
		add_action( 'admin_post_nexiguard_remove_country', array( $this, 'handle_remove_country' ) );
		add_action( 'admin_post_nexiguard_add_region', array( $this, 'handle_add_region' ) );
		add_action( 'admin_post_nexiguard_remove_region', array( $this, 'handle_remove_region' ) );
		add_action( 'admin_post_nexiguard_clear_logs', array( $this, 'handle_clear_logs' ) );
		add_action( 'admin_post_nexiguard_export_settings', array( $this, 'handle_export_settings' ) );
		add_action( 'admin_post_nexiguard_import_settings', array( $this, 'handle_import_settings' ) );
	}

	/**
	 * Adds the top-level admin menu.
	 *
	 * @return void
	 */
	public function add_menu() {
		$this->page_hook = add_menu_page(
			esc_html__( 'NexiGuard – IP & Geo Access Control', 'nexiguard-ip-geo-access-control' ),
			esc_html__( 'NexiGuard', 'nexiguard-ip-geo-access-control' ),
			'manage_options',
			self::MENU_SLUG,
			array( $this, 'render_page' ),
			'dashicons-shield-alt',
			81
		);
	}

	/**
	 * Registers Settings API entries.
	 *
	 * @return void
	 */
	public function register_settings() {
		register_setting(
			'nexiguard_settings_group',
			NexiGuard::OPTION_SETTINGS,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize_settings' ),
				'default'           => NexiGuard::default_settings(),
			)
		);
	}

	/**
	 * Enqueues admin assets only on this plugin page.
	 *
	 * @param string $hook_suffix Current admin page hook.
	 * @return void
	 */
	public function enqueue_assets( $hook_suffix ) {
		if ( $hook_suffix !== $this->page_hook ) {
			return;
		}

		wp_enqueue_style(
			'nexiguard_admin',
			$this->plugin->asset_url( 'assets/admin.css' ),
			array(),
			NEXIGUARD_VERSION
		);
		wp_enqueue_script(
			'nexiguard_admin',
			$this->plugin->asset_url( 'assets/admin.js' ),
			array(),
			NEXIGUARD_VERSION,
			true
		);
	}

	/**
	 * Sanitizes general settings from Settings API.
	 *
	 * @param mixed $input Raw settings input.
	 * @return array<string,mixed>
	 */
	public function sanitize_settings( $input ) {
		$settings = $this->sanitize_settings_array( $input );

		if ( empty( $settings['block_frontend'] ) && empty( $settings['block_login'] ) && empty( $settings['block_rest'] ) && empty( $settings['block_xmlrpc'] ) ) {
			$settings['enabled'] = 0;
			add_settings_error(
				'nexiguard_messages',
				'nexiguard_no_context',
				esc_html__( 'The plugin was disabled because no blocking context was selected.', 'nexiguard-ip-geo-access-control' ),
				'warning'
			);
		}

		add_settings_error(
			'nexiguard_messages',
			'nexiguard_settings_saved',
			esc_html__( 'Settings saved.', 'nexiguard-ip-geo-access-control' ),
			'updated'
		);

		return $settings;
	}

	/**
	 * Sanitizes a settings array without requiring it to come from Settings API.
	 *
	 * @param mixed $input Raw settings input.
	 * @return array<string,mixed>
	 */
	private function sanitize_settings_array( $input ) {
		$defaults = NexiGuard::default_settings();

		if ( ! is_array( $input ) ) {
			return $defaults;
		}

		$input         = wp_unslash( $input );
		$response_type = isset( $input['response_type'] ) ? sanitize_key( $input['response_type'] ) : $defaults['response_type'];
		$access_mode   = isset( $input['access_mode'] ) ? sanitize_key( $input['access_mode'] ) : $defaults['access_mode'];
		$geo_provider  = isset( $input['geo_provider'] ) ? sanitize_key( $input['geo_provider'] ) : $defaults['geo_provider'];
		$log_limit     = isset( $input['log_limit'] ) ? absint( $input['log_limit'] ) : $defaults['log_limit'];

		if ( ! in_array( $response_type, array( '403', '404', 'custom' ), true ) ) {
			$response_type = '403';
		}

		if ( ! in_array( $access_mode, array( 'blocklist', 'allowlist' ), true ) ) {
			$access_mode = 'blocklist';
		}

		if ( ! in_array( $geo_provider, array( 'none', 'maxmind', 'api' ), true ) ) {
			$geo_provider = 'none';
		}

		return array(
			'enabled'                  => empty( $input['enabled'] ) ? 0 : 1,
			'access_mode'              => $access_mode,
			'response_type'            => $response_type,
			'custom_message'           => isset( $input['custom_message'] ) ? wp_kses_post( $input['custom_message'] ) : $defaults['custom_message'],
			'block_frontend'           => empty( $input['block_frontend'] ) ? 0 : 1,
			'block_login'              => empty( $input['block_login'] ) ? 0 : 1,
			'block_rest'               => empty( $input['block_rest'] ) ? 0 : 1,
			'block_xmlrpc'             => empty( $input['block_xmlrpc'] ) ? 0 : 1,
			'never_block_admin'        => empty( $input['never_block_admin'] ) ? 0 : 1,
			'auto_detect_cloudflare'   => empty( $input['auto_detect_cloudflare'] ) ? 0 : 1,
			'trust_proxy_headers'      => empty( $input['trust_proxy_headers'] ) ? 0 : 1,
			'geo_provider'             => $geo_provider,
			'api_key'                  => isset( $input['api_key'] ) ? sanitize_text_field( $input['api_key'] ) : '',
			'api_endpoint'             => isset( $input['api_endpoint'] ) ? esc_url_raw( $input['api_endpoint'] ) : '',
			'api_country_key'          => isset( $input['api_country_key'] ) ? $this->sanitize_dot_key( $input['api_country_key'], 'country_code' ) : 'country_code',
			'api_region_key'           => isset( $input['api_region_key'] ) ? $this->sanitize_dot_key( $input['api_region_key'], 'region_code' ) : 'region_code',
			'maxmind_db_path'          => isset( $input['maxmind_db_path'] ) ? sanitize_text_field( $input['maxmind_db_path'] ) : '',
			'logging_enabled'          => empty( $input['logging_enabled'] ) ? 0 : 1,
			'log_limit'                => max( 1, min( 1000, $log_limit ) ),
			'delete_data_on_uninstall' => empty( $input['delete_data_on_uninstall'] ) ? 0 : 1,
		);
	}

	/**
	 * Renders the settings page.
	 *
	 * @return void
	 */
	public function render_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'nexiguard-ip-geo-access-control' ) );
		}

		$active_tab = $this->get_active_tab();

		?>
		<div class="wrap nexiguard-wrap">
			<h1><?php echo esc_html__( 'NexiGuard – IP & Geo Access Control', 'nexiguard-ip-geo-access-control' ); ?></h1>
			<p class="description">
				<?php echo esc_html__( 'Control public access by IP address, CIDR range, country, or region with safe defaults and optional logging.', 'nexiguard-ip-geo-access-control' ); ?>
			</p>

			<?php settings_errors( 'nexiguard_messages' ); ?>
			<?php $this->render_geo_notice(); ?>

			<nav class="nav-tab-wrapper nexiguard-tabs" aria-label="<?php echo esc_attr__( 'NexiGuard tabs', 'nexiguard-ip-geo-access-control' ); ?>">
				<?php foreach ( $this->get_tabs() as $tab => $label ) : ?>
					<a class="<?php echo esc_attr( 'nav-tab ' . ( $active_tab === $tab ? 'nav-tab-active' : '' ) ); ?>" href="<?php echo esc_url( $this->get_tab_url( $tab ) ); ?>">
						<?php echo esc_html( $label ); ?>
					</a>
				<?php endforeach; ?>
			</nav>

			<div class="nexiguard-panel">
				<?php
				if ( 'ip' === $active_tab ) {
					$this->render_ip_tab();
				} elseif ( 'geo' === $active_tab ) {
					$this->render_geo_tab();
				} elseif ( 'logs' === $active_tab ) {
					$this->render_logs_tab();
				} else {
					$this->render_general_tab();
				}
				?>
			</div>
		</div>
		<?php
	}

	/**
	 * Renders custom admin notices.
	 *
	 * @return void
	 */
	public function render_notices() {
		if ( ! $this->is_plugin_page() || ! current_user_can( 'manage_options' ) ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nonce value is sanitized and verified immediately below.
		$notice_nonce = isset( $_GET['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ) ) : '';

		if ( '' === $notice_nonce || ! wp_verify_nonce( $notice_nonce, 'nexiguard_notice' ) ) {
			return;
		}

		$code = isset( $_GET['nexiguard_notice'] ) ? sanitize_key( wp_unslash( $_GET['nexiguard_notice'] ) ) : '';

		if ( '' === $code ) {
			return;
		}

		$type     = isset( $_GET['nexiguard_notice_type'] ) ? sanitize_key( wp_unslash( $_GET['nexiguard_notice_type'] ) ) : 'success';
		$type     = in_array( $type, array( 'success', 'error', 'warning', 'info' ), true ) ? $type : 'success';
		$messages = array(
			'ip_added'         => __( 'IP rule added.', 'nexiguard-ip-geo-access-control' ),
			'ip_removed'       => __( 'IP rule removed.', 'nexiguard-ip-geo-access-control' ),
			'invalid_ip'       => __( 'Please enter a valid IP address or CIDR range.', 'nexiguard-ip-geo-access-control' ),
			'duplicate_ip'     => __( 'That IP rule already exists.', 'nexiguard-ip-geo-access-control' ),
			'current_ip'       => __( 'This rule matches your current IP address. Confirm the lockout warning before adding it.', 'nexiguard-ip-geo-access-control' ),
			'bulk_imported'    => __( 'Bulk import completed.', 'nexiguard-ip-geo-access-control' ),
			'country_added'    => __( 'Country rule added.', 'nexiguard-ip-geo-access-control' ),
			'country_removed'  => __( 'Country rule removed.', 'nexiguard-ip-geo-access-control' ),
			'invalid_country'  => __( 'Please enter or select a valid two-letter country code.', 'nexiguard-ip-geo-access-control' ),
			'region_added'     => __( 'Region rule added.', 'nexiguard-ip-geo-access-control' ),
			'region_removed'   => __( 'Region rule removed.', 'nexiguard-ip-geo-access-control' ),
			'invalid_region'   => __( 'Please enter a valid region code.', 'nexiguard-ip-geo-access-control' ),
			'duplicate_rule'   => __( 'That rule already exists.', 'nexiguard-ip-geo-access-control' ),
			'logs_cleared'     => __( 'Logs cleared.', 'nexiguard-ip-geo-access-control' ),
			'imported'         => __( 'Settings imported successfully.', 'nexiguard-ip-geo-access-control' ),
			'import_failed'    => __( 'Import failed. No settings were changed.', 'nexiguard-ip-geo-access-control' ),
		);

		if ( empty( $messages[ $code ] ) ) {
			return;
		}

		printf(
			'<div class="notice notice-%1$s is-dismissible"><p>%2$s</p>%3$s</div>',
			esc_attr( $type ),
			esc_html( $messages[ $code ] ),
			wp_kses_post( $this->get_notice_details() )
		);
	}

	/**
	 * Handles adding an IP or CIDR rule.
	 *
	 * @return void
	 */
	public function handle_add_ip() {
		check_admin_referer( 'nexiguard_add_ip' );
		$this->verify_capability();

		$rule = isset( $_POST['nexiguard_ip_rule'] ) ? sanitize_text_field( wp_unslash( $_POST['nexiguard_ip_rule'] ) ) : '';
		$rule = trim( $rule );

		if ( ! $this->blocker->is_valid_ip_rule( $rule ) ) {
			$this->redirect_with_notice( 'ip', 'invalid_ip', 'error' );
		}

		$current_ip = $this->blocker->get_client_ip();
		$confirmed  = isset( $_POST['nexiguard_confirm_current_ip'] )
			&& '1' === sanitize_text_field( wp_unslash( $_POST['nexiguard_confirm_current_ip'] ) );

		if ( '' !== $current_ip && $this->blocker->rule_matches_ip( $rule, $current_ip ) && ! $confirmed ) {
			$this->redirect_with_notice( 'ip', 'current_ip', 'error' );
		}

		$rules = $this->plugin->get_list_option( NexiGuard::OPTION_BLOCKED_IPS );

		if ( in_array( $rule, $rules, true ) ) {
			$this->redirect_with_notice( 'ip', 'duplicate_ip', 'warning' );
		}

		$rules[] = $rule;
		$this->plugin->update_list_option( NexiGuard::OPTION_BLOCKED_IPS, $rules );
		$this->redirect_with_notice( 'ip', 'ip_added', 'success' );
	}

	/**
	 * Handles bulk importing IP or CIDR rules.
	 *
	 * @return void
	 */
	public function handle_bulk_import_ips() {
		check_admin_referer( 'nexiguard_bulk_import_ips' );
		$this->verify_capability();

		$raw     = isset( $_POST['nexiguard_bulk_ip_rules'] ) ? sanitize_textarea_field( wp_unslash( $_POST['nexiguard_bulk_ip_rules'] ) ) : '';
		$lines   = preg_split( '/\r\n|\r|\n/', $raw );
		$rules   = $this->plugin->get_list_option( NexiGuard::OPTION_BLOCKED_IPS );
		$invalid = array();
		$added   = 0;

		if ( ! is_array( $lines ) ) {
			$lines = array();
		}

		foreach ( $lines as $line ) {
			$rule = trim( sanitize_text_field( $line ) );

			if ( '' === $rule ) {
				continue;
			}

			if ( ! $this->blocker->is_valid_ip_rule( $rule ) ) {
				$invalid[] = $rule;
				continue;
			}

			if ( ! in_array( $rule, $rules, true ) ) {
				$rules[] = $rule;
				++$added;
			}
		}

		$this->plugin->update_list_option( NexiGuard::OPTION_BLOCKED_IPS, $rules );
		$this->set_notice_details(
			array(
				'added'   => $added,
				'invalid' => $invalid,
			)
		);
		$this->redirect_with_notice( 'ip', 'bulk_imported', empty( $invalid ) ? 'success' : 'warning' );
	}

	/**
	 * Handles removing an IP or CIDR rule.
	 *
	 * @return void
	 */
	public function handle_remove_ip() {
		check_admin_referer( 'nexiguard_remove_ip' );
		$this->verify_capability();

		$rule  = isset( $_POST['nexiguard_ip_rule'] ) ? sanitize_text_field( wp_unslash( $_POST['nexiguard_ip_rule'] ) ) : '';
		$rules = $this->plugin->get_list_option( NexiGuard::OPTION_BLOCKED_IPS );
		$rules = array_values(
			array_filter(
				$rules,
				static function ( $item ) use ( $rule ) {
					return $item !== $rule;
				}
			)
		);

		$this->plugin->update_list_option( NexiGuard::OPTION_BLOCKED_IPS, $rules );
		$this->redirect_with_notice( 'ip', 'ip_removed', 'success' );
	}

	/**
	 * Handles adding a country rule.
	 *
	 * @return void
	 */
	public function handle_add_country() {
		check_admin_referer( 'nexiguard_add_country' );
		$this->verify_capability();

		$manual  = isset( $_POST['nexiguard_country_manual'] ) ? strtoupper( sanitize_text_field( wp_unslash( $_POST['nexiguard_country_manual'] ) ) ) : '';
		$select  = isset( $_POST['nexiguard_country_select'] ) ? strtoupper( sanitize_text_field( wp_unslash( $_POST['nexiguard_country_select'] ) ) ) : '';
		$country = '' !== trim( $manual ) ? $manual : $select;
		$country = preg_replace( '/[^A-Z]/', '', $country );
		$country = is_string( $country ) ? $country : '';

		if ( 2 !== strlen( $country ) || ! array_key_exists( $country, $this->get_country_choices() ) ) {
			$this->redirect_with_notice( 'geo', 'invalid_country', 'error' );
		}

		$countries = $this->plugin->get_list_option( NexiGuard::OPTION_BLOCKED_COUNTRIES );

		if ( in_array( $country, $countries, true ) ) {
			$this->redirect_with_notice( 'geo', 'duplicate_rule', 'warning' );
		}

		$countries[] = $country;
		$this->plugin->update_list_option( NexiGuard::OPTION_BLOCKED_COUNTRIES, $countries );
		$this->redirect_with_notice( 'geo', 'country_added', 'success' );
	}

	/**
	 * Handles removing a country rule.
	 *
	 * @return void
	 */
	public function handle_remove_country() {
		check_admin_referer( 'nexiguard_remove_country' );
		$this->verify_capability();

		$country   = isset( $_POST['nexiguard_country'] ) ? strtoupper( sanitize_text_field( wp_unslash( $_POST['nexiguard_country'] ) ) ) : '';
		$countries = $this->plugin->get_list_option( NexiGuard::OPTION_BLOCKED_COUNTRIES );
		$countries = array_values(
			array_filter(
				$countries,
				static function ( $item ) use ( $country ) {
					return $item !== $country;
				}
			)
		);

		$this->plugin->update_list_option( NexiGuard::OPTION_BLOCKED_COUNTRIES, $countries );
		$this->redirect_with_notice( 'geo', 'country_removed', 'success' );
	}

	/**
	 * Handles adding a region rule.
	 *
	 * @return void
	 */
	public function handle_add_region() {
		check_admin_referer( 'nexiguard_add_region' );
		$this->verify_capability();

		$region = isset( $_POST['nexiguard_region'] ) ? strtoupper( sanitize_text_field( wp_unslash( $_POST['nexiguard_region'] ) ) ) : '';
		$region = preg_replace( '/[^A-Z0-9_-]/', '', $region );
		$region = is_string( $region ) ? $region : '';

		if ( '' === $region || strlen( $region ) > 24 ) {
			$this->redirect_with_notice( 'geo', 'invalid_region', 'error' );
		}

		$regions = $this->plugin->get_list_option( NexiGuard::OPTION_BLOCKED_REGIONS );

		if ( in_array( $region, $regions, true ) ) {
			$this->redirect_with_notice( 'geo', 'duplicate_rule', 'warning' );
		}

		$regions[] = $region;
		$this->plugin->update_list_option( NexiGuard::OPTION_BLOCKED_REGIONS, $regions );
		$this->redirect_with_notice( 'geo', 'region_added', 'success' );
	}

	/**
	 * Handles removing a region rule.
	 *
	 * @return void
	 */
	public function handle_remove_region() {
		check_admin_referer( 'nexiguard_remove_region' );
		$this->verify_capability();

		$region  = isset( $_POST['nexiguard_region'] ) ? strtoupper( sanitize_text_field( wp_unslash( $_POST['nexiguard_region'] ) ) ) : '';
		$regions = $this->plugin->get_list_option( NexiGuard::OPTION_BLOCKED_REGIONS );
		$regions = array_values(
			array_filter(
				$regions,
				static function ( $item ) use ( $region ) {
					return $item !== $region;
				}
			)
		);

		$this->plugin->update_list_option( NexiGuard::OPTION_BLOCKED_REGIONS, $regions );
		$this->redirect_with_notice( 'geo', 'region_removed', 'success' );
	}

	/**
	 * Handles clearing logs.
	 *
	 * @return void
	 */
	public function handle_clear_logs() {
		check_admin_referer( 'nexiguard_clear_logs' );
		$this->verify_capability();
		$this->logger->clear_logs();
		$this->redirect_with_notice( 'logs', 'logs_cleared', 'success' );
	}

	/**
	 * Exports settings and rules as JSON.
	 *
	 * @return void
	 */
	public function handle_export_settings() {
		check_admin_referer( 'nexiguard_export_settings' );
		$this->verify_capability();

		$data = array(
			'plugin'            => 'nexiguard-ip-geo-access-control',
			'version'           => NEXIGUARD_VERSION,
			'settings'          => $this->plugin->get_settings(),
			'blocked_ips'       => $this->plugin->get_list_option( NexiGuard::OPTION_BLOCKED_IPS ),
			'blocked_countries' => $this->plugin->get_list_option( NexiGuard::OPTION_BLOCKED_COUNTRIES ),
			'blocked_regions'   => $this->plugin->get_list_option( NexiGuard::OPTION_BLOCKED_REGIONS ),
		);

		nocache_headers();
		header( 'Content-Type: application/json; charset=' . get_option( 'blog_charset' ) );
		header( 'Content-Disposition: attachment; filename=nexiguard-settings.json' );
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- JSON is generated from sanitized options for a download response.
		echo wp_json_encode( $data, JSON_PRETTY_PRINT );
		exit;
	}

	/**
	 * Imports settings and rules from JSON.
	 *
	 * @return void
	 */
	public function handle_import_settings() {
		check_admin_referer( 'nexiguard_import_settings' );
		$this->verify_capability();

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- JSON is decoded and supported values are sanitized before saving.
		$raw_json = isset( $_POST['nexiguard_import_json'] ) ? wp_unslash( $_POST['nexiguard_import_json'] ) : '';

		if ( ! is_string( $raw_json ) || '' === trim( $raw_json ) ) {
			$this->set_notice_details( array( 'errors' => array( __( 'Import JSON is empty.', 'nexiguard-ip-geo-access-control' ) ) ) );
			$this->redirect_with_notice( 'general', 'import_failed', 'error' );
		}

		$data = json_decode( $raw_json, true );

		if ( ! is_array( $data ) ) {
			$this->set_notice_details( array( 'errors' => array( __( 'Import JSON could not be decoded.', 'nexiguard-ip-geo-access-control' ) ) ) );
			$this->redirect_with_notice( 'general', 'import_failed', 'error' );
		}

		$validated = $this->validate_import_data( $data );

		if ( ! empty( $validated['errors'] ) ) {
			$this->set_notice_details( array( 'errors' => $validated['errors'] ) );
			$this->redirect_with_notice( 'general', 'import_failed', 'error' );
		}

		$this->plugin->update_settings( $validated['settings'] );
		$this->plugin->update_list_option( NexiGuard::OPTION_BLOCKED_IPS, $validated['blocked_ips'] );
		$this->plugin->update_list_option( NexiGuard::OPTION_BLOCKED_COUNTRIES, $validated['blocked_countries'] );
		$this->plugin->update_list_option( NexiGuard::OPTION_BLOCKED_REGIONS, $validated['blocked_regions'] );
		$this->redirect_with_notice( 'general', 'imported', 'success' );
	}

	/**
	 * Renders the general settings tab.
	 *
	 * @return void
	 */
	private function render_general_tab() {
		$settings = $this->plugin->get_settings();
		$ip_data  = $this->blocker->get_client_ip_data();

		?>
		<form method="post" action="options.php" class="nexiguard-card">
			<?php settings_fields( 'nexiguard_settings_group' ); ?>

			<h2><?php echo esc_html__( 'General Settings', 'nexiguard-ip-geo-access-control' ); ?></h2>
			<table class="form-table" role="presentation">
				<tbody>
					<tr>
						<th scope="row"><?php echo esc_html__( 'Enable protection', 'nexiguard-ip-geo-access-control' ); ?></th>
						<td>
							<label><input type="checkbox" name="<?php echo esc_attr( NexiGuard::OPTION_SETTINGS ); ?>[enabled]" value="1" <?php checked( 1, (int) $settings['enabled'] ); ?> /> <?php echo esc_html__( 'Enable NexiGuard blocking rules.', 'nexiguard-ip-geo-access-control' ); ?></label>
							<p class="description"><?php echo esc_html__( 'Safe default: disabled after activation.', 'nexiguard-ip-geo-access-control' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php echo esc_html__( 'Access Mode', 'nexiguard-ip-geo-access-control' ); ?></th>
						<td>
							<select name="<?php echo esc_attr( NexiGuard::OPTION_SETTINGS ); ?>[access_mode]">
								<option value="blocklist" <?php selected( 'blocklist', $settings['access_mode'] ); ?>><?php echo esc_html__( 'Block List: visitors matching rules are blocked', 'nexiguard-ip-geo-access-control' ); ?></option>
								<option value="allowlist" <?php selected( 'allowlist', $settings['access_mode'] ); ?>><?php echo esc_html__( 'Allow List: only visitors matching rules are allowed', 'nexiguard-ip-geo-access-control' ); ?></option>
							</select>
							<p class="description"><?php echo esc_html__( 'Allow List mode applies to IP/CIDR, country, and region rules. Use carefully to avoid blocking legitimate visitors.', 'nexiguard-ip-geo-access-control' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php echo esc_html__( 'Blocked response', 'nexiguard-ip-geo-access-control' ); ?></th>
						<td>
							<select name="<?php echo esc_attr( NexiGuard::OPTION_SETTINGS ); ?>[response_type]">
								<option value="403" <?php selected( '403', $settings['response_type'] ); ?>><?php echo esc_html__( '403 Permission Denied', 'nexiguard-ip-geo-access-control' ); ?></option>
								<option value="404" <?php selected( '404', $settings['response_type'] ); ?>><?php echo esc_html__( '404 Not Found', 'nexiguard-ip-geo-access-control' ); ?></option>
								<option value="custom" <?php selected( 'custom', $settings['response_type'] ); ?>><?php echo esc_html__( 'Custom message', 'nexiguard-ip-geo-access-control' ); ?></option>
							</select>
							<p class="description"><?php echo esc_html__( 'Recommended default: 403 Permission Denied.', 'nexiguard-ip-geo-access-control' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="nexiguard-custom-message"><?php echo esc_html__( 'Custom blocked message', 'nexiguard-ip-geo-access-control' ); ?></label></th>
						<td>
							<textarea id="nexiguard-custom-message" name="<?php echo esc_attr( NexiGuard::OPTION_SETTINGS ); ?>[custom_message]" rows="4" class="large-text"><?php echo esc_textarea( $settings['custom_message'] ); ?></textarea>
							<p class="description"><?php echo esc_html__( 'Plain text and basic safe HTML are allowed. Scripts, iframes, and unsafe HTML are removed.', 'nexiguard-ip-geo-access-control' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php echo esc_html__( 'Apply blocking to', 'nexiguard-ip-geo-access-control' ); ?></th>
						<td class="nexiguard-checkbox-list">
							<label><input type="checkbox" name="<?php echo esc_attr( NexiGuard::OPTION_SETTINGS ); ?>[block_frontend]" value="1" <?php checked( 1, (int) $settings['block_frontend'] ); ?> /> <?php echo esc_html__( 'Frontend', 'nexiguard-ip-geo-access-control' ); ?></label>
							<label><input type="checkbox" name="<?php echo esc_attr( NexiGuard::OPTION_SETTINGS ); ?>[block_login]" value="1" <?php checked( 1, (int) $settings['block_login'] ); ?> /> <?php echo esc_html__( 'Login page', 'nexiguard-ip-geo-access-control' ); ?></label>
							<label><input type="checkbox" name="<?php echo esc_attr( NexiGuard::OPTION_SETTINGS ); ?>[block_rest]" value="1" <?php checked( 1, (int) $settings['block_rest'] ); ?> /> <?php echo esc_html__( 'REST API', 'nexiguard-ip-geo-access-control' ); ?></label>
							<label><input type="checkbox" name="<?php echo esc_attr( NexiGuard::OPTION_SETTINGS ); ?>[block_xmlrpc]" value="1" <?php checked( 1, (int) $settings['block_xmlrpc'] ); ?> /> <?php echo esc_html__( 'XML-RPC', 'nexiguard-ip-geo-access-control' ); ?></label>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php echo esc_html__( 'Admin safety', 'nexiguard-ip-geo-access-control' ); ?></th>
						<td>
							<label><input type="checkbox" name="<?php echo esc_attr( NexiGuard::OPTION_SETTINGS ); ?>[never_block_admin]" value="1" <?php checked( 1, (int) $settings['never_block_admin'] ); ?> /> <?php echo esc_html__( 'Never block logged-in administrators.', 'nexiguard-ip-geo-access-control' ); ?></label>
							<p class="description"><?php echo esc_html__( 'Emergency bypass: define NEXIGUARD_DISABLE as true in wp-config.php to stop all blocking.', 'nexiguard-ip-geo-access-control' ); ?></p>
							<p class="description">
								<?php
								printf(
									/* translators: 1: detected IP, 2: source header. */
									esc_html__( 'Current detected admin IP: %1$s Source: %2$s', 'nexiguard-ip-geo-access-control' ),
									'<code>' . esc_html( '' !== $ip_data['ip'] ? $ip_data['ip'] : __( 'Unavailable', 'nexiguard-ip-geo-access-control' ) ) . '</code>',
									'<code>' . esc_html( '' !== $ip_data['source'] ? $ip_data['source'] : __( 'Unavailable', 'nexiguard-ip-geo-access-control' ) ) . '</code>'
								);
								?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php echo esc_html__( 'Visitor IP detection', 'nexiguard-ip-geo-access-control' ); ?></th>
						<td>
							<label><input type="checkbox" name="<?php echo esc_attr( NexiGuard::OPTION_SETTINGS ); ?>[auto_detect_cloudflare]" value="1" <?php checked( 1, (int) $settings['auto_detect_cloudflare'] ); ?> /> <?php echo esc_html__( 'Auto-detect Cloudflare visitor IP using HTTP_CF_CONNECTING_IP.', 'nexiguard-ip-geo-access-control' ); ?></label>
							<p class="description"><?php echo esc_html__( 'Disabled by default. Enable only when the site is behind Cloudflare.', 'nexiguard-ip-geo-access-control' ); ?></p>
							<label><input type="checkbox" name="<?php echo esc_attr( NexiGuard::OPTION_SETTINGS ); ?>[trust_proxy_headers]" value="1" <?php checked( 1, (int) $settings['trust_proxy_headers'] ); ?> /> <?php echo esc_html__( 'Trust proxy headers X-Forwarded-For and X-Real-IP.', 'nexiguard-ip-geo-access-control' ); ?></label>
							<p class="description"><?php echo esc_html__( 'Proxy headers are spoofable unless your web server is behind a trusted proxy. They are not trusted by default.', 'nexiguard-ip-geo-access-control' ); ?></p>
						</td>
					</tr>
				</tbody>
			</table>

			<?php $this->render_geo_settings( $settings ); ?>
			<?php $this->render_logging_settings( $settings ); ?>
			<?php submit_button( esc_html__( 'Save Settings', 'nexiguard-ip-geo-access-control' ) ); ?>
		</form>

		<?php $this->render_settings_tools(); ?>
		<?php
	}

	/**
	 * Renders GeoIP provider settings.
	 *
	 * @param array<string,mixed> $settings Settings.
	 * @return void
	 */
	private function render_geo_settings( $settings ) {
		?>
		<h2><?php echo esc_html__( 'GeoIP Provider', 'nexiguard-ip-geo-access-control' ); ?></h2>
		<p class="description nexiguard-privacy-note"><?php echo esc_html__( 'Privacy note: visitor IPs are never sent externally unless API provider mode is selected and an endpoint is configured by an administrator.', 'nexiguard-ip-geo-access-control' ); ?></p>
		<table class="form-table" role="presentation">
			<tbody>
				<tr>
					<th scope="row"><label for="nexiguard-geo-provider"><?php echo esc_html__( 'Provider type', 'nexiguard-ip-geo-access-control' ); ?></label></th>
					<td>
						<select id="nexiguard-geo-provider" name="<?php echo esc_attr( NexiGuard::OPTION_SETTINGS ); ?>[geo_provider]">
							<option value="none" <?php selected( 'none', $settings['geo_provider'] ); ?>><?php echo esc_html__( 'None', 'nexiguard-ip-geo-access-control' ); ?></option>
							<option value="maxmind" <?php selected( 'maxmind', $settings['geo_provider'] ); ?>><?php echo esc_html__( 'MaxMind local database', 'nexiguard-ip-geo-access-control' ); ?></option>
							<option value="api" <?php selected( 'api', $settings['geo_provider'] ); ?>><?php echo esc_html__( 'API provider', 'nexiguard-ip-geo-access-control' ); ?></option>
						</select>
						<p class="description"><?php echo esc_html__( 'Country and region rules are ignored until a working provider is configured.', 'nexiguard-ip-geo-access-control' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="nexiguard-maxmind-path"><?php echo esc_html__( 'MaxMind database path', 'nexiguard-ip-geo-access-control' ); ?></label></th>
					<td><input id="nexiguard-maxmind-path" type="text" class="regular-text" name="<?php echo esc_attr( NexiGuard::OPTION_SETTINGS ); ?>[maxmind_db_path]" value="<?php echo esc_attr( $settings['maxmind_db_path'] ); ?>" placeholder="/path/to/GeoLite2-City.mmdb" /></td>
				</tr>
				<tr>
					<th scope="row"><label for="nexiguard-api-endpoint"><?php echo esc_html__( 'API endpoint', 'nexiguard-ip-geo-access-control' ); ?></label></th>
					<td><input id="nexiguard-api-endpoint" type="url" class="regular-text" name="<?php echo esc_attr( NexiGuard::OPTION_SETTINGS ); ?>[api_endpoint]" value="<?php echo esc_attr( $settings['api_endpoint'] ); ?>" placeholder="https://example.com/geo/{ip}" /></td>
				</tr>
				<tr>
					<th scope="row"><label for="nexiguard-api-key"><?php echo esc_html__( 'API key', 'nexiguard-ip-geo-access-control' ); ?></label></th>
					<td><input id="nexiguard-api-key" type="password" class="regular-text" autocomplete="off" name="<?php echo esc_attr( NexiGuard::OPTION_SETTINGS ); ?>[api_key]" value="<?php echo esc_attr( $settings['api_key'] ); ?>" /></td>
				</tr>
				<tr>
					<th scope="row"><?php echo esc_html__( 'API response keys', 'nexiguard-ip-geo-access-control' ); ?></th>
					<td>
						<label><?php echo esc_html__( 'Country key', 'nexiguard-ip-geo-access-control' ); ?> <input type="text" name="<?php echo esc_attr( NexiGuard::OPTION_SETTINGS ); ?>[api_country_key]" value="<?php echo esc_attr( $settings['api_country_key'] ); ?>" class="regular-text code" /></label><br />
						<label><?php echo esc_html__( 'Region key', 'nexiguard-ip-geo-access-control' ); ?> <input type="text" name="<?php echo esc_attr( NexiGuard::OPTION_SETTINGS ); ?>[api_region_key]" value="<?php echo esc_attr( $settings['api_region_key'] ); ?>" class="regular-text code" /></label>
						<p class="description"><?php echo esc_html__( 'Dot notation is supported, for example location.country_code or subdivisions.0.iso_code.', 'nexiguard-ip-geo-access-control' ); ?></p>
					</td>
				</tr>
			</tbody>
		</table>
		<?php
	}

	/**
	 * Renders logging and uninstall settings.
	 *
	 * @param array<string,mixed> $settings Settings.
	 * @return void
	 */
	private function render_logging_settings( $settings ) {
		?>
		<h2><?php echo esc_html__( 'Logging and Cleanup', 'nexiguard-ip-geo-access-control' ); ?></h2>
		<table class="form-table" role="presentation">
			<tbody>
				<tr>
					<th scope="row"><?php echo esc_html__( 'Blocked attempt logging', 'nexiguard-ip-geo-access-control' ); ?></th>
					<td>
						<label><input type="checkbox" name="<?php echo esc_attr( NexiGuard::OPTION_SETTINGS ); ?>[logging_enabled]" value="1" <?php checked( 1, (int) $settings['logging_enabled'] ); ?> /> <?php echo esc_html__( 'Log blocked attempts.', 'nexiguard-ip-geo-access-control' ); ?></label>
						<p class="description"><?php echo esc_html__( 'Logs store only date/time, IP address, matched rule type, and requested path.', 'nexiguard-ip-geo-access-control' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="nexiguard-log-limit"><?php echo esc_html__( 'Maximum log entries', 'nexiguard-ip-geo-access-control' ); ?></label></th>
					<td><input id="nexiguard-log-limit" type="number" min="1" max="1000" name="<?php echo esc_attr( NexiGuard::OPTION_SETTINGS ); ?>[log_limit]" value="<?php echo esc_attr( absint( $settings['log_limit'] ) ); ?>" /></td>
				</tr>
				<tr>
					<th scope="row"><?php echo esc_html__( 'Uninstall cleanup', 'nexiguard-ip-geo-access-control' ); ?></th>
					<td><label><input type="checkbox" name="<?php echo esc_attr( NexiGuard::OPTION_SETTINGS ); ?>[delete_data_on_uninstall]" value="1" <?php checked( 1, (int) $settings['delete_data_on_uninstall'] ); ?> /> <?php echo esc_html__( 'Delete plugin data on uninstall.', 'nexiguard-ip-geo-access-control' ); ?></label></td>
				</tr>
			</tbody>
		</table>
		<?php
	}

	/**
	 * Renders settings import/export tools.
	 *
	 * @return void
	 */
	private function render_settings_tools() {
		?>
		<div class="nexiguard-card">
			<h2><?php echo esc_html__( 'Export / Import Settings', 'nexiguard-ip-geo-access-control' ); ?></h2>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="nexiguard-inline-form">
				<input type="hidden" name="action" value="nexiguard_export_settings" />
				<?php wp_nonce_field( 'nexiguard_export_settings' ); ?>
				<?php submit_button( esc_html__( 'Export Settings JSON', 'nexiguard-ip-geo-access-control' ), 'secondary', 'submit', false ); ?>
			</form>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="nexiguard_import_settings" />
				<?php wp_nonce_field( 'nexiguard_import_settings' ); ?>
				<label for="nexiguard-import-json"><strong><?php echo esc_html__( 'Import settings JSON', 'nexiguard-ip-geo-access-control' ); ?></strong></label>
				<textarea id="nexiguard-import-json" name="nexiguard_import_json" rows="8" class="large-text code" placeholder="{&quot;plugin&quot;:&quot;nexiguard-ip-geo-access-control&quot;}"></textarea>
				<p class="description"><?php echo esc_html__( 'Import validates the JSON structure before saving. Current settings are not overwritten if validation fails.', 'nexiguard-ip-geo-access-control' ); ?></p>
				<?php submit_button( esc_html__( 'Import Settings JSON', 'nexiguard-ip-geo-access-control' ), 'secondary' ); ?>
			</form>
		</div>
		<?php
	}

	/**
	 * Renders the IP blocking tab.
	 *
	 * @return void
	 */
	private function render_ip_tab() {
		$rules   = $this->plugin->get_list_option( NexiGuard::OPTION_BLOCKED_IPS );
		$ip_data = $this->blocker->get_client_ip_data();

		?>
		<div class="nexiguard-card">
			<h2><?php echo esc_html__( 'IP Restrictions', 'nexiguard-ip-geo-access-control' ); ?></h2>
			<p><?php echo esc_html__( 'Rules are used as a block list or allow list depending on Access Mode. Examples: 203.0.113.10, 198.51.100.0/24, 2001:db8::/32.', 'nexiguard-ip-geo-access-control' ); ?></p>
			<div class="notice notice-warning inline"><p>
				<?php
				printf(
					/* translators: %s: detected admin IP address. */
					esc_html__( 'Current detected admin IP: %s. Rules matching this IP require confirmation before saving.', 'nexiguard-ip-geo-access-control' ),
					'<code>' . esc_html( '' !== $ip_data['ip'] ? $ip_data['ip'] : __( 'Unavailable', 'nexiguard-ip-geo-access-control' ) ) . '</code>'
				);
				?>
			</p></div>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="nexiguard-inline-form">
				<input type="hidden" name="action" value="nexiguard_add_ip" />
				<?php wp_nonce_field( 'nexiguard_add_ip' ); ?>
				<label for="nexiguard-ip-rule" class="screen-reader-text"><?php echo esc_html__( 'IP address or CIDR range', 'nexiguard-ip-geo-access-control' ); ?></label>
				<input id="nexiguard-ip-rule" type="text" name="nexiguard_ip_rule" class="regular-text code" placeholder="203.0.113.10 or 198.51.100.0/24" required />
				<label class="nexiguard-confirm"><input type="checkbox" name="nexiguard_confirm_current_ip" value="1" /> <?php echo esc_html__( 'I understand this rule may match my current IP.', 'nexiguard-ip-geo-access-control' ); ?></label>
				<?php submit_button( esc_html__( 'Add IP Rule', 'nexiguard-ip-geo-access-control' ), 'primary', 'submit', false ); ?>
			</form>

			<h3><?php echo esc_html__( 'Bulk Import IP/CIDR Rules', 'nexiguard-ip-geo-access-control' ); ?></h3>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="nexiguard_bulk_import_ips" />
				<?php wp_nonce_field( 'nexiguard_bulk_import_ips' ); ?>
				<textarea name="nexiguard_bulk_ip_rules" rows="6" class="large-text code" placeholder="203.0.113.10&#10;198.51.100.0/24&#10;2001:db8::/32"></textarea>
				<p class="description"><?php echo esc_html__( 'Enter one IP address or CIDR range per line. Valid entries are saved; invalid entries are listed in a notice.', 'nexiguard-ip-geo-access-control' ); ?></p>
				<?php submit_button( esc_html__( 'Import IP Rules', 'nexiguard-ip-geo-access-control' ), 'secondary' ); ?>
			</form>

			<?php $this->render_ip_table( $rules ); ?>
		</div>
		<?php
	}

	/**
	 * Renders the country and region tab.
	 *
	 * @return void
	 */
	private function render_geo_tab() {
		$countries = $this->plugin->get_list_option( NexiGuard::OPTION_BLOCKED_COUNTRIES );
		$regions   = $this->plugin->get_list_option( NexiGuard::OPTION_BLOCKED_REGIONS );
		$choices   = $this->get_country_choices();

		?>
		<div class="nexiguard-grid">
			<div class="nexiguard-card">
				<h2><?php echo esc_html__( 'Country Restrictions', 'nexiguard-ip-geo-access-control' ); ?></h2>
				<p><?php echo esc_html__( 'Select a country from the ISO 3166-1 alpha-2 list or enter a two-letter country code manually.', 'nexiguard-ip-geo-access-control' ); ?></p>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="nexiguard-inline-form">
					<input type="hidden" name="action" value="nexiguard_add_country" />
					<?php wp_nonce_field( 'nexiguard_add_country' ); ?>
					<label for="nexiguard-country-select" class="screen-reader-text"><?php echo esc_html__( 'Country', 'nexiguard-ip-geo-access-control' ); ?></label>
					<select id="nexiguard-country-select" name="nexiguard_country_select">
						<option value=""><?php echo esc_html__( 'Select country', 'nexiguard-ip-geo-access-control' ); ?></option>
						<?php foreach ( $choices as $code => $name ) : ?>
							<option value="<?php echo esc_attr( $code ); ?>"><?php echo esc_html( $code . ' - ' . $name ); ?></option>
						<?php endforeach; ?>
					</select>
					<label for="nexiguard-country-manual" class="screen-reader-text"><?php echo esc_html__( 'Manual country code', 'nexiguard-ip-geo-access-control' ); ?></label>
					<input id="nexiguard-country-manual" type="text" name="nexiguard_country_manual" class="small-text code" maxlength="2" placeholder="US" />
					<?php submit_button( esc_html__( 'Add Country', 'nexiguard-ip-geo-access-control' ), 'primary', 'submit', false ); ?>
				</form>
				<?php $this->render_country_table( $countries ); ?>
			</div>

			<div class="nexiguard-card">
				<h2><?php echo esc_html__( 'Region Restrictions', 'nexiguard-ip-geo-access-control' ); ?></h2>
				<p><?php echo esc_html__( 'Add region/state codes returned by your GeoIP provider, such as CA or US-CA.', 'nexiguard-ip-geo-access-control' ); ?></p>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="nexiguard-inline-form">
					<input type="hidden" name="action" value="nexiguard_add_region" />
					<?php wp_nonce_field( 'nexiguard_add_region' ); ?>
					<label for="nexiguard-region" class="screen-reader-text"><?php echo esc_html__( 'Region code', 'nexiguard-ip-geo-access-control' ); ?></label>
					<input id="nexiguard-region" type="text" name="nexiguard_region" class="regular-text code" maxlength="24" placeholder="US-CA" required />
					<?php submit_button( esc_html__( 'Add Region', 'nexiguard-ip-geo-access-control' ), 'primary', 'submit', false ); ?>
				</form>
				<?php $this->render_region_table( $regions ); ?>
			</div>
		</div>
		<?php
	}

	/**
	 * Renders the logs tab.
	 *
	 * @return void
	 */
	private function render_logs_tab() {
		$logs = array_reverse( $this->logger->get_logs() );

		?>
		<div class="nexiguard-card">
			<h2><?php echo esc_html__( 'Logs', 'nexiguard-ip-geo-access-control' ); ?></h2>
			<p class="nexiguard-privacy-note"><?php echo esc_html__( 'Privacy note: logging is optional and stores only date/time, IP address, matched rule type, and requested path for blocked attempts.', 'nexiguard-ip-geo-access-control' ); ?></p>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="nexiguard_clear_logs" />
				<?php wp_nonce_field( 'nexiguard_clear_logs' ); ?>
				<?php submit_button( esc_html__( 'Clear Logs', 'nexiguard-ip-geo-access-control' ), 'secondary', 'submit', false ); ?>
			</form>

			<table class="widefat striped nexiguard-table">
				<thead><tr><th><?php echo esc_html__( 'Date/time (UTC)', 'nexiguard-ip-geo-access-control' ); ?></th><th><?php echo esc_html__( 'IP address', 'nexiguard-ip-geo-access-control' ); ?></th><th><?php echo esc_html__( 'Rule type', 'nexiguard-ip-geo-access-control' ); ?></th><th><?php echo esc_html__( 'Requested path', 'nexiguard-ip-geo-access-control' ); ?></th></tr></thead>
				<tbody>
					<?php if ( empty( $logs ) ) : ?>
						<tr><td colspan="4"><?php echo esc_html__( 'No blocked attempts have been logged.', 'nexiguard-ip-geo-access-control' ); ?></td></tr>
					<?php else : ?>
						<?php foreach ( $logs as $log ) : ?>
							<tr>
								<td><?php echo esc_html( isset( $log['datetime'] ) ? $log['datetime'] : '' ); ?></td>
								<td><code><?php echo esc_html( isset( $log['ip'] ) ? $log['ip'] : '' ); ?></code></td>
								<td><?php echo esc_html( isset( $log['rule_type'] ) ? $log['rule_type'] : '' ); ?></td>
								<td><code><?php echo esc_html( isset( $log['path'] ) ? $log['path'] : '' ); ?></code></td>
							</tr>
						<?php endforeach; ?>
					<?php endif; ?>
				</tbody>
			</table>
		</div>
		<?php
	}

	/**
	 * Renders the IP rules table.
	 *
	 * @param array<int,string> $rules Rules.
	 * @return void
	 */
	private function render_ip_table( $rules ) {
		?>
		<table class="widefat striped nexiguard-table">
			<thead><tr><th><?php echo esc_html__( 'Rule', 'nexiguard-ip-geo-access-control' ); ?></th><th><?php echo esc_html__( 'Type', 'nexiguard-ip-geo-access-control' ); ?></th><th><?php echo esc_html__( 'Action', 'nexiguard-ip-geo-access-control' ); ?></th></tr></thead>
			<tbody>
				<?php if ( empty( $rules ) ) : ?>
					<tr><td colspan="3"><?php echo esc_html__( 'No IP rules have been added.', 'nexiguard-ip-geo-access-control' ); ?></td></tr>
				<?php else : ?>
					<?php foreach ( $rules as $rule ) : ?>
						<tr>
							<td><code><?php echo esc_html( $rule ); ?></code></td>
							<td><?php echo false !== strpos( $rule, '/' ) ? esc_html__( 'CIDR range', 'nexiguard-ip-geo-access-control' ) : esc_html__( 'IP address', 'nexiguard-ip-geo-access-control' ); ?></td>
							<td><?php $this->render_remove_form( 'nexiguard_remove_ip', 'nexiguard_ip_rule', $rule, 'nexiguard_remove_ip' ); ?></td>
						</tr>
					<?php endforeach; ?>
				<?php endif; ?>
			</tbody>
		</table>
		<?php
	}

	/**
	 * Renders the country table.
	 *
	 * @param array<int,string> $countries Country rules.
	 * @return void
	 */
	private function render_country_table( $countries ) {
		$this->render_simple_rule_table( $countries, esc_html__( 'Country code', 'nexiguard-ip-geo-access-control' ), esc_html__( 'No country rules have been added.', 'nexiguard-ip-geo-access-control' ), 'nexiguard_remove_country', 'nexiguard_country', 'nexiguard_remove_country' );
	}

	/**
	 * Renders the region table.
	 *
	 * @param array<int,string> $regions Region rules.
	 * @return void
	 */
	private function render_region_table( $regions ) {
		$this->render_simple_rule_table( $regions, esc_html__( 'Region code', 'nexiguard-ip-geo-access-control' ), esc_html__( 'No region rules have been added.', 'nexiguard-ip-geo-access-control' ), 'nexiguard_remove_region', 'nexiguard_region', 'nexiguard_remove_region' );
	}

	/**
	 * Renders a simple rule table.
	 *
	 * @param array<int,string> $items Items.
	 * @param string            $label Column label.
	 * @param string            $empty_message Empty state.
	 * @param string            $action Admin post action.
	 * @param string            $field_name Hidden field name.
	 * @param string            $nonce_action Nonce action.
	 * @return void
	 */
	private function render_simple_rule_table( $items, $label, $empty_message, $action, $field_name, $nonce_action ) {
		?>
		<table class="widefat striped nexiguard-table">
			<thead><tr><th><?php echo esc_html( $label ); ?></th><th><?php echo esc_html__( 'Action', 'nexiguard-ip-geo-access-control' ); ?></th></tr></thead>
			<tbody>
				<?php if ( empty( $items ) ) : ?>
					<tr><td colspan="2"><?php echo esc_html( $empty_message ); ?></td></tr>
				<?php else : ?>
					<?php foreach ( $items as $item ) : ?>
						<tr><td><code><?php echo esc_html( $item ); ?></code></td><td><?php $this->render_remove_form( $action, $field_name, $item, $nonce_action ); ?></td></tr>
					<?php endforeach; ?>
				<?php endif; ?>
			</tbody>
		</table>
		<?php
	}

	/**
	 * Renders a remove form.
	 *
	 * @param string $action Admin post action.
	 * @param string $field_name Hidden field name.
	 * @param string $value Hidden field value.
	 * @param string $nonce_action Nonce action.
	 * @return void
	 */
	private function render_remove_form( $action, $field_name, $value, $nonce_action ) {
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="nexiguard-remove-form">
			<input type="hidden" name="action" value="<?php echo esc_attr( $action ); ?>" />
			<input type="hidden" name="<?php echo esc_attr( $field_name ); ?>" value="<?php echo esc_attr( $value ); ?>" />
			<?php wp_nonce_field( $nonce_action ); ?>
			<?php submit_button( esc_html__( 'Remove', 'nexiguard-ip-geo-access-control' ), 'link-delete', 'submit', false ); ?>
		</form>
		<?php
	}

	/**
	 * Renders a GeoIP configuration notice.
	 *
	 * @return void
	 */
	private function render_geo_notice() {
		if ( $this->geo->has_configured_provider() ) {
			return;
		}

		?>
		<div class="notice notice-info inline"><p><?php echo esc_html__( 'IP-only blocking works without any third-party service. Country and region blocking requires either a readable local GeoIP database or an explicitly configured API provider.', 'nexiguard-ip-geo-access-control' ); ?></p></div>
		<?php
	}

	/**
	 * Validates imported settings data.
	 *
	 * @param array<string,mixed> $data Import data.
	 * @return array<string,mixed>
	 */
	private function validate_import_data( $data ) {
		$errors = array();

		if ( empty( $data['settings'] ) || ! is_array( $data['settings'] ) ) {
			$errors[] = __( 'Missing settings object.', 'nexiguard-ip-geo-access-control' );
		}

		$settings  = empty( $errors ) ? $this->sanitize_settings_array( $data['settings'] ) : array();
		$ip_rules  = $this->sanitize_imported_ip_rules( isset( $data['blocked_ips'] ) ? $data['blocked_ips'] : array(), $errors );
		$countries = $this->sanitize_imported_countries( isset( $data['blocked_countries'] ) ? $data['blocked_countries'] : array(), $errors );
		$regions   = $this->sanitize_imported_regions( isset( $data['blocked_regions'] ) ? $data['blocked_regions'] : array(), $errors );

		return array(
			'errors'            => $errors,
			'settings'          => $settings,
			'blocked_ips'       => $ip_rules,
			'blocked_countries' => $countries,
			'blocked_regions'   => $regions,
		);
	}

	/**
	 * Sanitizes imported IP rules.
	 *
	 * @param mixed             $items Raw items.
	 * @param array<int,string> $errors Errors passed by reference.
	 * @return array<int,string>
	 */
	private function sanitize_imported_ip_rules( $items, &$errors ) {
		if ( ! is_array( $items ) ) {
			$errors[] = __( 'blocked_ips must be an array.', 'nexiguard-ip-geo-access-control' );
			return array();
		}

		$rules = array();

		foreach ( $items as $item ) {
			$rule = sanitize_text_field( (string) $item );

			if ( ! $this->blocker->is_valid_ip_rule( $rule ) ) {
				$errors[] = sprintf(
					/* translators: %s: invalid IP rule. */
					__( 'Invalid IP rule: %s', 'nexiguard-ip-geo-access-control' ),
					$rule
				);
				continue;
			}

			$rules[] = $rule;
		}

		return array_values( array_unique( $rules ) );
	}

	/**
	 * Sanitizes imported country rules.
	 *
	 * @param mixed             $items Raw items.
	 * @param array<int,string> $errors Errors passed by reference.
	 * @return array<int,string>
	 */
	private function sanitize_imported_countries( $items, &$errors ) {
		if ( ! is_array( $items ) ) {
			$errors[] = __( 'blocked_countries must be an array.', 'nexiguard-ip-geo-access-control' );
			return array();
		}

		$countries = array();
		$choices   = $this->get_country_choices();

		foreach ( $items as $item ) {
			$country = strtoupper( sanitize_text_field( (string) $item ) );
			$country = preg_replace( '/[^A-Z]/', '', $country );
			$country = is_string( $country ) ? $country : '';

			if ( 2 !== strlen( $country ) || ! array_key_exists( $country, $choices ) ) {
				$errors[] = sprintf(
					/* translators: %s: invalid country code. */
					__( 'Invalid country code: %s', 'nexiguard-ip-geo-access-control' ),
					$country
				);
				continue;
			}

			$countries[] = $country;
		}

		return array_values( array_unique( $countries ) );
	}

	/**
	 * Sanitizes imported region rules.
	 *
	 * @param mixed             $items Raw items.
	 * @param array<int,string> $errors Errors passed by reference.
	 * @return array<int,string>
	 */
	private function sanitize_imported_regions( $items, &$errors ) {
		if ( ! is_array( $items ) ) {
			$errors[] = __( 'blocked_regions must be an array.', 'nexiguard-ip-geo-access-control' );
			return array();
		}

		$regions = array();

		foreach ( $items as $item ) {
			$region = strtoupper( sanitize_text_field( (string) $item ) );
			$region = preg_replace( '/[^A-Z0-9_-]/', '', $region );
			$region = is_string( $region ) ? $region : '';

			if ( '' === $region || strlen( $region ) > 24 ) {
				$errors[] = sprintf(
					/* translators: %s: invalid region code. */
					__( 'Invalid region code: %s', 'nexiguard-ip-geo-access-control' ),
					$region
				);
				continue;
			}

			$regions[] = $region;
		}

		return array_values( array_unique( $regions ) );
	}

	/**
	 * Returns tab labels.
	 *
	 * @return array<string,string>
	 */
	private function get_tabs() {
		return array(
			'general' => __( 'General', 'nexiguard-ip-geo-access-control' ),
			'ip'      => __( 'IP Blocking', 'nexiguard-ip-geo-access-control' ),
			'geo'     => __( 'Country & Region Blocking', 'nexiguard-ip-geo-access-control' ),
			'logs'    => __( 'Logs', 'nexiguard-ip-geo-access-control' ),
		);
	}

	/**
	 * Returns the current active tab.
	 *
	 * @return string
	 */
	private function get_active_tab() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only tab selection; no state is changed.
		$tab  = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'general';
		$tabs = $this->get_tabs();

		return array_key_exists( $tab, $tabs ) ? $tab : 'general';
	}

	/**
	 * Builds a tab URL.
	 *
	 * @param string $tab Tab key.
	 * @return string
	 */
	private function get_tab_url( $tab ) {
		return add_query_arg(
			array(
				'page' => self::MENU_SLUG,
				'tab'  => sanitize_key( $tab ),
			),
			admin_url( 'admin.php' )
		);
	}

	/**
	 * Checks if the current screen is this plugin page.
	 *
	 * @return bool
	 */
	private function is_plugin_page() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only admin screen detection; no state is changed.
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : '';

		return self::MENU_SLUG === $page;
	}

	/**
	 * Verifies settings capability.
	 *
	 * @return void
	 */
	private function verify_capability() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to perform this action.', 'nexiguard-ip-geo-access-control' ) );
		}
	}

	/**
	 * Redirects back to the settings page with a notice.
	 *
	 * @param string $tab Tab key.
	 * @param string $notice Notice code.
	 * @param string $type Notice type.
	 * @return void
	 */
	private function redirect_with_notice( $tab, $notice, $type ) {
		wp_safe_redirect(
			add_query_arg(
				array(
					'page'                     => self::MENU_SLUG,
					'tab'                      => sanitize_key( $tab ),
					'nexiguard_notice'      => sanitize_key( $notice ),
					'nexiguard_notice_type' => sanitize_key( $type ),
					'_wpnonce'                 => wp_create_nonce( 'nexiguard_notice' ),
				),
				admin_url( 'admin.php' )
			)
		);
		exit;
	}

	/**
	 * Stores details for the next admin notice.
	 *
	 * @param array<string,mixed> $details Notice details.
	 * @return void
	 */
	private function set_notice_details( $details ) {
		$user_id = get_current_user_id();

		if ( $user_id > 0 ) {
			set_transient( 'nexiguard_notice_details_' . $user_id, $details, MINUTE_IN_SECONDS * 5 );
		}
	}

	/**
	 * Returns formatted details for the current admin notice.
	 *
	 * @return string
	 */
	private function get_notice_details() {
		$user_id = get_current_user_id();

		if ( $user_id <= 0 ) {
			return '';
		}

		$details = get_transient( 'nexiguard_notice_details_' . $user_id );
		delete_transient( 'nexiguard_notice_details_' . $user_id );

		if ( ! is_array( $details ) ) {
			return '';
		}

		$output = '';

		if ( isset( $details['added'] ) ) {
			$output .= '<p>' . esc_html(
				sprintf(
					/* translators: %d: number of valid imported rules. */
					__( 'Valid rules added: %d', 'nexiguard-ip-geo-access-control' ),
					absint( $details['added'] )
				)
			) . '</p>';
		}

		if ( ! empty( $details['invalid'] ) && is_array( $details['invalid'] ) ) {
			$output .= '<p><strong>' . esc_html__( 'Invalid entries:', 'nexiguard-ip-geo-access-control' ) . '</strong></p><ul>';
			foreach ( $details['invalid'] as $invalid ) {
				$output .= '<li><code>' . esc_html( (string) $invalid ) . '</code></li>';
			}
			$output .= '</ul>';
		}

		if ( ! empty( $details['errors'] ) && is_array( $details['errors'] ) ) {
			$output .= '<ul>';
			foreach ( $details['errors'] as $error ) {
				$output .= '<li>' . esc_html( (string) $error ) . '</li>';
			}
			$output .= '</ul>';
		}

		return $output;
	}

	/**
	 * Sanitizes a dot-notated JSON key path.
	 *
	 * @param string $value Raw value.
	 * @param string $default Default value.
	 * @return string
	 */
	private function sanitize_dot_key( $value, $default ) {
		$value = preg_replace( '/[^A-Za-z0-9_.-]/', '', sanitize_text_field( $value ) );
		$value = is_string( $value ) ? $value : '';

		return '' === $value ? $default : $value;
	}

	/**
	 * Returns static ISO 3166-1 alpha-2 country choices.
	 *
	 * @return array<string,string>
	 */
	private function get_country_choices() {
		return array(
			'AF'=>'Afghanistan','AX'=>'Aland Islands','AL'=>'Albania','DZ'=>'Algeria','AS'=>'American Samoa','AD'=>'Andorra','AO'=>'Angola','AI'=>'Anguilla','AQ'=>'Antarctica','AG'=>'Antigua and Barbuda','AR'=>'Argentina','AM'=>'Armenia','AW'=>'Aruba','AU'=>'Australia','AT'=>'Austria','AZ'=>'Azerbaijan','BS'=>'Bahamas','BH'=>'Bahrain','BD'=>'Bangladesh','BB'=>'Barbados','BY'=>'Belarus','BE'=>'Belgium','BZ'=>'Belize','BJ'=>'Benin','BM'=>'Bermuda','BT'=>'Bhutan','BO'=>'Bolivia','BQ'=>'Bonaire, Sint Eustatius and Saba','BA'=>'Bosnia and Herzegovina','BW'=>'Botswana','BV'=>'Bouvet Island','BR'=>'Brazil','IO'=>'British Indian Ocean Territory','BN'=>'Brunei Darussalam','BG'=>'Bulgaria','BF'=>'Burkina Faso','BI'=>'Burundi','CV'=>'Cabo Verde','KH'=>'Cambodia','CM'=>'Cameroon','CA'=>'Canada','KY'=>'Cayman Islands','CF'=>'Central African Republic','TD'=>'Chad','CL'=>'Chile','CN'=>'China','CX'=>'Christmas Island','CC'=>'Cocos Islands','CO'=>'Colombia','KM'=>'Comoros','CG'=>'Congo','CD'=>'Congo, Democratic Republic of the','CK'=>'Cook Islands','CR'=>'Costa Rica','CI'=>'Cote d Ivoire','HR'=>'Croatia','CU'=>'Cuba','CW'=>'Curacao','CY'=>'Cyprus','CZ'=>'Czechia','DK'=>'Denmark','DJ'=>'Djibouti','DM'=>'Dominica','DO'=>'Dominican Republic','EC'=>'Ecuador','EG'=>'Egypt','SV'=>'El Salvador','GQ'=>'Equatorial Guinea','ER'=>'Eritrea','EE'=>'Estonia','SZ'=>'Eswatini','ET'=>'Ethiopia','FK'=>'Falkland Islands','FO'=>'Faroe Islands','FJ'=>'Fiji','FI'=>'Finland','FR'=>'France','GF'=>'French Guiana','PF'=>'French Polynesia','TF'=>'French Southern Territories','GA'=>'Gabon','GM'=>'Gambia','GE'=>'Georgia','DE'=>'Germany','GH'=>'Ghana','GI'=>'Gibraltar','GR'=>'Greece','GL'=>'Greenland','GD'=>'Grenada','GP'=>'Guadeloupe','GU'=>'Guam','GT'=>'Guatemala','GG'=>'Guernsey','GN'=>'Guinea','GW'=>'Guinea-Bissau','GY'=>'Guyana','HT'=>'Haiti','HM'=>'Heard Island and McDonald Islands','VA'=>'Holy See','HN'=>'Honduras','HK'=>'Hong Kong','HU'=>'Hungary','IS'=>'Iceland','IN'=>'India','ID'=>'Indonesia','IR'=>'Iran','IQ'=>'Iraq','IE'=>'Ireland','IM'=>'Isle of Man','IL'=>'Israel','IT'=>'Italy','JM'=>'Jamaica','JP'=>'Japan','JE'=>'Jersey','JO'=>'Jordan','KZ'=>'Kazakhstan','KE'=>'Kenya','KI'=>'Kiribati','KP'=>'Korea, Democratic Peoples Republic of','KR'=>'Korea, Republic of','KW'=>'Kuwait','KG'=>'Kyrgyzstan','LA'=>'Lao Peoples Democratic Republic','LV'=>'Latvia','LB'=>'Lebanon','LS'=>'Lesotho','LR'=>'Liberia','LY'=>'Libya','LI'=>'Liechtenstein','LT'=>'Lithuania','LU'=>'Luxembourg','MO'=>'Macao','MG'=>'Madagascar','MW'=>'Malawi','MY'=>'Malaysia','MV'=>'Maldives','ML'=>'Mali','MT'=>'Malta','MH'=>'Marshall Islands','MQ'=>'Martinique','MR'=>'Mauritania','MU'=>'Mauritius','YT'=>'Mayotte','MX'=>'Mexico','FM'=>'Micronesia','MD'=>'Moldova','MC'=>'Monaco','MN'=>'Mongolia','ME'=>'Montenegro','MS'=>'Montserrat','MA'=>'Morocco','MZ'=>'Mozambique','MM'=>'Myanmar','NA'=>'Namibia','NR'=>'Nauru','NP'=>'Nepal','NL'=>'Netherlands','NC'=>'New Caledonia','NZ'=>'New Zealand','NI'=>'Nicaragua','NE'=>'Niger','NG'=>'Nigeria','NU'=>'Niue','NF'=>'Norfolk Island','MK'=>'North Macedonia','MP'=>'Northern Mariana Islands','NO'=>'Norway','OM'=>'Oman','PK'=>'Pakistan','PW'=>'Palau','PS'=>'Palestine, State of','PA'=>'Panama','PG'=>'Papua New Guinea','PY'=>'Paraguay','PE'=>'Peru','PH'=>'Philippines','PN'=>'Pitcairn','PL'=>'Poland','PT'=>'Portugal','PR'=>'Puerto Rico','QA'=>'Qatar','RE'=>'Reunion','RO'=>'Romania','RU'=>'Russian Federation','RW'=>'Rwanda','BL'=>'Saint Barthelemy','SH'=>'Saint Helena','KN'=>'Saint Kitts and Nevis','LC'=>'Saint Lucia','MF'=>'Saint Martin','PM'=>'Saint Pierre and Miquelon','VC'=>'Saint Vincent and the Grenadines','WS'=>'Samoa','SM'=>'San Marino','ST'=>'Sao Tome and Principe','SA'=>'Saudi Arabia','SN'=>'Senegal','RS'=>'Serbia','SC'=>'Seychelles','SL'=>'Sierra Leone','SG'=>'Singapore','SX'=>'Sint Maarten','SK'=>'Slovakia','SI'=>'Slovenia','SB'=>'Solomon Islands','SO'=>'Somalia','ZA'=>'South Africa','GS'=>'South Georgia and the South Sandwich Islands','SS'=>'South Sudan','ES'=>'Spain','LK'=>'Sri Lanka','SD'=>'Sudan','SR'=>'Suriname','SJ'=>'Svalbard and Jan Mayen','SE'=>'Sweden','CH'=>'Switzerland','SY'=>'Syrian Arab Republic','TW'=>'Taiwan','TJ'=>'Tajikistan','TZ'=>'Tanzania','TH'=>'Thailand','TL'=>'Timor-Leste','TG'=>'Togo','TK'=>'Tokelau','TO'=>'Tonga','TT'=>'Trinidad and Tobago','TN'=>'Tunisia','TR'=>'Turkiye','TM'=>'Turkmenistan','TC'=>'Turks and Caicos Islands','TV'=>'Tuvalu','UG'=>'Uganda','UA'=>'Ukraine','AE'=>'United Arab Emirates','GB'=>'United Kingdom','US'=>'United States','UM'=>'United States Minor Outlying Islands','UY'=>'Uruguay','UZ'=>'Uzbekistan','VU'=>'Vanuatu','VE'=>'Venezuela','VN'=>'Viet Nam','VG'=>'Virgin Islands, British','VI'=>'Virgin Islands, U.S.','WF'=>'Wallis and Futuna','EH'=>'Western Sahara','YE'=>'Yemen','ZM'=>'Zambia','ZW'=>'Zimbabwe',
		);
	}
}
