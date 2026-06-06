=== NexiGuard – IP & Geo Access Control ===
Contributors: nexiby
Tags: security, ip block, geo block, access control, firewall
Requires at least: 6.0
Tested up to: 7.0
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Restrict website access by IP addresses, CIDR ranges, countries, and regions.

== Description ==

NexiGuard – IP & Geo Access Control is a public WordPress access control plugin for administrators who need to restrict site access using local IP rules and optional GeoIP data.

Features include:

* Block List mode: visitors matching rules are blocked.
* Allow List mode: only visitors matching rules are allowed.
* Exact IP address rules.
* CIDR range rules for IPv4 and IPv6.
* Country and region/state rules when a GeoIP provider is configured.
* Optional blocking for the frontend, login page, REST API, and XML-RPC.
* 403, 404, or custom blocked responses.
* Custom blocked messages with plain text and basic safe HTML.
* Safe visitor IP detection using REMOTE_ADDR by default.
* Optional Cloudflare visitor IP detection.
* Optional trusted proxy header support.
* Bulk import for IP/CIDR rules.
* Export and import settings as JSON.
* Optional minimal blocked-attempt logs.
* Admin lockout protection and an emergency bypass constant.

= Privacy and GeoIP =

IP blocking works without any third-party service. Country and region blocking requires either a readable local GeoIP database or an explicitly configured API provider.

Visitor IP addresses are not sent externally unless an administrator selects API provider mode and configures an API endpoint. Optional logs store only date/time, IP address, matched rule type, and requested path.

= Admin safety =

NexiGuard is disabled by default after activation. Logged-in administrators are never blocked by default. The admin screen displays the detected admin IP and requires confirmation before adding an IP/CIDR rule that matches it.

Emergency bypass: define `NEXIGUARD_DISABLE` as `true` in `wp-config.php` to stop all blocking.

== Installation ==

1. Upload the `nexiguard-ip-geo-access-control` folder to `/wp-content/plugins/`.
2. Activate **NexiGuard – IP & Geo Access Control** from the Plugins screen.
3. Go to **NexiGuard** in the WordPress admin menu.
4. Review the detected admin IP and source.
5. Add IP, CIDR, country, or region rules.
6. Enable protection after confirming the desired access mode and request contexts.

== Frequently Asked Questions ==

= Does NexiGuard work without a third-party service? =

Yes. Exact IP and CIDR blocking work locally without any external dependency.

= Do country and region rules require a provider? =

Yes. Country and region rules require a local GeoIP database or an explicitly configured API provider.

= Are visitor IPs sent to external services? =

No, not by default. Visitor IPs are sent externally only when an administrator selects API provider mode and configures an API endpoint.

= Does the plugin trust proxy headers by default? =

No. The plugin uses `REMOTE_ADDR` by default. Cloudflare and proxy header support are disabled until an administrator enables them.

= What is Allow List mode? =

Allow List mode blocks visitors unless they match one of your configured IP, CIDR, country, or region rules. Use it carefully.

= What data is logged? =

Only blocked attempts are logged, and only when logging is enabled. Logs contain date/time, IP address, matched rule type, and requested path.

= How can I avoid an accidental lockout? =

Logged-in administrators are excluded by default, and matching the current admin IP requires confirmation. You can also define `NEXIGUARD_DISABLE` as `true` in `wp-config.php`.

== Screenshots ==

1. General settings with access mode, response type, IP detection, GeoIP provider, logging, and cleanup settings.
2. IP Blocking tab with single-rule add, bulk import, and rule table.
3. Country & Region Blocking tab with ISO country selector and manual region rules.
4. Logs tab with recent blocked attempts and clear logs button.

== Changelog ==

= 1.0.0 =
* Initial public release.

== Upgrade Notice ==

= 1.0.0 =
Initial public release of NexiGuard – IP & Geo Access Control.

== License ==

NexiGuard – IP & Geo Access Control is licensed under GPL-2.0-or-later.
