(function () {
	'use strict';

	document.addEventListener('DOMContentLoaded', function () {

		/* ── Country select ↔ manual field sync ──────────────────────────── */
		var countrySelect = document.getElementById('nexiguard-country-select');
		var manualCountry = document.getElementById('nexiguard-country-manual');

		if (countrySelect && manualCountry) {
			countrySelect.addEventListener('change', function () {
				if (countrySelect.value) {
					manualCountry.value = '';
				}
			});
			manualCountry.addEventListener('input', function () {
				if (manualCountry.value.trim()) {
					countrySelect.value = '';
				}
			});
		}

		/* ── Enhance IP table: wrap type labels in badge spans ───────────── */
		document.querySelectorAll('.nexiguard-table tbody td').forEach(function (td) {
			var text = td.textContent.trim();
			if (text === 'CIDR range') {
				td.innerHTML = '<span class="ng-badge">' + text + '</span>';
			} else if (text === 'IP address') {
				td.innerHTML = '<span class="ng-badge ng-badge-ip">' + text + '</span>';
			}
		});

		/* ── Enhance log table: wrap rule_type in styled badge ───────────── */
		document.querySelectorAll('.nexiguard-table td').forEach(function (td) {
			var prev = td.previousElementSibling;
			if (prev && prev.querySelector('code') && !td.querySelector('form') && !td.querySelector('code') && !td.querySelector('span')) {
				var text = td.textContent.trim();
				if (text && text.length > 0 && text.indexOf(' ') === -1) {
					td.innerHTML = '<span class="ng-rule-type">' + text + '</span>';
				}
			}
		});

		/* ── Add status badge to header banner ───────────────────────────── */
		var wrap = document.querySelector('.nexiguard-wrap');
		if (!wrap) return;

		var enabledCheckbox = document.querySelector('input[name$="[enabled]"]');
		var isEnabled = enabledCheckbox ? enabledCheckbox.checked : false;

		// Insert header banner after the h1 / description
		var h1    = wrap.querySelector('h1');
		var desc  = wrap.querySelector('.description');
		var panel = wrap.querySelector('.nexiguard-panel');
		var afterEl = desc || h1;

		if (afterEl && panel && !wrap.querySelector('.nexiguard-header-banner')) {
			var banner = document.createElement('div');
			banner.className = 'nexiguard-header-banner';

			var dot = isEnabled
				? '<span class="ng-dot active"></span>'
				: '<span class="ng-dot"></span>';

			banner.innerHTML =
				'<div class="ng-banner-icon">' +
					'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">' +
						'<path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/>' +
					'</svg>' +
				'</div>' +
				'<div class="ng-banner-text">' +
					'<h1>NexiGuard — IP &amp; Geo Access Control</h1>' +
					'<p>Control public access by IP address, CIDR range, country, or region.</p>' +
				'</div>' +
				'<div class="ng-banner-status">' +
					dot +
					(isEnabled ? 'Protection Active' : 'Protection Disabled') +
				'</div>';

			afterEl.insertAdjacentElement('afterend', banner);

			// Hide the original h1 heading (banner replaces it visually)
			if (h1) h1.style.cssText = 'position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;';
			if (desc) desc.style.display = 'none';
		}

		/* ── Remove button confirmation ───────────────────────────────────── */
		document.querySelectorAll('.nexiguard-remove-form').forEach(function (form) {
			form.addEventListener('submit', function (e) {
				var btn   = form.querySelector('[type="submit"]');
				var label = btn ? btn.value || btn.textContent : '';
				if (label.toLowerCase().indexOf('remove') !== -1) {
					if (!window.confirm('Remove this rule?')) {
						e.preventDefault();
					}
				}
			});
		});

		/* ── Textarea auto-expand ─────────────────────────────────────────── */
		document.querySelectorAll('.nexiguard-card textarea').forEach(function (ta) {
			ta.addEventListener('input', function () {
				ta.style.height = 'auto';
				ta.style.height = (ta.scrollHeight + 2) + 'px';
			});
		});

		/* ── Smooth card hover glow ───────────────────────────────────────── */
		document.querySelectorAll('.nexiguard-card').forEach(function (card) {
			card.addEventListener('mousemove', function (e) {
				var rect  = card.getBoundingClientRect();
				var x     = ((e.clientX - rect.left) / rect.width  * 100).toFixed(1);
				var y     = ((e.clientY - rect.top)  / rect.height * 100).toFixed(1);
				card.style.background =
					'radial-gradient(circle at ' + x + '% ' + y + '%, rgba(79,70,229,.04) 0%, #fff 60%)';
			});
			card.addEventListener('mouseleave', function () {
				card.style.background = '';
			});
		});
	});
}());
