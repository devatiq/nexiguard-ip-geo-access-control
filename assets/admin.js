(function () {
	'use strict';

	document.addEventListener('DOMContentLoaded', function () {
		var countrySelect = document.getElementById('nexiguard-country-select');
		var manualCountry = document.getElementById('nexiguard-country-manual');

		if (!countrySelect || !manualCountry) {
			return;
		}

		countrySelect.addEventListener('change', function () {
			if (countrySelect.value) {
				manualCountry.value = '';
			}
		});
	});
}());
