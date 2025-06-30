let urlInput = document.getElementById('urlInput');
let analyzeBtn = document.getElementById('analyzeBtn');
let resultsContainer = document.getElementById('resultsContainer');
let loading = document.getElementById('loading');
let errorMessage = document.getElementById('errorMessage');

analyzeBtn.addEventListener('click', analyzeURL);
urlInput.addEventListener('keypress', (e) => {
	if (e.key === 'Enter') analyzeURL();
});
urlInput.addEventListener('input', clearResults);

function analyzeURL() {
	let urlString = urlInput.value.trim();

	if (!urlString) {
		showError('Please enter a URL to analyze');
		return;
	}

	showLoading();

	setTimeout(() => {
		try {
			const analysis = performAnalysis(urlString);
			displayResults(analysis);
		} catch (error) {
			showError(error.message);
		}
	}, 600);
}

function performAnalysis(urlString) {
	if (!urlString.match(/^https?:\/\//i) && !urlString.match(/^ftp:\/\//i)) {
		urlString = 'https://' + urlString;
	}

	let url;
	try {
		url = new URL(urlString);
	} catch {
		throw new Error(
			'Invalid URL format. Please check your URL and try again.'
		);
	}

	return {
		original: urlString,
		url: url,
		basic: getBasicInfo(url),
		components: getURLComponents(url),
		domain: getDomainInfo(url),
		security: getSecurityInfo(url),
	};
}

function getBasicInfo(url) {
	return {
		Website: url.hostname,
		Protocol: url.protocol.replace(':', '').toUpperCase(),
		Port: url.port || (url.protocol === 'https:' ? '443' : '80'),
		Path: url.pathname === '/' ? 'Root' : url.pathname,
		'Query Params': new URLSearchParams(url.search).size || 'None',
		Fragment: url.hash ? url.hash.substring(1) : 'None',
	};
}

function getURLComponents(url) {
	const pathSegments = url.pathname.split('/').filter(Boolean);
	const queryParams = new URLSearchParams(url.search);

	return {
		'Full URL': url.href,
		Origin: url.origin,
		Hostname: url.hostname,
		'Path Depth': pathSegments.length + ' levels',
		'URL Length': url.href.length + ' chars',
		'Relative Path': url.pathname + url.search + url.hash || '/',
	};
}

function getDomainInfo(url) {
	const hostname = url.hostname;
	const parts = hostname.split('.');
	const isIP = /^\d+\.\d+\.\d+\.\d+$/.test(hostname);

	let subdomain = '';
	let domain = hostname;
	let tld = '';

	if (!isIP && parts.length > 2) {
		tld = parts.slice(-1)[0];
		domain = parts.slice(-2, -1)[0];
		subdomain = parts.slice(0, -2).join('.');
	}

	return {
		'Domain Type': isIP ? 'IP Address' : 'Domain Name',
		'Main Domain': domain,
		Subdomain: subdomain || 'None',
		TLD: tld || (isIP ? 'N/A' : 'Unknown'),
		'Domain Parts': parts.length + ' parts',
		'Is Local': isLocalhost(hostname) ? 'Yes' : 'No',
	};
}

function getSecurityInfo(url) {
	const isSecure = url.protocol === 'https:';
	const hasWWW = url.hostname.startsWith('www.');
	const hasEncoding = hasEncodedChars(url.href);
	const hasSuspicious = checkSuspiciousPatterns(url.href);
	const hasIntlChars = hasInternationalChars(url.href);

	return {
		HTTPS: isSecure ? '✅ Secure' : '❌ Insecure',
		'WWW Prefix': hasWWW ? '✅ Yes' : '❌ No',
		'URL Encoding': hasEncoding ? '⚠️ Present' : '✅ Clean',
		Suspicious: hasSuspicious ? '⚠️ Detected' : '✅ Clean',
		'Intl. Chars': hasIntlChars ? '🌐 Present' : '✅ ASCII',
		'Standard Port': isStandardPort(url) ? '✅ Yes' : '⚠️ Custom',
	};
}

function isLocalhost(hostname) {
	return (
		hostname === 'localhost' ||
		hostname === '127.0.0.1' ||
		hostname.endsWith('.local')
	);
}

function isStandardPort(url) {
	return (
		(url.protocol === 'https:' &&
			(url.port === '' || url.port === '443')) ||
		(url.protocol === 'http:' && (url.port === '' || url.port === '80'))
	);
}

function hasEncodedChars(urlString) {
	return /%[0-9A-Fa-f]{2}/.test(urlString);
}

function hasInternationalChars(urlString) {
	return /[^\x00-\x7F]/.test(urlString);
}

function checkSuspiciousPatterns(urlString) {
	const suspicious = [
		/bit\.ly|tinyurl|t\.co/i,
		/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/,
		/[а-яё]/i,
		/-{4,}/,
		/[0-9]{10,}/,
	];
	return suspicious.some((pattern) => pattern.test(urlString));
}

function displayResults(analysis) {
	hideLoading();
	hideError();

	document.getElementById('basicContent').innerHTML = createResultItems(
		analysis.basic
	);
	document.getElementById('componentsContent').innerHTML = createResultItems(
		analysis.components
	);
	document.getElementById('domainContent').innerHTML = createResultItems(
		analysis.domain
	);
	document.getElementById('securityContent').innerHTML = createResultItems(
		analysis.security
	);

	resultsContainer.style.display = 'block';
}

function createResultItems(data) {
	return Object.entries(data)
		.map(([label, value]) => {
			const statusClass = getStatusClass(value);
			return `
					<div class="result-item">
						<span class="result-label">${label}:</span>
						<span class="result-value ${statusClass}">${value}</span>
					</div>
				`;
		})
		.join('');
}

function getStatusClass(value) {
	if (typeof value === 'string') {
		if (value.includes('✅') || value.includes('Secure'))
			return 'status-good';
		if (value.includes('⚠️') || value.includes('Custom'))
			return 'status-warning';
		if (value.includes('❌') || value.includes('Insecure'))
			return 'status-bad';
	}
	return '';
}

function showLoading() {
	loading.style.display = 'block';
	resultsContainer.style.display = 'none';
	hideError();
	analyzeBtn.disabled = true;
}

function hideLoading() {
	loading.style.display = 'none';
	analyzeBtn.disabled = false;
}

function showError(message) {
	hideLoading();
	errorMessage.textContent = message;
	errorMessage.style.display = 'block';
	resultsContainer.style.display = 'none';
}

function hideError() {
	errorMessage.style.display = 'none';
}

function clearResults() {
	resultsContainer.style.display = 'none';
	hideError();
}

function analyzeExample(url) {
	urlInput.value = url;
	analyzeURL();
}
