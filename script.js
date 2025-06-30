class URLAnalyzer {
	constructor() {
		this.urlInput = document.getElementById('urlInput');
		this.analyzeBtn = document.getElementById('analyzeBtn');
		this.resultsContainer = document.getElementById('resultsContainer');
		this.loading = document.getElementById('loading');
		this.errorMessage = document.getElementById('errorMessage');

		this.initEventListeners();
	}

	initEventListeners() {
		this.analyzeBtn.addEventListener('click', () => this.analyzeURL());
		this.urlInput.addEventListener('keypress', (e) => {
			if (e.key === 'Enter') this.analyzeURL();
		});
		this.urlInput.addEventListener('input', () => this.clearResults());
	}

	analyzeURL() {
		const urlString = this.urlInput.value.trim();

		if (!urlString) {
			this.showError('Please enter a URL to analyze');
			return;
		}

		this.showLoading();

		setTimeout(() => {
			try {
				const analysis = this.performAnalysis(urlString);
				this.displayResults(analysis);
			} catch (error) {
				this.showError(error.message);
			}
		}, 600);
	}

	performAnalysis(urlString) {
		if (
			!urlString.match(/^https?:\/\//i) &&
			!urlString.match(/^ftp:\/\//i)
		) {
			urlString = 'https://' + urlString;
		}

		let url;
		try {
			url = new URL(urlString);
		} catch (error) {
			throw new Error(
				'Invalid URL format. Please check your URL and try again.'
			);
		}

		return {
			original: urlString,
			url: url,
			basic: this.getBasicInfo(url),
			components: this.getURLComponents(url),
			domain: this.getDomainInfo(url),
			security: this.getSecurityInfo(url),
		};
	}

	getBasicInfo(url) {
		return {
			Website: url.hostname,
			Protocol: url.protocol.replace(':', '').toUpperCase(),
			Port: url.port || (url.protocol === 'https:' ? '443' : '80'),
			Path: url.pathname === '/' ? 'Root' : url.pathname,
			'Query Params': new URLSearchParams(url.search).size || 'None',
			Fragment: url.hash ? url.hash.substring(1) : 'None',
		};
	}

	getURLComponents(url) {
		const pathSegments = url.pathname
			.split('/')
			.filter((segment) => segment);
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

	getDomainInfo(url) {
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
			'Is Local': this.isLocalhost(hostname) ? 'Yes' : 'No',
		};
	}

	getSecurityInfo(url) {
		const isSecure = url.protocol === 'https:';
		const hasWWW = url.hostname.startsWith('www.');
		const hasEncoding = this.hasEncodedChars(url.href);
		const hasSuspicious = this.checkSuspiciousPatterns(url.href);
		const hasIntlChars = this.hasInternationalChars(url.href);

		return {
			HTTPS: isSecure ? '✅ Secure' : '❌ Insecure',
			'WWW Prefix': hasWWW ? '✅ Yes' : '❌ No',
			'URL Encoding': hasEncoding ? '⚠️ Present' : '✅ Clean',
			Suspicious: hasSuspicious ? '⚠️ Detected' : '✅ Clean',
			'Intl. Chars': hasIntlChars ? '🌐 Present' : '✅ ASCII',
			'Standard Port': this.isStandardPort(url) ? '✅ Yes' : '⚠️ Custom',
		};
	}

	isLocalhost(hostname) {
		return (
			hostname === 'localhost' ||
			hostname === '127.0.0.1' ||
			hostname.endsWith('.local')
		);
	}

	isStandardPort(url) {
		return (
			(url.protocol === 'https:' &&
				(url.port === '' || url.port === '443')) ||
			(url.protocol === 'http:' && (url.port === '' || url.port === '80'))
		);
	}

	hasEncodedChars(urlString) {
		return /%[0-9A-Fa-f]{2}/.test(urlString);
	}

	hasInternationalChars(urlString) {
		return /[^\x00-\x7F]/.test(urlString);
	}

	checkSuspiciousPatterns(urlString) {
		const suspicious = [
			/bit\.ly|tinyurl|t\.co/i,
			/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/,
			/[а-яё]/i,
			/-{4,}/,
			/[0-9]{10,}/,
		];

		return suspicious.some((pattern) => pattern.test(urlString));
	}

	displayResults(analysis) {
		this.hideLoading();
		this.hideError();

		document.getElementById('basicContent').innerHTML =
			this.createResultItems(analysis.basic);
		document.getElementById('componentsContent').innerHTML =
			this.createResultItems(analysis.components);
		document.getElementById('domainContent').innerHTML =
			this.createResultItems(analysis.domain);
		document.getElementById('securityContent').innerHTML =
			this.createResultItems(analysis.security);

		this.resultsContainer.style.display = 'block';
	}

	createResultItems(data) {
		return Object.entries(data)
			.map(([label, value]) => {
				const statusClass = this.getStatusClass(value);
				return `
                            <div class="result-item">
                                <span class="result-label">${label}:</span>
                                <span class="result-value ${statusClass}">${value}</span>
                            </div>
                        `;
			})
			.join('');
	}

	getStatusClass(value) {
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

	showLoading() {
		this.loading.style.display = 'block';
		this.resultsContainer.style.display = 'none';
		this.hideError();
		this.analyzeBtn.disabled = true;
	}

	hideLoading() {
		this.loading.style.display = 'none';
		this.analyzeBtn.disabled = false;
	}

	showError(message) {
		this.hideLoading();
		this.errorMessage.textContent = message;
		this.errorMessage.style.display = 'block';
		this.resultsContainer.style.display = 'none';
	}

	hideError() {
		this.errorMessage.style.display = 'none';
	}

	clearResults() {
		this.resultsContainer.style.display = 'none';
		this.hideError();
	}
}

function analyzeExample(url) {
	document.getElementById('urlInput').value = url;
	urlAnalyzer.analyzeURL();
}

// Initialize the app
const urlAnalyzer = new URLAnalyzer();
