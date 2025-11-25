// Enhanced Phishing Monitor Dashboard - Dual Feed System
class EnhancedPhishingMonitor {
    constructor() {
        // Application state
        this.ws = null;
        this.isConnected = false;
        this.isPaused = false;
        this.startTime = Date.now();
        
        // Feed-specific state
        this.certstreamPaused = false;
        this.opensquatEnabled = true;
        this.opensquatInterval = 20; // minutes
        this.opensquatTimer = null;
        
        // Statistics
        this.stats = {
            certsProcessed: 0,
            certstreamMatched: 0,
            opensquatFound: 0,
            totalThreats: 0,
            alertsSent: 0
        };

        // Data storage
        this.storageKeys = {
            monitoredDomains: 'enhanced_monitor_domains',
            emailSettings: 'enhanced_monitor_email',
            threatHistory: 'enhanced_monitor_threats',
            appSettings: 'enhanced_monitor_settings',
            opensquatUsage: 'enhanced_monitor_opensquat_usage',
            certstreamData: 'enhanced_monitor_certstream',
            opensquatData: 'enhanced_monitor_opensquat_data'
        };

        // Configuration
        this.certstreamUrl = 'wss://certstream.calidog.io/';
        this.opensquatApi = 'https://api.domainsec.io/v1/free/keyword/';
        this.similarityThresholds = {
            high: 0.9,
            medium: 0.75,
            low: 0.6
        };

        // Active filter for threats display
        this.activeFilter = 'all';

        this.init();
    }

    init() {
        this.loadStoredData();
        this.setupEventListeners();
        this.setupEmailJS();
        this.connectToCertstream();
        this.startOpensquatMonitoring();
        this.startUptimeCounter();
        this.updateUI();
        this.resetDailyUsage();
    }

    loadStoredData() {
        // Load monitored domains
        this.monitoredDomains = JSON.parse(
            localStorage.getItem(this.storageKeys.monitoredDomains) || '[]'
        );

        // Load email settings
        this.emailSettings = JSON.parse(
            localStorage.getItem(this.storageKeys.emailSettings) || '{}'
        );

        // Load threat history
        this.threatHistory = JSON.parse(
            localStorage.getItem(this.storageKeys.threatHistory) || '[]'
        );

        // Load app settings
        this.appSettings = JSON.parse(
            localStorage.getItem(this.storageKeys.appSettings) || 
            '{"similarityThreshold": 0.75, "autoAlerts": true, "soundAlerts": true, "certstreamFiltering": true}'
        );

        // Load opensquat usage
        this.opensquatUsage = JSON.parse(
            localStorage.getItem(this.storageKeys.opensquatUsage) || 
            '{"count": 0, "date": "", "lastCheck": ""}'
        );

        // Load feed data
        this.certstreamData = JSON.parse(
            localStorage.getItem(this.storageKeys.certstreamData) || '[]'
        );
        
        this.opensquatData = JSON.parse(
            localStorage.getItem(this.storageKeys.opensquatData) || '[]'
        );
    }

    saveData(key, data) {
        localStorage.setItem(key, JSON.stringify(data));
    }

    setupEventListeners() {
        // Domain form submission
        document.getElementById('domain-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.addDomain();
        });

        // Settings modal
        document.getElementById('settings-btn').addEventListener('click', () => {
            this.showModal('settings-modal');
        });

        document.getElementById('close-settings').addEventListener('click', () => {
            this.hideModal('settings-modal');
        });

        // Threat detail modal
        document.getElementById('close-threat-detail').addEventListener('click', () => {
            this.hideModal('threat-detail-modal');
        });

        // Modal backdrop clicks
        document.querySelectorAll('.modal-backdrop').forEach(backdrop => {
            backdrop.addEventListener('click', (e) => {
                const modal = e.target.closest('.modal');
                this.hideModal(modal.id);
            });
        });

        // Settings tabs
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                this.switchTab(e.target.dataset.tab);
            });
        });

        // Email settings form
        document.getElementById('email-settings-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.saveEmailSettings();
        });

        // Test email button
        document.getElementById('test-email').addEventListener('click', () => {
            this.sendTestEmail();
        });

        // Feed controls
        document.getElementById('pause-certstream').addEventListener('click', () => {
            this.toggleCertstreamFeed();
        });

        document.getElementById('clear-certstream').addEventListener('click', () => {
            this.clearCertstreamFeed();
        });

        document.getElementById('refresh-opensquat').addEventListener('click', () => {
            this.manualOpensquatCheck();
        });

        document.getElementById('clear-opensquat').addEventListener('click', () => {
            this.clearOpensquatFeed();
        });

        // Threat filters
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                this.setThreatFilter(e.target.dataset.filter);
            });
        });

        // Settings controls
        document.getElementById('similarity-threshold').addEventListener('input', (e) => {
            document.getElementById('threshold-value').textContent = 
                Math.round(e.target.value * 100) + '%';
            this.appSettings.similarityThreshold = parseFloat(e.target.value);
            this.saveData(this.storageKeys.appSettings, this.appSettings);
        });

        document.getElementById('opensquat-interval').addEventListener('change', (e) => {
            this.opensquatInterval = parseInt(e.target.value);
            this.restartOpensquatMonitoring();
        });

        // Checkbox settings
        ['auto-alerts', 'sound-alerts', 'certstream-filtering', 'opensquat-enabled'].forEach(id => {
            document.getElementById(id).addEventListener('change', (e) => {
                const setting = id.replace('-', '').replace('-', '');
                this.appSettings[setting] = e.target.checked;
                if (id === 'opensquat-enabled') {
                    this.opensquatEnabled = e.target.checked;
                    if (e.target.checked) {
                        this.startOpensquatMonitoring();
                    } else {
                        this.stopOpensquatMonitoring();
                    }
                }
                this.saveData(this.storageKeys.appSettings, this.appSettings);
            });
        });

        // Export buttons
        ['export-threats', 'export-certstream', 'export-opensquat', 'export-domains', 'export-logs'].forEach(id => {
            document.getElementById(id).addEventListener('click', () => {
                const type = id.replace('export-', '');
                this.exportData(type);
            });
        });

        document.getElementById('export-data').addEventListener('click', () => {
            this.exportData('all');
        });

        document.getElementById('clear-all-data').addEventListener('click', () => {
            this.clearAllData();
        });

        document.getElementById('reset-usage').addEventListener('click', () => {
            this.resetOpensquatUsage();
        });
    }

    setupEmailJS() {
        if (this.emailSettings.publicKey) {
            emailjs.init(this.emailSettings.publicKey);
            this.updateEmailStatus(true);
        }
    }

    connectToCertstream() {
        this.logActivity('Connecting to Certstream...', 'info');
        
        try {
            this.ws = new WebSocket(this.certstreamUrl);
            
            this.ws.onopen = () => {
                this.isConnected = true;
                this.updateConnectionStatus('certstream', true);
                this.logActivity('Connected to Certstream', 'success');
            };

            this.ws.onmessage = (event) => {
                if (!this.certstreamPaused && this.appSettings.certstreamFiltering) {
                    this.processCertificate(JSON.parse(event.data));
                }
            };

            this.ws.onclose = () => {
                this.isConnected = false;
                this.updateConnectionStatus('certstream', false);
                this.logActivity('Disconnected from Certstream', 'error');
                
                // Attempt to reconnect after 5 seconds
                setTimeout(() => {
                    if (!this.isConnected) {
                        this.connectToCertstream();
                    }
                }, 5000);
            };

            this.ws.onerror = (error) => {
                this.logActivity('Certstream connection error', 'error');
                console.error('WebSocket error:', error);
            };

        } catch (error) {
            this.logActivity('Failed to connect to Certstream', 'error');
            console.error('Connection error:', error);
        }
    }

    processCertificate(data) {
        if (data.message_type !== 'certificate_update') return;

        const cert = data.data;
        if (!cert.leaf_cert || !cert.leaf_cert.subject) return;

        const domains = cert.leaf_cert.all_domains || [];
        this.stats.certsProcessed++;

        domains.forEach(domain => {
            const cleanDomain = domain.replace(/^\*\./, '').toLowerCase();
            const matchResult = this.isDomainMatch(cleanDomain);
            if (matchResult.match) {
                this.stats.certstreamMatched++;
                this.addToCertstreamFeed(cleanDomain, cert, matchResult);
                this.checkForThreat(cleanDomain, 'certstream', matchResult, cert);
            }
        });

        this.updateStats();
    }

    isDomainMatch(certificateDomain) {
        let bestMatch = { match: false, score: 0, type: 'none', keyword: '' };

        for (const monitoredDomain of this.monitoredDomains) {
            // 1. Exact match
            if (certificateDomain === monitoredDomain) {
                return { match: true, score: 1.0, type: 'exact', keyword: monitoredDomain };
            }
            
            // 2. Substring match
            if (certificateDomain.includes(monitoredDomain) || monitoredDomain.includes(certificateDomain)) {
                const score = 0.9;
                if (score > bestMatch.score) {
                    bestMatch = { match: true, score, type: 'substring', keyword: monitoredDomain };
                }
            }
            
            // 3. Similarity match (typosquatting detection)
            const similarity = this.calculateLevenshteinSimilarity(certificateDomain, monitoredDomain);
            if (similarity >= this.appSettings.similarityThreshold && similarity > bestMatch.score) {
                bestMatch = { match: true, score: similarity, type: 'similar', keyword: monitoredDomain };
            }
        }

        return bestMatch;
    }

    calculateLevenshteinSimilarity(str1, str2) {
        const matrix = [];
        const len1 = str1.length;
        const len2 = str2.length;

        for (let i = 0; i <= len2; i++) {
            matrix[i] = [i];
        }

        for (let j = 0; j <= len1; j++) {
            matrix[0][j] = j;
        }

        for (let i = 1; i <= len2; i++) {
            for (let j = 1; j <= len1; j++) {
                if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
                    matrix[i][j] = matrix[i - 1][j - 1];
                } else {
                    matrix[i][j] = Math.min(
                        matrix[i - 1][j - 1] + 1,
                        matrix[i][j - 1] + 1,
                        matrix[i - 1][j] + 1
                    );
                }
            }
        }

        const maxLength = Math.max(len1, len2);
        return maxLength === 0 ? 1 : (maxLength - matrix[len2][len1]) / maxLength;
    }

    addToCertstreamFeed(domain, cert, matchResult) {
        const feed = document.getElementById('certstream-feed');
        const entry = document.createElement('div');
        
        const threatLevel = this.calculateThreatLevel(matchResult.score);
        entry.className = `threat-item threat-${threatLevel} new-item`;
        
        const now = new Date().toLocaleTimeString();
        const issuer = cert.leaf_cert.issuer ? cert.leaf_cert.issuer.CN || 'Unknown' : 'Unknown';
        
        entry.innerHTML = `
            <div class="threat-source source-certstream">Certstream</div>
            <div class="threat-domain">${domain}</div>
            <div class="threat-details">
                Match: ${matchResult.keyword} (${matchResult.type}, ${Math.round(matchResult.score * 100)}%)<br>
                Issuer: ${issuer}<br>
                Detected: ${now}
            </div>
            <div class="threat-meta">
                <span class="threat-similarity">${Math.round(matchResult.score * 100)}% similar</span>
                <span>${now}</span>
            </div>
        `;

        entry.addEventListener('click', () => {
            this.showThreatDetail({
                domain,
                source: 'certstream',
                matchResult,
                certificate: cert,
                detectedAt: now
            });
        });

        // Remove empty state if present
        const emptyState = feed.querySelector('.empty-state');
        if (emptyState) {
            emptyState.remove();
        }

        feed.insertBefore(entry, feed.firstChild);

        // Store in certstream data
        this.certstreamData.unshift({
            domain,
            matchResult,
            certificate: cert,
            timestamp: Date.now(),
            threatLevel
        });

        // Limit feed to 100 entries
        while (feed.children.length > 100) {
            feed.removeChild(feed.lastChild);
        }
        
        // Limit stored data
        if (this.certstreamData.length > 100) {
            this.certstreamData = this.certstreamData.slice(0, 100);
        }
        
        this.saveData(this.storageKeys.certstreamData, this.certstreamData);
    }

    startOpensquatMonitoring() {
        if (!this.opensquatEnabled || this.monitoredDomains.length === 0) return;

        this.stopOpensquatMonitoring(); // Clear any existing timer
        
        const intervalMs = this.opensquatInterval * 60 * 1000;
        
        // Initial check after 30 seconds
        setTimeout(() => {
            this.performOpensquatCheck();
        }, 30000);
        
        // Set up periodic checks
        this.opensquatTimer = setInterval(() => {
            this.performOpensquatCheck();
        }, intervalMs);

        this.updateNextCheckTime();
        this.logActivity(`Opensquat monitoring started (${this.opensquatInterval}min intervals)`, 'info');
    }

    stopOpensquatMonitoring() {
        if (this.opensquatTimer) {
            clearInterval(this.opensquatTimer);
            this.opensquatTimer = null;
        }
    }

    restartOpensquatMonitoring() {
        this.stopOpensquatMonitoring();
        this.startOpensquatMonitoring();
    }

    async performOpensquatCheck() {
        if (!this.opensquatEnabled || this.monitoredDomains.length === 0) return;
        
        if (this.opensquatUsage.count >= 5) {
            this.logActivity('Opensquat daily limit reached (5/5)', 'warning');
            this.updateConnectionStatus('opensquat', 'warning');
            return;
        }

        this.logActivity('Running Opensquat check...', 'info');
        this.updateConnectionStatus('opensquat', true);
        
        for (const domain of this.monitoredDomains) {
            if (this.opensquatUsage.count >= 5) break;
            
            try {
                const response = await fetch(`${this.opensquatApi}${domain}`);
                if (response.ok) {
                    const data = await response.json();
                    this.processOpensquatResults(data, domain);
                    this.incrementOpensquatUsage();
                } else {
                    this.logActivity(`Opensquat API error for ${domain}: ${response.status}`, 'error');
                }
                
                // Add delay between requests to be respectful
                await new Promise(resolve => setTimeout(resolve, 1000));
                
            } catch (error) {
                this.logActivity(`Opensquat API error for ${domain}: ${error.message}`, 'error');
                console.error('Opensquat API error:', error);
            }
        }
        
        this.opensquatUsage.lastCheck = new Date().toISOString();
        this.saveData(this.storageKeys.opensquatUsage, this.opensquatUsage);
        this.updateOpensquatUI();
        this.updateNextCheckTime();
    }

    processOpensquatResults(data, originalDomain) {
        if (!data.domains || data.domains.length === 0) return;

        data.domains.forEach(suspiciousDomain => {
            // Check if we already have this domain
            const existingThreat = this.threatHistory.find(t => 
                t.domain === suspiciousDomain && t.source === 'opensquat'
            );
            
            if (!existingThreat) {
                this.stats.opensquatFound++;
                const similarity = this.calculateLevenshteinSimilarity(suspiciousDomain, originalDomain);
                const threatLevel = this.calculateThreatLevel(similarity);
                
                this.addToOpensquatFeed(suspiciousDomain, originalDomain, similarity, threatLevel);
                this.checkForThreat(suspiciousDomain, 'opensquat', {
                    score: similarity,
                    keyword: originalDomain,
                    type: 'opensquat'
                });
            }
        });
    }

    addToOpensquatFeed(domain, originalDomain, similarity, threatLevel) {
        const feed = document.getElementById('opensquat-feed');
        const entry = document.createElement('div');
        
        entry.className = `threat-item threat-${threatLevel} new-item`;
        
        const now = new Date().toLocaleTimeString();
        
        entry.innerHTML = `
            <div class="threat-source source-opensquat">Opensquat</div>
            <div class="threat-domain">${domain}</div>
            <div class="threat-details">
                Similar to: ${originalDomain}<br>
                Newly registered domain<br>
                Detected: ${now}
            </div>
            <div class="threat-meta">
                <span class="threat-similarity">${Math.round(similarity * 100)}% similar</span>
                <span>${now}</span>
            </div>
        `;

        entry.addEventListener('click', () => {
            this.showThreatDetail({
                domain,
                source: 'opensquat',
                originalDomain,
                similarity,
                threatLevel,
                detectedAt: now
            });
        });

        // Remove empty state if present
        const emptyState = feed.querySelector('.empty-state');
        if (emptyState) {
            emptyState.remove();
        }

        feed.insertBefore(entry, feed.firstChild);

        // Store in opensquat data
        this.opensquatData.unshift({
            domain,
            originalDomain,
            similarity,
            threatLevel,
            timestamp: Date.now()
        });

        // Limit stored data
        if (this.opensquatData.length > 100) {
            this.opensquatData = this.opensquatData.slice(0, 100);
        }
        
        this.saveData(this.storageKeys.opensquatData, this.opensquatData);
    }

    checkForThreat(domain, source, matchResult, certificateData = null) {
        const threatLevel = this.calculateThreatLevel(matchResult.score);
        
        if (threatLevel === 'high' || threatLevel === 'medium') {
            const threat = {
                id: Date.now() + Math.random(),
                domain: domain,
                source: source,
                detectedAt: new Date().toISOString(),
                threatLevel: threatLevel,
                similarity: matchResult.score,
                matchedKeyword: matchResult.keyword,
                matchType: matchResult.type,
                certificate: certificateData,
                status: 'active'
            };

            this.addThreat(threat);
            
            if (this.appSettings.autoAlerts && this.emailSettings.serviceId) {
                this.sendAlert(threat);
            }
        }
    }

    calculateThreatLevel(similarity) {
        if (similarity >= this.similarityThresholds.high) return 'high';
        if (similarity >= this.similarityThresholds.medium) return 'medium';
        return 'low';
    }

    addThreat(threat) {
        this.threatHistory.unshift(threat);
        this.stats.totalThreats++;
        this.saveData(this.storageKeys.threatHistory, this.threatHistory);
        this.updateThreatsDisplay();
        this.updateStats();
        this.logActivity(`${threat.threatLevel.toUpperCase()} threat detected from ${threat.source}: ${threat.domain}`, 'error');
        
        // Play sound if enabled
        if (this.appSettings.soundAlerts) {
            this.playNotificationSound();
        }
    }

    addDomain() {
        const input = document.getElementById('domain-input');
        const domain = input.value.trim().toLowerCase();
        
        if (!domain) return;
        
        // Basic domain validation
        if (!/^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*$/.test(domain)) {
            this.logActivity(`Invalid domain format: ${domain}`, 'warning');
            return;
        }
        
        if (this.monitoredDomains.includes(domain)) {
            this.logActivity(`Domain already monitored: ${domain}`, 'warning');
            return;
        }

        this.monitoredDomains.push(domain);
        this.saveData(this.storageKeys.monitoredDomains, this.monitoredDomains);
        this.updateDomainsDisplay();
        this.logActivity(`Added domain to monitoring: ${domain}`, 'success');
        input.value = '';

        // Restart opensquat monitoring if needed
        if (this.opensquatEnabled && this.monitoredDomains.length === 1) {
            this.startOpensquatMonitoring();
        }
    }

    removeDomain(domain) {
        this.monitoredDomains = this.monitoredDomains.filter(d => d !== domain);
        this.saveData(this.storageKeys.monitoredDomains, this.monitoredDomains);
        this.updateDomainsDisplay();
        this.logActivity(`Removed domain from monitoring: ${domain}`, 'info');

        // Stop opensquat monitoring if no domains left
        if (this.monitoredDomains.length === 0) {
            this.stopOpensquatMonitoring();
        }
    }

    setThreatFilter(filter) {
        this.activeFilter = filter;
        
        // Update filter buttons
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        document.querySelector(`[data-filter="${filter}"]`).classList.add('active');
        
        this.updateThreatsDisplay();
    }

    updateThreatsDisplay() {
        const container = document.getElementById('threats-list');
        const count = document.getElementById('threat-count');
        
        let filteredThreats = this.threatHistory.filter(t => t.status === 'active');
        
        // Apply filter
        if (this.activeFilter !== 'all') {
            if (this.activeFilter === 'high') {
                filteredThreats = filteredThreats.filter(t => t.threatLevel === 'high');
            } else {
                filteredThreats = filteredThreats.filter(t => t.source === this.activeFilter);
            }
        }
        
        count.textContent = `${filteredThreats.length} Threats`;
        
        if (filteredThreats.length === 0) {
            container.innerHTML = '<div class="empty-state"><p>No threats match the current filter.</p></div>';
            return;
        }

        container.innerHTML = filteredThreats.slice(0, 20).map(threat => `
            <div class="threat-item threat-${threat.threatLevel}" onclick="monitor.showThreatDetail(${JSON.stringify(threat).replace(/"/g, '&quot;')})">
                <div class="threat-source source-${threat.source}">${threat.source}</div>
                <div class="threat-domain">${threat.domain}</div>
                <div class="threat-details">
                    Matched: ${threat.matchedKeyword} (${threat.matchType})<br>
                    Detected: ${new Date(threat.detectedAt).toLocaleString()}<br>
                    Threat Level: ${threat.threatLevel.toUpperCase()}
                </div>
                <div class="threat-meta">
                    <span class="threat-similarity">${Math.round(threat.similarity * 100)}% similar</span>
                    <button class="btn btn--sm btn--outline" onclick="event.stopPropagation(); monitor.dismissThreat('${threat.id}')">
                        Dismiss
                    </button>
                </div>
            </div>
        `).join('');
    }

    dismissThreat(threatId) {
        const threat = this.threatHistory.find(t => t.id == threatId);
        if (threat) {
            threat.status = 'dismissed';
            this.saveData(this.storageKeys.threatHistory, this.threatHistory);
            this.updateThreatsDisplay();
            this.logActivity(`Dismissed threat: ${threat.domain}`, 'info');
        }
    }

    showThreatDetail(threat) {
        const modal = document.getElementById('threat-detail-modal');
        const content = document.getElementById('threat-detail-content');
        
        content.innerHTML = `
            <div class="detail-section">
                <h4>Basic Information</h4>
                <div class="detail-grid">
                    <span class="detail-label">Domain:</span>
                    <span class="detail-value">${threat.domain}</span>
                    <span class="detail-label">Source:</span>
                    <span class="detail-value">${threat.source}</span>
                    <span class="detail-label">Threat Level:</span>
                    <span class="detail-value">${threat.threatLevel}</span>
                    <span class="detail-label">Similarity:</span>
                    <span class="detail-value">${Math.round((threat.similarity || 0) * 100)}%</span>
                    <span class="detail-label">Matched Keyword:</span>
                    <span class="detail-value">${threat.matchedKeyword || 'N/A'}</span>
                    <span class="detail-label">Match Type:</span>
                    <span class="detail-value">${threat.matchType || 'N/A'}</span>
                    <span class="detail-label">Detected At:</span>
                    <span class="detail-value">${new Date(threat.detectedAt || Date.now()).toLocaleString()}</span>
                </div>
            </div>
            ${threat.certificate ? `
                <div class="detail-section">
                    <h4>Certificate Information</h4>
                    <div class="detail-grid">
                        <span class="detail-label">Issuer:</span>
                        <span class="detail-value">${threat.certificate.leaf_cert?.issuer?.CN || 'Unknown'}</span>
                        <span class="detail-label">Serial Number:</span>
                        <span class="detail-value">${threat.certificate.leaf_cert?.serial_number || 'Unknown'}</span>
                        <span class="detail-label">Not Before:</span>
                        <span class="detail-value">${threat.certificate.leaf_cert?.not_before || 'Unknown'}</span>
                        <span class="detail-label">Not After:</span>
                        <span class="detail-value">${threat.certificate.leaf_cert?.not_after || 'Unknown'}</span>
                    </div>
                </div>
            ` : ''}
        `;
        
        this.showModal('threat-detail-modal');
    }

    async manualOpensquatCheck() {
        if (this.opensquatUsage.count >= 5) {
            this.logActivity('Cannot perform manual check: daily limit reached', 'warning');
            return;
        }
        
        await this.performOpensquatCheck();
    }

    toggleCertstreamFeed() {
        this.certstreamPaused = !this.certstreamPaused;
        const btn = document.getElementById('pause-certstream');
        btn.textContent = this.certstreamPaused ? '▶️ Resume' : '⏸️ Pause';
        this.logActivity(`Certstream feed ${this.certstreamPaused ? 'paused' : 'resumed'}`, 'info');
    }

    clearCertstreamFeed() {
        document.getElementById('certstream-feed').innerHTML = 
            '<div class="empty-state"><p>Waiting for matching certificates...</p><p class="feed-note">Only certificates matching your monitored domains will appear here.</p></div>';
        this.certstreamData = [];
        this.saveData(this.storageKeys.certstreamData, this.certstreamData);
        this.logActivity('Certstream feed cleared', 'info');
    }

    clearOpensquatFeed() {
        document.getElementById('opensquat-feed').innerHTML = 
            '<div class="empty-state"><p>No Opensquat data yet...</p><p class="feed-note">Newly registered suspicious domains will appear here.</p></div>';
        this.opensquatData = [];
        this.saveData(this.storageKeys.opensquatData, this.opensquatData);
        this.logActivity('Opensquat feed cleared', 'info');
    }

    incrementOpensquatUsage() {
        this.opensquatUsage.count++;
        this.opensquatUsage.date = new Date().toDateString();
        this.saveData(this.storageKeys.opensquatUsage, this.opensquatUsage);
        this.updateOpensquatUI();
    }

    resetDailyUsage() {
        const today = new Date().toDateString();
        if (this.opensquatUsage.date !== today) {
            this.opensquatUsage.count = 0;
            this.opensquatUsage.date = today;
            this.saveData(this.storageKeys.opensquatUsage, this.opensquatUsage);
        }
    }

    resetOpensquatUsage() {
        this.opensquatUsage.count = 0;
        this.opensquatUsage.date = new Date().toDateString();
        this.saveData(this.storageKeys.opensquatUsage, this.opensquatUsage);
        this.updateOpensquatUI();
        this.updateConnectionStatus('opensquat', true);
        this.logActivity('Opensquat usage counter reset', 'info');
    }

    updateOpensquatUI() {
        document.getElementById('opensquat-usage').textContent = `${this.opensquatUsage.count}/5`;
        document.getElementById('opensquat-last-check').textContent = 
            this.opensquatUsage.lastCheck ? 
            new Date(this.opensquatUsage.lastCheck).toLocaleTimeString() : 'Never';
        document.getElementById('current-usage').textContent = `${this.opensquatUsage.count}/5`;
        document.getElementById('opensquat-found').textContent = this.stats.opensquatFound;
    }

    updateNextCheckTime() {
        const intervalMs = this.opensquatInterval * 60 * 1000;
        const nextCheck = new Date(Date.now() + intervalMs);
        document.getElementById('next-check').textContent = nextCheck.toLocaleTimeString();
    }

    updateDomainsDisplay() {
        const container = document.getElementById('domains-list');
        const count = document.getElementById('domains-count');
        
        count.textContent = this.monitoredDomains.length;
        
        container.innerHTML = this.monitoredDomains.map(domain => `
            <div class="domain-item">
                <span class="domain-name">${domain}</span>
                <button class="remove-domain" onclick="monitor.removeDomain('${domain}')">
                    ✕
                </button>
            </div>
        `).join('');
    }

    updateStats() {
        document.getElementById('certstream-processed').textContent = this.stats.certsProcessed;
        document.getElementById('certstream-matched').textContent = this.stats.certstreamMatched;
        document.getElementById('certstream-stats').textContent = this.stats.certstreamMatched;
        document.getElementById('opensquat-stats').textContent = this.stats.opensquatFound;
        document.getElementById('total-threats').textContent = this.stats.totalThreats;
        document.getElementById('alerts-sent').textContent = this.stats.alertsSent;
    }

    startUptimeCounter() {
        setInterval(() => {
            const uptime = Date.now() - this.startTime;
            const hours = Math.floor(uptime / 3600000);
            const minutes = Math.floor((uptime % 3600000) / 60000);
            const seconds = Math.floor((uptime % 60000) / 1000);
            
            const uptimeDisplay = document.getElementById('uptime');
            if (uptimeDisplay) {
                uptimeDisplay.textContent = 
                    `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
            }
        }, 1000);
    }

    updateConnectionStatus(service, status) {
        const indicator = document.getElementById(`${service}-status`);
        if (indicator) {
            let className = 'status-dot ';
            if (status === true) className += 'status-online';
            else if (status === 'warning') className += 'status-warning';
            else className += 'status-offline';
            indicator.className = className;
        }
    }

    updateEmailStatus(configured) {
        const indicator = document.getElementById('email-status');
        indicator.className = `status-dot ${configured ? 'status-online' : 'status-offline'}`;
    }

    logActivity(message, type = 'info') {
        const feed = document.getElementById('activity-feed');
        const item = document.createElement('div');
        item.className = `activity-item activity-${type}`;
        
        const time = new Date().toLocaleTimeString();
        item.innerHTML = `
            <span class="activity-time">${time}</span>
            <span class="activity-message">${message}</span>
        `;
        
        feed.insertBefore(item, feed.firstChild);
        
        // Limit to 50 items
        while (feed.children.length > 50) {
            feed.removeChild(feed.lastChild);
        }
    }

    showModal(modalId) {
        document.getElementById(modalId).classList.remove('hidden');
        if (modalId === 'settings-modal') {
            this.loadEmailSettings();
            this.loadAppSettings();
        }
    }

    hideModal(modalId) {
        document.getElementById(modalId).classList.add('hidden');
    }

    switchTab(tabName) {
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
        
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });
        document.getElementById(`${tabName}-tab`).classList.add('active');
    }

    saveEmailSettings() {
        this.emailSettings = {
            serviceId: document.getElementById('emailjs-service').value,
            templateId: document.getElementById('emailjs-template').value,
            publicKey: document.getElementById('emailjs-key').value,
            alertEmail: document.getElementById('alert-email').value
        };

        this.saveData(this.storageKeys.emailSettings, this.emailSettings);
        
        if (this.emailSettings.publicKey) {
            emailjs.init(this.emailSettings.publicKey);
            this.updateEmailStatus(true);
        }

        this.logActivity('Email settings saved', 'success');
    }

    loadEmailSettings() {
        if (this.emailSettings.serviceId) {
            document.getElementById('emailjs-service').value = this.emailSettings.serviceId;
        }
        if (this.emailSettings.templateId) {
            document.getElementById('emailjs-template').value = this.emailSettings.templateId;
        }
        if (this.emailSettings.publicKey) {
            document.getElementById('emailjs-key').value = this.emailSettings.publicKey;
        }
        if (this.emailSettings.alertEmail) {
            document.getElementById('alert-email').value = this.emailSettings.alertEmail;
        }
    }

    loadAppSettings() {
        document.getElementById('similarity-threshold').value = this.appSettings.similarityThreshold;
        document.getElementById('threshold-value').textContent = 
            Math.round(this.appSettings.similarityThreshold * 100) + '%';
        document.getElementById('auto-alerts').checked = this.appSettings.autoAlerts;
        document.getElementById('sound-alerts').checked = this.appSettings.soundAlerts;
        document.getElementById('certstream-filtering').checked = this.appSettings.certstreamFiltering;
        document.getElementById('opensquat-enabled').checked = this.opensquatEnabled;
        document.getElementById('opensquat-interval').value = this.opensquatInterval;
    }

    async sendAlert(threat) {
        if (!this.emailSettings.serviceId || !this.emailSettings.alertEmail) return;

        try {
            const templateParams = {
                to_email: this.emailSettings.alertEmail,
                threat_domain: threat.domain,
                source: threat.source,
                matched_keyword: threat.matchedKeyword,
                threat_level: threat.threatLevel.toUpperCase(),
                similarity_score: Math.round(threat.similarity * 100) + '%',
                detection_time: new Date(threat.detectedAt).toLocaleString(),
                dashboard_url: window.location.href
            };

            await emailjs.send(
                this.emailSettings.serviceId,
                this.emailSettings.templateId,
                templateParams
            );

            this.stats.alertsSent++;
            this.logActivity(`Email alert sent for ${threat.domain}`, 'success');
        } catch (error) {
            this.logActivity('Failed to send email alert', 'error');
            console.error('Email error:', error);
        }
    }

    async sendTestEmail() {
        if (!this.emailSettings.serviceId || !this.emailSettings.alertEmail) {
            this.logActivity('Email settings incomplete', 'error');
            return;
        }

        try {
            const templateParams = {
                to_email: this.emailSettings.alertEmail,
                threat_domain: 'test-phishing-domain.com',
                source: 'test',
                matched_keyword: 'test-keyword',
                threat_level: 'TEST ALERT',
                similarity_score: '95%',
                detection_time: new Date().toLocaleString(),
                dashboard_url: window.location.href
            };

            await emailjs.send(
                this.emailSettings.serviceId,
                this.emailSettings.templateId,
                templateParams
            );

            this.logActivity('Test email sent successfully', 'success');
        } catch (error) {
            this.logActivity('Test email failed', 'error');
            console.error('Test email error:', error);
        }
    }

    exportData(type) {
        let data, filename;
        
        switch (type) {
            case 'threats':
                data = this.threatHistory;
                filename = 'all_threats_export.json';
                break;
            case 'certstream':
                data = this.certstreamData;
                filename = 'certstream_data.json';
                break;
            case 'opensquat':
                data = this.opensquatData;
                filename = 'opensquat_data.json';
                break;
            case 'domains':
                data = this.monitoredDomains;
                filename = 'monitored_domains.json';
                break;
            case 'logs':
                data = Array.from(document.querySelectorAll('.activity-item')).map(item => ({
                    time: item.querySelector('.activity-time').textContent,
                    message: item.querySelector('.activity-message').textContent,
                    type: Array.from(item.classList).find(c => c.startsWith('activity-'))
                }));
                filename = 'activity_logs.json';
                break;
            case 'all':
                data = {
                    threats: this.threatHistory,
                    certstream: this.certstreamData,
                    opensquat: this.opensquatData,
                    domains: this.monitoredDomains,
                    stats: this.stats,
                    settings: this.appSettings,
                    usage: this.opensquatUsage,
                    exportTime: new Date().toISOString()
                };
                filename = 'enhanced_dashboard_export.json';
                break;
        }
        
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
        
        this.logActivity(`Data exported: ${filename}`, 'info');
    }

    clearAllData() {
        if (confirm('Are you sure you want to clear all data? This cannot be undone.')) {
            Object.values(this.storageKeys).forEach(key => {
                localStorage.removeItem(key);
            });
            
            this.monitoredDomains = [];
            this.threatHistory = [];
            this.certstreamData = [];
            this.opensquatData = [];
            this.stats = { certsProcessed: 0, certstreamMatched: 0, opensquatFound: 0, totalThreats: 0, alertsSent: 0 };
            this.opensquatUsage = { count: 0, date: '', lastCheck: '' };
            
            this.updateUI();
            this.clearCertstreamFeed();
            this.clearOpensquatFeed();
            this.logActivity('All data cleared', 'warning');
        }
    }

    playNotificationSound() {
        try {
            const audioContext = new (window.AudioContext || window.webkitAudioContext)();
            const oscillator = audioContext.createOscillator();
            const gainNode = audioContext.createGain();
            
            oscillator.connect(gainNode);
            gainNode.connect(audioContext.destination);
            
            oscillator.frequency.setValueAtTime(800, audioContext.currentTime);
            oscillator.frequency.setValueAtTime(600, audioContext.currentTime + 0.1);
            
            gainNode.gain.setValueAtTime(0.3, audioContext.currentTime);
            gainNode.gain.setValueAtTime(0, audioContext.currentTime + 0.2);
            
            oscillator.start(audioContext.currentTime);
            oscillator.stop(audioContext.currentTime + 0.2);
        } catch (error) {
            console.log('Audio notification not available');
        }
    }

    updateUI() {
        this.updateDomainsDisplay();
        this.updateThreatsDisplay();
        this.updateStats();
        this.updateOpensquatUI();
    }
}

// Initialize the enhanced application
const monitor = new EnhancedPhishingMonitor();

// Global functions for event handlers
window.monitor = monitor;