/**
 * Stream Handler for CyberSec-CLI Web Interface
 * Handles Server-Sent Events (SSE) for real-time scan results
 */

class StreamHandler {
    constructor() {
        this.eventSource = null;
        this.isConnected = false;
        this.scanResults = {
            critical: [],
            high: [],
            medium: [],
            low: []
        };
        this.totalPorts = 0;
        this.scannedPorts = 0;
        this.isCancelled = false;
    }

    /**
     * Start streaming scan results
     * @param {string} target - Target to scan
     * @param {string} ports - Ports to scan (e.g., "1-1000" or "80,443,8080")
     * @param {boolean} enhancedDetection - Whether to use enhanced service detection
     */
    startStream(target, ports = "1-1000", enhancedDetection = true) {
        // Close any existing connection
        this.close();

        // Reset state
        this.isCancelled = false;
        this.scanResults = {
            critical: [],
            high: [],
            medium: [],
            low: []
        };
        this.totalPorts = 0;
        this.scannedPorts = 0;


        // Build URL with parameters
        const url = new URL('/api/scan/stream', window.location.origin);
        url.searchParams.append('target', target);
        url.searchParams.append('ports', ports);
        url.searchParams.append('enhanced_service_detection', enhancedDetection);

        try {
            // Create EventSource connection
            this.eventSource = new EventSource(url.toString());
            this.isConnected = true;

            // Set up event listeners
            this.eventSource.onmessage = (event) => {
                if (this.isCancelled) return;
                
                try {
                    const data = JSON.parse(event.data);
                    this.handleEvent(data);
                } catch (error) {
                    console.error('Error parsing SSE event:', error);
                }
            };

            this.eventSource.onerror = (error) => {
                if (this.isCancelled) return;
                
                console.error('SSE connection error:', error);
                this.handleError('Connection error occurred');
                this.close();
            };

            this.eventSource.onopen = () => {
                console.log('SSE connection opened');
                // Show the indicator only once the connection is established
                this.showScanningIndicator();
            };

        } catch (error) {
            console.error('Error creating EventSource:', error);
            this.handleError('Failed to start streaming');
        }
    }

    /**
     * Handle incoming SSE events
     * @param {Object} data - Event data
     */
    handleEvent(data) {
        switch (data.type) {
            case 'scan_start':
                this.handleScanStart(data);
                break;
            case 'group_start':
                this.handleGroupStart(data);
                break;
            case 'tier_results':
                this.handleTierResults(data);
                break;
            case 'critical_ports':
                this.handleCriticalPorts(data);
                break;
            case 'group_complete':
                this.handleGroupComplete(data);
                break;
            case 'scan_complete':
                this.handleScanComplete(data);
                break;
            case 'error':
                this.handleError(data.message);
                break;
            default:
                console.warn('Unknown event type:', data.type);
        }
    }

    /**
     * Handle scan start event
     * @param {Object} data - Event data
     */
    handleScanStart(data) {
        this.totalPorts = data.total_ports;
        this.updateProgress(0);
        this.updateStatus(`Starting scan on ${data.target} (${this.totalPorts} ports)`);
    }

    /**
     * Handle group start event
     * @param {Object} data - Event data
     */
    handleGroupStart(data) {
        this.updateStatus(`Scanning ${data.priority} priority ports (${data.count} ports)`);
        this.updateProgress(data.progress);
    }

    /**
     * Handle tier results event
     * @param {Object} data - Event data
     */
    handleTierResults(data) {
        // Add ports to appropriate priority group
        if (data.open_ports && data.open_ports.length > 0) {
            data.open_ports.forEach(port => {
                this.scanResults[data.priority].push(port);
            });
            
            // Update UI with new results
            this.renderPriorityGroup(data.priority, data.open_ports);
        }
        
        this.updateProgress(data.progress);
    }

    /**
     * Handle critical ports event
     * @param {Object} data - Event data
     */
    handleCriticalPorts(data) {
        // This is sent at the end with all critical ports found
        if (data.ports && data.ports.length > 0) {
            // Highlight critical ports section
            const criticalSection = document.getElementById('critical-ports-section');
            if (criticalSection) {
                criticalSection.classList.add('highlight');
                setTimeout(() => {
                    criticalSection.classList.remove('highlight');
                }, 3000);
            }
        }
    }

    /**
     * Handle group complete event
     * @param {Object} data - Event data
     */
    handleGroupComplete(data) {
        this.updateProgress(data.progress);
        this.updateStatus(`${data.priority.charAt(0).toUpperCase() + data.priority.slice(1)} priority scan complete (${data.open_count} open ports)`);
    }

    /**
     * Handle scan complete event
     * @param {Object} data - Event data
     */
    handleScanComplete(data) {
        this.updateProgress(100);
        this.updateStatus('Scan completed');
        this.close();
        
        // Show completion message
        const completionMsg = document.getElementById('scan-completion-message');
        if (completionMsg) {
            completionMsg.classList.remove('hidden');
            setTimeout(() => {
                completionMsg.classList.add('hidden');
            }, 5000);
        }
    }

    /**
     * Handle error event
     * @param {string} message - Error message
     */
    handleError(message) {
        this.updateStatus(`Error: ${message}`, 'error');
        this.close();
    }

    /**
     * Render a priority group of ports
     * @param {string} priority - Priority level (critical, high, medium, low)
     * @param {Array} ports - Array of port objects
     */
    renderPriorityGroup(priority, ports) {
        const containerId = `${priority}-ports-container`;
        const container = document.getElementById(containerId);
        
        if (!container) {
            console.warn(`Container not found: ${containerId}`);
            return;
        }

        // Create or update the ports grid for this priority
        let grid = container.querySelector('.ports-grid');
        if (!grid) {
            grid = document.createElement('div');
            grid.className = 'ports-grid grid grid-cols-1 gap-4 mt-4';
            container.appendChild(grid);
        }

        // Add new ports to the grid
        ports.forEach(port => {
            const portCard = this.createPortCard(port, priority);
            grid.appendChild(portCard);
        });
        
        // If this is the critical priority and we have ports, show the critical ports section
        if (priority === 'critical' && ports.length > 0) {
            const criticalSection = document.getElementById('critical-ports-section');
            if (criticalSection) {
                criticalSection.classList.remove('hidden');
            }
        }

        // Show the container if it was hidden
        container.classList.remove('hidden');
    }

    /**
     * Create a port card element
     * @param {Object} port - Port information
     * @param {string} priority - Priority level
     * @returns {HTMLElement} Port card element
     */
    createPortCard(port, priority) {
        const card = document.createElement('div');
        
        // Use the port's risk level if available, otherwise use priority
        const riskLevel = port.risk ? port.risk.toLowerCase() : priority.toLowerCase();
        
        card.className = `port-card bg-gray-800 rounded-lg overflow-hidden border-l-4 ${this.getPortSeverityClass(riskLevel)}`;
        
        // Port header
        const header = document.createElement('div');
        header.className = 'px-4 py-3 bg-gray-700 flex flex-wrap justify-between items-center';
        
        const portInfo = document.createElement('div');
        portInfo.className = 'flex items-center';
        portInfo.textContent = `Port ${port.port} ${riskLevel.toUpperCase()}${port.protocol ? ' ' + port.protocol.toUpperCase() : ''}`;
        
        const serviceInfo = document.createElement('span');
        serviceInfo.className = 'text-sm text-gray-300';
        serviceInfo.textContent = port.service || 'Unknown Service';
        
        header.appendChild(portInfo);
        header.appendChild(serviceInfo);
        
        // Port details
        const details = document.createElement('div');
        details.className = 'p-4';
        
        const service = this.escapeHtml(port.service || 'Unknown');
        const version = this.escapeHtml(port.version || 'Not detected');
        const exposure = port.exposure ? this.escapeHtml(port.exposure) : '';
        
        let detailsHtml = `
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                <div>
                    <p class="text-sm text-gray-400">Service</p>
                    <p class="font-mono break-all">${service}</p>
                </div>
                <div>
                    <p class="text-sm text-gray-400">Version</p>
                    <p class="font-mono break-all">${version}</p>
                </div>
                ${port.cvss_score ? `
                <div>
                    <p class="text-sm text-gray-400">CVSS Score</p>
                    <p class="font-mono break-all">${port.cvss_score.toFixed(1)}/10</p>
                </div>` : ''}
                ${exposure ? `
                <div>
                    <p class="text-sm text-gray-400">Exposure</p>
                    <p class="font-mono break-all">${exposure}</p>
                </div>` : ''}
        `;
        
        if (port.banner) {
            detailsHtml += `
                <div class="md:col-span-2">
                    <p class="text-sm text-gray-400">Banner</p>
                    <pre class="font-mono text-xs bg-gray-900 p-2 rounded overflow-x-auto whitespace-pre-wrap break-all">${this.escapeHtml(port.banner)}</pre>
                </div>
            `;
        }
        
        // Add vulnerabilities if any
        if (port.vulnerabilities && port.vulnerabilities.length > 0) {
            detailsHtml += `
                <div class="md:col-span-2">
                    <p class="text-sm font-medium text-red-400 mb-2">
                        <i class="fas fa-shield-alt mr-1"></i> Known Vulnerabilities
                    </p>
                    <ul class="list-disc list-inside text-sm text-gray-300 space-y-1 pl-4">
                        ${port.vulnerabilities.map(vuln => 
                            `<li class="break-words">${this.escapeHtml(vuln)}</li>`
                        ).join('')}
                    </ul>
                </div>`;
        }

        // Add MITRE ATT&CK techniques if present
        if (port.mitre_attack && port.mitre_attack.length > 0) {
            detailsHtml += `
                <div class="md:col-span-2">
                    <p class="text-sm font-medium text-indigo-400 mb-2">
                        <i class="fas fa-bullseye mr-1"></i> MITRE ATT&CK
                    </p>
                    <div class="flex flex-wrap gap-2">
                        ${port.mitre_attack.map(tid => `
                            <span class="px-2 py-1 text-xs bg-indigo-900 text-indigo-100 rounded-full border border-indigo-700">
                                ${this.escapeHtml(tid)}
                            </span>`).join('')}
                    </div>
                </div>`;
        }

        // TLS details
        if (port.tls) {
            detailsHtml += `
                <div class="md:col-span-2 grid grid-cols-1 md:grid-cols-2 gap-4 mt-2">
                    <div>
                        <p class="text-sm text-gray-400">TLS Version</p>
                        <p class="font-mono break-all">${this.escapeHtml(port.tls.tls_version || 'Unknown')}</p>
                    </div>
                    <div>
                        <p class="text-sm text-gray-400">Cipher Suite</p>
                        <p class="font-mono break-all">${this.escapeHtml(port.tls.cipher_suite || 'Unknown')}</p>
                    </div>
                    ${port.tls.error ? `<div class="md:col-span-2 text-sm text-yellow-400">TLS Inspection Error: ${this.escapeHtml(port.tls.error)}</div>` : ''}
                </div>`;
        }

        // HTTP inspection details
        if (port.http) {
            if (port.http.error) {
                detailsHtml += `
                    <div class="md:col-span-2 mt-3 text-sm text-yellow-400">
                        <i class="fas fa-globe mr-1"></i> HTTP Inspection Error: ${this.escapeHtml(port.http.error)}
                    </div>`;
            } else {
                const audit = port.http.security_headers_audit || {};
                const missingHeaders = Object.entries(audit)
                    .filter(([, status]) => status === 'missing' || status === 'weak')
                    .map(([name, status]) => `${name} (${status})`);
                const cspWarnings = port.http.csp_warnings || [];
                const corsWarnings = port.http.cors_warnings || [];
                detailsHtml += `
                    <div class="md:col-span-2 mt-3">
                        <p class="text-sm font-medium text-blue-300 mb-1">
                            <i class="fas fa-globe mr-1"></i> HTTP Inspection
                        </p>
                        <p class="text-sm text-gray-300">Status: ${port.http.status_code || 'N/A'} | HTTP ${port.http.http_version || ''}</p>
                        <p class="text-sm text-gray-300">Security Score: ${port.http.security_score ?? 'N/A'}</p>
                        ${missingHeaders.length ? `<p class="text-sm text-yellow-400 mt-1">Missing/Weak: ${missingHeaders.join(', ')}</p>` : ''}
                        ${cspWarnings.length ? `<p class="text-sm text-yellow-400 mt-1">CSP: ${cspWarnings.join('; ')}</p>` : ''}
                        ${corsWarnings.length ? `<p class="text-sm text-yellow-400 mt-1">CORS: ${corsWarnings.join('; ')}</p>` : ''}
                        ${port.http.directory_listing ? `<p class="text-sm text-red-400 mt-1">Directory listing detected</p>` : ''}
                        ${port.http.forms_over_http ? `<p class="text-sm text-yellow-400 mt-1">Forms submit over HTTP</p>` : ''}
                    </div>`;

            }
        }
        
        // Add default credentials warning if present
        if (port.default_creds) {
            detailsHtml += `
                <div class="md:col-span-2">
                    <p class="text-sm font-medium text-yellow-400 mb-2">
                        <i class="fas fa-exclamation-triangle mr-1"></i> Default Credentials Warning
                    </p>
                    <p class="text-sm text-gray-300">${this.escapeHtml(port.default_creds)}</p>
                </div>`;
        }
        
        // Add recommendations
        if (port.recommendations && port.recommendations.length > 0) {
            detailsHtml += `
                <div class="md:col-span-2 mt-4 pt-4 border-t border-gray-700">
                    <p class="text-sm font-medium text-blue-400 mb-2">
                        <i class="fas fa-lightbulb mr-1"></i> Security Recommendations
                    </p>
                    <ul class="space-y-2">
                        ${port.recommendations.filter(rec => rec.trim()).map(rec => `
                            <li class="flex items-start">
                                <span class="text-green-400 mr-2 mt-1 flex-shrink-0">✓</span>
                                <span class="text-sm break-words">${this.escapeHtml(rec)}</span>
                            </li>
                        `).join('')}
                    </ul>
                </div>`;
        }
        
        detailsHtml += '</div>';
        details.innerHTML = detailsHtml;
        
        card.appendChild(header);
        card.appendChild(details);
        
        return card;
    }

    /**
     * Get CSS class for port severity
     * @param {string} riskLevel - Risk level
     * @returns {string} CSS class
     */
    getPortSeverityClass(riskLevel) {
        switch (riskLevel.toLowerCase()) {
            case 'critical': return 'border-red-600';
            case 'high': return 'border-red-500';
            case 'medium': return 'border-yellow-500';
            case 'low': return 'border-blue-400';
            case 'info': return 'border-blue-300';
            default: return 'border-gray-500';
        }
    }

    /**
     * Get CSS class for risk badge
     * @param {string} riskLevel - Risk level
     * @returns {string} CSS class
     */
    getRiskBadgeClass(riskLevel) {
        switch (riskLevel.toLowerCase()) {
            case 'critical': return '!bg-red-700 !text-white';
            case 'high': return '!bg-red-600 !text-white';
            case 'medium': return '!bg-yellow-500 !text-gray-900';
            case 'low': return '!bg-blue-500 !text-white';
            case 'info': return '!bg-blue-400 !text-white';
            default: return '!bg-gray-500 !text-white';
        }
    }

    /**
     * Escape HTML to prevent XSS
     * @param {string} unsafe - Unsafe string
     * @returns {string} Escaped string
     */
    escapeHtml(unsafe) {
        return (unsafe || '')
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    /**
     * Update progress bar
     * @param {number} percentage - Progress percentage
     */
    updateProgress(percentage) {
        const progressBar = document.getElementById('scanProgressBar') || document.getElementById('scan-progress-bar');
        const progressText = document.getElementById('scanProgressPercent') || document.getElementById('scan-progress-text');

        if (progressBar) {
            progressBar.style.width = `${percentage}%`;
            progressBar.setAttribute('aria-valuenow', percentage);
        }

        if (progressText) {
            progressText.textContent = `${percentage}%`;
        }
    }

    /**
     * Update status text
     * @param {string} message - Status message
     * @param {string} type - Message type (info, error, success)
     */
    updateStatus(message, type = 'info') {
        const statusElement = document.getElementById('statusText') || document.getElementById('scan-status');
        if (statusElement) {
            statusElement.textContent = message;
            statusElement.className = type === 'error' ? 'status-error' : type === 'success' ? 'status-complete' : 'status-scanning';
        }
    }

    /**
     * Show scanning indicator
     */
    showScanningIndicator() {
        const indicator = document.getElementById('scanProgress') || document.getElementById('scanning-indicator');
        if (indicator) {
            indicator.classList.remove('hidden');
            // reset progress
            const pb = document.getElementById('scanProgressBar');
            const pct = document.getElementById('scanProgressPercent');
            if (pb) pb.style.width = '0%';
            if (pct) pct.textContent = '0%';
        }
    }

    /**
     * Hide scanning indicator
     */
    hideScanningIndicator() {
        const indicator = document.getElementById('scanProgress') || document.getElementById('scanning-indicator');
        if (indicator) {
            indicator.classList.add('hidden');
        }
    }

    /**
     * Cancel the current scan
     */
    cancel() {
        this.isCancelled = true;
        this.close();
        this.hideScanningIndicator();
        this.updateStatus('Scan cancelled', 'error');
    }

    /**
     * Close the EventSource connection
     */
    close() {
        if (this.eventSource) {
            this.eventSource.close();
            this.eventSource = null;
            this.isConnected = false;
        }
        this.hideScanningIndicator();
    }
}

// Export for use in other modules
window.StreamHandler = StreamHandler;
