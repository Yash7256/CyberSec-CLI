function renderPortScanResults(data) {
    console.log('Rendering port scan data:', data); // Debug log
    // Create main container
    const container = document.createElement('div');
    container.className = 'port-scan-results space-y-6';

    // Add scan summary
    const summary = document.createElement('div');
    summary.className = 'bg-gray-800 p-4 rounded-lg border-l-4 border-blue-500';
    summary.innerHTML = `
        <h3 class="text-xl font-semibold text-blue-400 mb-3">🔍 Port Scan Summary</h3>
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <div class="bg-gray-900 p-3 rounded">
                <p class="text-gray-400 text-sm">Target</p>
                <p class="text-white font-mono break-all">${data.target || 'N/A'}</p>
            </div>
            <div class="bg-gray-900 p-3 rounded">
                <p class="text-gray-400 text-sm">Scan Type</p>
                <p class="text-white">${data.scanType || 'N/A'}</p>
            </div>
            <div class="bg-gray-900 p-3 rounded">
                <p class="text-gray-400 text-sm">Timestamp</p>
                <p class="text-white">${new Date().toLocaleString()}</p>
            </div>
            <div class="bg-gray-900 p-3 rounded">
                <p class="text-gray-400 text-sm">Ports Scanned</p>
                <p class="text-white">${data.portsScanned || 0}</p>
            </div>
            <div class="bg-gray-900 p-3 rounded">
                <p class="text-gray-400 text-sm">Open Ports</p>
                <p class="text-green-400 font-bold">${data.openPorts ? data.openPorts.length : 0}</p>
            </div>
            <div class="bg-gray-900 p-3 rounded">
                <p class="text-gray-400 text-sm">Closed Ports</p>
                <p class="text-red-400">${data.closedPorts || 0}</p>
            </div>
        </div>
    `;
    container.appendChild(summary);

    // Add open ports section if there are any open ports
    if (data.openPorts && data.openPorts.length > 0) {
        const openPortsSection = document.createElement('div');
        openPortsSection.className = 'mt-6';
        openPortsSection.innerHTML = `
            <h3 class="text-lg font-semibold text-green-400 mb-3 flex items-center">
                <i class="fas fa-door-open mr-2"></i>
                Open Ports (${data.openPorts.length} found)
            </h3>
        `;

        // Create ports grid
        const portsGrid = document.createElement('div');
        portsGrid.className = 'grid grid-cols-1 gap-4';

        // Add each open port
        data.openPorts.forEach(port => {
            if (!port.port) return; // Skip invalid port entries
            
            // Create port card with proper styling
            const portCard = document.createElement('div');
            portCard.className = `port-card bg-gray-800 rounded-lg overflow-hidden border-l-4 ${getPortSeverityClass(port.risk)}`;
            portCard.style.borderLeftWidth = '4px'; // Ensure border is visible
            portCard.style.borderLeftStyle = 'solid';
            
            // Port header
            const header = document.createElement('div');
            header.className = 'px-4 py-3 bg-gray-700 flex flex-wrap justify-between items-center';

            // Create risk badge with inline styles to ensure they're applied
            let riskBadge = '';
            if (port.risk) {
                const riskLevel = (port.risk || '').toLowerCase();
                let bgColor = 'bg-gray-500';
                let textColor = 'text-white';
                
                if (riskLevel.includes('critical')) {
                    bgColor = 'bg-red-700';
                } else if (riskLevel.includes('high')) {
                    bgColor = 'bg-red-600';
                } else if (riskLevel.includes('medium')) {
                    bgColor = 'bg-yellow-500';
                    textColor = 'text-gray-900';
                } else if (riskLevel.includes('low')) {
                    bgColor = 'bg-blue-500';
                } else if (riskLevel.includes('info')) {
                    bgColor = 'bg-blue-400';
                }
                
                riskBadge = `
                <span class="ml-3 px-3 py-1 text-xs font-bold rounded-full ${bgColor} ${textColor} risk-badge" 
                      style="background-color: var(--${bgColor.replace('bg-', '')}) !important;">
                    ${port.risk.toUpperCase()}
                </span>`;
            }          
            // Create protocol badge
            let protocolBadge = '';
            if (port.protocol) {
                protocolBadge = `
                <span class="ml-2 px-3 py-1 text-xs bg-blue-900 text-blue-200 rounded-full">
                    ${port.protocol.toUpperCase()}
                </span>`;
            }
            
            header.innerHTML = `
                <div class="flex items-center mb-1 sm:mb-0">
                    <span class="font-mono font-bold text-lg">Port ${port.port}</span>
                    ${riskBadge}
                    ${protocolBadge}
                </div>
                <span class="text-sm text-gray-300">${port.service || 'Unknown Service'}</span>
            `;
            portCard.appendChild(header);

            // Port details
            const details = document.createElement('div');
            details.className = 'p-4';
            
            let detailsHtml = `
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                    <div>
                        <p class="text-sm text-gray-400">Service</p>
                        <p class="font-mono break-all">${port.service || 'Unknown'}</p>
                    </div>
                    <div>
                        <p class="text-sm text-gray-400">Version</p>
                        <p class="font-mono break-all">${port.version || 'Not detected'}</p>
                    </div>
                    ${port.state ? `
                    <div>
                        <p class="text-sm text-gray-400">State</p>
                        <p class="font-mono break-all">${port.state}</p>
                    </div>` : ''}
                    ${port.reason ? `
                    <div>
                        <p class="text-sm text-gray-400">Reason</p>
                        <p class="font-mono break-all">${port.reason}</p>
                    </div>` : ''}`;

            // Add banner if available
            if (port.banner) {
                detailsHtml += `
                    <div class="md:col-span-2">
                        <p class="text-sm text-gray-400">Banner</p>
                        <pre class="font-mono text-xs bg-gray-900 p-2 rounded overflow-x-auto whitespace-pre-wrap break-all">${escapeHtml(port.banner)}</pre>
                    </div>`;
            }
            
            detailsHtml += `
                </div>`;

            // Add vulnerabilities if any
            if (port.vulnerabilities && port.vulnerabilities.length > 0) {
                detailsHtml += `
                    <div class="mb-4">
                        <p class="text-sm font-medium text-red-400 mb-2">
                            <i class="fas fa-shield-alt mr-1"></i> Known Vulnerabilities
                        </p>
                        <ul class="list-disc list-inside text-sm text-gray-300 space-y-1 pl-4">
                            ${port.vulnerabilities.map(vuln => 
                                `<li class="break-words">${escapeHtml(vuln)}</li>`
                            ).join('')}
                        </ul>
                    </div>`;
            }

            // Add recommendations
            if (port.recommendations && port.recommendations.length > 0) {
                detailsHtml += `
                    <div class="mt-4 pt-4 border-t border-gray-700">
                        <p class="text-sm font-medium text-blue-400 mb-2">
                            <i class="fas fa-lightbulb mr-1"></i> Recommendations
                        </p>
                        <ul class="space-y-2">
                            ${port.recommendations.map(rec => `
                                <li class="flex items-start">
                                    <span class="text-green-400 mr-2 mt-1 flex-shrink-0">✓</span>
                                    <span class="text-sm break-words">${escapeHtml(rec)}</span>
                                </li>
                            `).join('')}
                        </ul>
                    </div>`;
            }

            details.innerHTML = detailsHtml;
            portCard.appendChild(details);
            portsGrid.appendChild(portCard);
        });

        openPortsSection.appendChild(portsGrid);
        container.appendChild(openPortsSection);
    } else {
        // Show message if no open ports found
        const noPortsMsg = document.createElement('div');
        noPortsMsg.className = 'mt-6 p-4 bg-gray-800 rounded-lg text-center';
        noPortsMsg.innerHTML = `
            <p class="text-gray-400">
                <i class="fas fa-info-circle mr-2"></i>
                No open ports found on the target.
            </p>
        `;
        container.appendChild(noPortsMsg);
    }

    return container;
}

// Helper function to escape HTML
function escapeHtml(unsafe) {
    return (unsafe || '')
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function getPortSeverityClass(risk) {
    const riskLevel = (risk || '').toLowerCase();
    if (riskLevel.includes('critical')) return 'border-red-600';
    if (riskLevel.includes('high')) return 'border-red-500';
    if (riskLevel.includes('medium')) return 'border-yellow-500';
    if (riskLevel.includes('low')) return 'border-blue-400';
    if (riskLevel.includes('info')) return 'border-blue-300';
    return 'border-gray-500';
}

function getRiskBadgeClass(risk) {
    const riskLevel = (risk || '').toLowerCase();
    
    if (riskLevel.includes('critical')) 
        return '!bg-red-700 !text-white hover:!bg-red-800';
    if (riskLevel.includes('high')) 
        return '!bg-red-600 !text-white hover:!bg-red-700';
    if (riskLevel.includes('medium')) 
        return '!bg-yellow-500 !text-gray-900 hover:!bg-yellow-600';
    if (riskLevel.includes('low')) 
        return '!bg-blue-500 !text-white hover:!bg-blue-600';
    if (riskLevel.includes('info'))
        return '!bg-blue-400 !text-white hover:!bg-blue-500';
        
    return '!bg-gray-500 !text-white';
}

// Example usage removed
// NOTE: Demo/example data (previously containing ggits.org and 21 ports) was
// intentionally removed to avoid showing or implying scans of third-party
// websites. The renderer expects real scan data from the backend WebSocket
// or API and will render results dynamically when actual scan output is
// received.
