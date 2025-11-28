// WebSocket connection
let socket;
let isConnected = false;
let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 5;
const RECONNECT_DELAY = 3000; // 3 seconds
const commandHistory = [];
let historyIndex = -1;

// DOM Elements
const commandInput = document.getElementById('commandInput');
const outputDiv = document.getElementById('output');
const wsStatus = document.getElementById('wsStatus');
const recentCommandsList = document.getElementById('recentCommands');
const lastCommandSpan = document.getElementById('lastCommand');
const responseTimeSpan = document.getElementById('responseTime');

// Connect to WebSocket
function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
    // Attach token from localStorage if present
    const token = (localStorage.getItem('wsToken') || '').trim();
    const tokenQuery = token ? `?token=${encodeURIComponent(token)}` : '';
    const wsUrl = `${protocol}${window.location.host}/ws/command${tokenQuery}`;
    
    try {
        socket = new WebSocket(wsUrl);
        
        socket.onopen = () => {
            console.log('WebSocket connected');
            isConnected = true;
            reconnectAttempts = 0; // Reset reconnect attempts on successful connection
            wsStatus.textContent = 'Connected';
            wsStatus.className = 'status-connected';
            addOutput('Connected to CyberSec-CLI Web Interface', 'info');
        };
        
        socket.onclose = (event) => {
            console.log(`WebSocket disconnected. Code: ${event.code}, Reason: ${event.reason}`);
            isConnected = false;
            wsStatus.textContent = 'Disconnected';
            wsStatus.className = 'status-disconnected';
            
            // Only show reconnection message if this wasn't an intentional close
            if (event.code !== 1000) { // 1000 is normal closure
                reconnectAttempts++;
                if (reconnectAttempts <= MAX_RECONNECT_ATTEMPTS) {
                    const delay = RECONNECT_DELAY * Math.pow(2, reconnectAttempts - 1); // Exponential backoff
                    addOutput(`Disconnected from server. Attempting to reconnect (${reconnectAttempts}/${MAX_RECONNECT_ATTEMPTS})...`, 'warning');
                    setTimeout(connectWebSocket, delay);
                } else {
                    addOutput('Max reconnection attempts reached. Please refresh the page.', 'error');
                }
            }
        };
        
        socket.onerror = (error) => {
            console.error('WebSocket error:', error);
            wsStatus.textContent = 'Error';
            wsStatus.className = 'status-error';
        };
        
        socket.onmessage = (event) => {
            const now = new Date();
            const timeString = now.toLocaleTimeString();
            let message = event.data;
            
            // Update response time
            if (lastCommandTime) {
                const responseTime = now - lastCommandTime;
                responseTimeSpan.textContent = `${responseTime}ms`;
            }
            
            try {
                // Check if this is a JSON message
                let parsedMessage;
                try {
                    parsedMessage = JSON.parse(message);
                } catch (e) {
                    // Not a JSON message, handle as plain text
                    parsedMessage = null;
                }

                // Handle port scan results
                if (parsedMessage && parsedMessage.type === 'port_scan') {
                    // Clear any previous output for this command
                    outputDiv.querySelectorAll('.port-scan-container').forEach(el => el.remove());
                    
                    // Create a container for the port scan results
                    const container = document.createElement('div');
                    container.className = 'port-scan-container';
                    
                    try {
                        // Format the data for the renderer
                        const scanData = {
                            target: parsedMessage.target || 'Unknown target',
                            scanType: parsedMessage.scan_type || 'TCP Connect',
                            portsScanned: parsedMessage.ports_scanned || 0,
                            closedPorts: parsedMessage.closed_ports || 0,
                            openPorts: (parsedMessage.open_ports || []).map(port => ({
                                port: port.port,
                                service: port.service || 'unknown',
                                version: port.version || 'Not detected',
                                banner: port.banner || '',
                                risk: port.risk || 'UNKNOWN',
                                vulnerabilities: port.vulnerabilities || [],
                                recommendations: port.recommendations || []
                            }))
                        };
                        
                        // Render using our component
                        const scanResults = renderPortScanResults(scanData);
                        container.appendChild(scanResults);
                        outputDiv.appendChild(container);
                        
                        // Auto-scroll to show the results
                        container.scrollIntoView({ behavior: 'smooth' });
                        return;
                    } catch (error) {
                        console.error('Error rendering port scan:', error);
                        // Fall back to raw output if parsing fails
                        addOutput('Error rendering port scan results. Showing raw output:', 'error');
                        addOutput(JSON.stringify(parsedMessage, null, 2), 'output');
                        return;
                    }
                }

                // Handle pre-scan warnings (target resolved but not reachable on common ports)
                if (parsedMessage && parsedMessage.type === 'pre_scan_warning') {
                    // If user has already consented for this session, auto-send the force with consent
                    try {
                        const consent = sessionStorage.getItem('preScanConsent');
                        if (consent === 'true') {
                            if (socket && socket.readyState === WebSocket.OPEN) {
                                socket.send(JSON.stringify({ command: parsedMessage.original_command, force: true, consent: true }));
                                addOutput(`Auto-sent forced scan for ${parsedMessage.target} (consent remembered)`, 'warning');
                            } else {
                                addOutput('Unable to auto-send force command — WebSocket disconnected', 'error');
                            }
                            return;
                        }
                    } catch (e) {
                        // sessionStorage may be unavailable in some contexts; fall back to modal
                    }

                    // Show a richer modal confirmation rather than a plain confirm()
                    showPreScanModal(parsedMessage);
                    return;
                }
                
                // Handle plain text messages
                if (!parsedMessage) {
                    // Handle different message types
                    if (message.startsWith('[OUT]')) {
                        addOutput(message.substring(5).trim(), 'output');
                    } else if (message.startsWith('[ERR]')) {
                        addOutput(message.substring(5).trim(), 'error');
                    } else if (message.startsWith('[END]')) {
                        addOutput(message.substring(5).trim(), 'success');
                    } else if (message.trim()) {
                        // Only show non-empty messages
                        addOutput(message, 'info');
                    }
                }
            } catch (error) {
                console.error('Error processing message:', error);
                addOutput('Error processing command output', 'error');
            }
            
            // Auto-scroll to bottom
            outputDiv.scrollTop = outputDiv.scrollHeight;
        };
        
    } catch (error) {
        console.error('Error setting up WebSocket:', error);
        wsStatus.textContent = 'Connection Error';
        wsStatus.className = 'status-error';
        addOutput('Failed to connect to the server. Please check your connection and refresh the page.', 'error');
    }
}

// Add output to the terminal
function addOutput(text, type = 'info') {
    const outputLine = document.createElement('div');
    outputLine.className = `terminal-output terminal-output-${type}`;
    
    // Add timestamp
    const now = new Date();
    const timeString = now.toLocaleTimeString();
    const timeSpan = document.createElement('span');
    timeSpan.className = 'text-gray-500 mr-2';
    timeSpan.textContent = `[${timeString}]`;
    outputLine.appendChild(timeSpan);
    
    // Add the actual message
    const textSpan = document.createElement('span');
    textSpan.textContent = text;
    outputLine.appendChild(textSpan);
    
    outputDiv.appendChild(outputLine);
    
    // Auto-scroll to bottom
    outputDiv.scrollTop = outputDiv.scrollHeight;
}

// Execute a command
let lastCommandTime;

function executeCommand(command) {
    if (!command.trim()) return;
    
    // Add to command history
    commandHistory.unshift(command);
    if (commandHistory.length > 10) {
        commandHistory.pop();
    }
    
    // Update recent commands list
    updateRecentCommands();
    
    // Display the command in the terminal
    addOutput(`$ ${command}`, 'command');
    
    // Send the command via WebSocket
    if (isConnected) {
        lastCommandTime = new Date();
        lastCommandSpan.textContent = command;
        socket.send(JSON.stringify({ command }));
    } else {
        addOutput('Not connected to server', 'error');
    }
    
    // Clear input
    commandInput.value = '';
    historyIndex = -1;
}

// Update recent commands list
function updateRecentCommands() {
    recentCommandsList.innerHTML = '';
    
    if (commandHistory.length === 0) {
        const li = document.createElement('li');
        li.className = 'text-gray-400';
        li.textContent = 'No recent commands';
        recentCommandsList.appendChild(li);
        return;
    }
    
    commandHistory.forEach((cmd, index) => {
        const li = document.createElement('li');
        li.className = 'flex items-center justify-between py-1 px-2 hover:bg-gray-700 rounded cursor-pointer';
        
        const cmdText = document.createElement('span');
        cmdText.className = 'truncate';
        cmdText.textContent = cmd;
        
        const runBtn = document.createElement('button');
        runBtn.className = 'ml-2 text-blue-400 hover:text-blue-300';
        runBtn.innerHTML = '<i class="fas fa-play"></i>';
        runBtn.onclick = (e) => {
            e.stopPropagation();
            executeCommand(cmd);
        };
        
        li.appendChild(cmdText);
        li.appendChild(runBtn);
        
        li.onclick = () => {
            commandInput.value = cmd;
            commandInput.focus();
        };
        
        recentCommandsList.appendChild(li);
    });
}

// Event Listeners
commandInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
        const command = commandInput.value.trim();
        if (command) {
            executeCommand(command);
        }
    } else if (e.key === 'ArrowUp') {
        // Navigate command history
        e.preventDefault();
        if (historyIndex < commandHistory.length - 1) {
            historyIndex++;
            commandInput.value = commandHistory[historyIndex] || '';
        }
    } else if (e.key === 'ArrowDown') {
        // Navigate command history
        e.preventDefault();
        if (historyIndex > 0) {
            historyIndex--;
            commandInput.value = commandHistory[historyIndex] || '';
        } else if (historyIndex === 0) {
            historyIndex = -1;
            commandInput.value = '';
        }
    } else if (e.key === 'Tab') {
        // Tab completion (basic implementation)
        e.preventDefault();
        const input = commandInput.value.trim();
        if (input) {
            // Simple command completion
            const commands = ['scan', 'harden', 'anomaly', 'help'];
            const matching = commands.filter(cmd => cmd.startsWith(input));
            if (matching.length === 1) {
                commandInput.value = matching[0] + ' ';
            }
        }
    }
});

// Quick action buttons
document.querySelectorAll('button[onclick^="executeCommand"]').forEach(btn => {
    btn.onclick = (e) => {
        const command = btn.getAttribute('onclick').match(/'([^']+)'/)[1];
        executeCommand(command);
    };
});

// Settings drawer behavior
const openSettingsBtn = document.getElementById('openSettingsBtn');
const settingsDrawer = document.getElementById('settingsDrawer');
const closeSettingsBtn = document.getElementById('closeSettingsBtn');
const saveSettingsBtn = document.getElementById('saveSettingsBtn');
const wsTokenInput = document.getElementById('wsTokenInput');

function openSettings() {
    settingsDrawer.classList.remove('hidden');
}
function closeSettings() {
    settingsDrawer.classList.add('hidden');
}

openSettingsBtn.addEventListener('click', () => {
    // populate from localStorage
    wsTokenInput.value = localStorage.getItem('wsToken') || '';
    openSettings();
});
closeSettingsBtn.addEventListener('click', closeSettings);
saveSettingsBtn.addEventListener('click', () => {
    const val = wsTokenInput.value.trim();
    if (val) localStorage.setItem('wsToken', val);
    else localStorage.removeItem('wsToken');
    addOutput('Settings saved. Reconnecting WebSocket to apply token...', 'info');
    closeSettings();
    if (socket && socket.readyState === WebSocket.OPEN) socket.close(1000);
    setTimeout(connectWebSocket, 300);
});

// Parse port scan output into structured data
function parsePortScanOutput(output) {
    try {
        const result = {
            target: '',
            scanType: '',
            portsScanned: 0,
            closedPorts: 0,
            openPorts: []
        };

        // Extract scan summary
        const targetMatch = output.match(/🎯 Target: ([^\n]+)/);
        const scanTypeMatch = output.match(/🔍 Scan Type: ([^\n]+)/);
        const portsMatch = output.match(/Scanned (\d+), .*Open: (\d+).*Closed: (\d+)/);

        if (targetMatch) result.target = targetMatch[1].trim();
        if (scanTypeMatch) result.scanType = scanTypeMatch[1].trim();
        if (portsMatch) {
            result.portsScanned = parseInt(portsMatch[1]);
            result.openPortsCount = parseInt(portsMatch[2]);
            result.closedPorts = parseInt(portsMatch[3]);
        }

        // Extract open ports - handle both formats (with and without port sections)
        if (output.includes('╭─ Port ')) {
            // New format with port sections
            const portSections = output.split('╭─ Port ').slice(1);
            
            portSections.forEach(section => {
                const portMatch = section.match(/^(\d+)/);
                if (!portMatch) return;
                
                const port = parseInt(portMatch[1]);
                const portData = {
                    port: port,
                    service: 'Unknown',
                    version: 'Not detected',
                    risk: 'UNKNOWN',
                    banner: '',
                    vulnerabilities: [],
                    recommendations: []
                };

                // Extract service info
                const serviceMatch = section.match(/📌 ([^\n]+)/);
                if (serviceMatch) {
                    portData.service = serviceMatch[1].replace('service detected', '').trim();
                }

                // Extract version if available
                const versionMatch = section.match(/Version: ([^\n]+)/i);
                if (versionMatch) {
                    portData.version = versionMatch[1].trim();
                }

                // Extract risk level
                const riskMatch = section.match(/Risk: ([^\n]+)/i) || 
                                 section.match(/🔢 CVSS: [\d.]+\/10 \(([^)]+)\)/);
                if (riskMatch) {
                    portData.risk = (riskMatch[1] || 'UNKNOWN').toUpperCase();
                }

                // Extract banner
                const bannerMatch = section.match(/Banner: ([^\n]+)/i) || 
                                   section.match(/Banner:\s*\n([\s\S]+?)(?=\n\S|$)/);
                if (bannerMatch) {
                    portData.banner = bannerMatch[1].trim();
                }

                // Extract vulnerabilities
                const vulnSection = section.match(/🚨 Known Vulnerabilities:([\s\S]*?)(?=\n\S|$)/);
                if (vulnSection && vulnSection[1]) {
                    const vulnLines = vulnSection[1].split('\n')
                        .map(line => line.trim())
                        .filter(line => line.startsWith('-'));
                    
                    portData.vulnerabilities = vulnLines.map(v => v.replace(/^[-•*]\s*/, '').trim());
                }

                // Extract recommendations
                const recSection = section.match(/🛡️\s*Recommendations:([\s\S]*?)(?=\n\S|$)/);
                if (recSection && recSection[1]) {
                    portData.recommendations = recSection[1].split('\n')
                        .map(line => line.trim())
                        .filter(line => line.match(/^\d+\./))
                        .map(r => r.replace(/^\d+\.\s*/, '').trim());
                }

                result.openPorts.push(portData);
            });
        } else {
            // Fallback for simple port list format
            const portLines = output.split('\n').filter(line => line.match(/^\d+\/tcp\s+/));
            portLines.forEach(line => {
                const match = line.match(/^(\d+)\/tcp\s+(\S+)/);
                if (match) {
                    result.openPorts.push({
                        port: parseInt(match[1]),
                        service: match[2],
                        version: 'Not detected',
                        risk: 'UNKNOWN',
                        banner: '',
                        vulnerabilities: [],
                        recommendations: []
                    });
                }
            });
        }

        return result;
    } catch (error) {
        console.error('Error parsing port scan output:', error);
        console.error('Output that caused the error:', output);
        return null;
    }
}

// Initialize
connectWebSocket();

// Auto-focus input when clicking anywhere in the terminal
document.getElementById('terminal').addEventListener('click', () => {
    commandInput.focus();
});

// Initial welcome message
addOutput('Type a command or click on the quick actions to get started.', 'info');
addOutput('For example, try: scan --help', 'info');

// --- Pre-scan modal handling ---
function showPreScanModal(data) {
    const modal = document.getElementById('preScanModal');
    const msgEl = document.getElementById('preScanMsg');
    const targetEl = document.getElementById('preScanTarget');
    const ipEl = document.getElementById('preScanIP');
    const detailsEl = document.getElementById('preScanDetails');

    // Populate fields
    msgEl.textContent = data.message || `Target ${data.target} resolved to ${data.ip} but did not respond on common web ports.`;
    targetEl.textContent = data.target || '-';
    ipEl.textContent = data.ip || '-';
    detailsEl.textContent = `The backend performed a quick probe and did not see a response on common web ports (80/443). Only proceed if you have authorization to scan this host.`;

    // Show modal
    modal.classList.remove('hidden');
    modal.classList.add('flex');

    // Wire buttons (one-time attach guard)
    const proceedBtn = document.getElementById('preScanProceed');
    const cancelBtn = document.getElementById('preScanCancel');

    // Remove previous listeners by cloning
    const newProceed = proceedBtn.cloneNode(true);
    proceedBtn.parentNode.replaceChild(newProceed, proceedBtn);
    const newCancel = cancelBtn.cloneNode(true);
    cancelBtn.parentNode.replaceChild(newCancel, cancelBtn);

    newProceed.addEventListener('click', () => {
        // If the user checked 'Don't ask again', persist consent for this session
        const dontAsk = document.getElementById('preScanDontAsk');
        const consentFlag = !!(dontAsk && dontAsk.checked);
        try {
            if (consentFlag) sessionStorage.setItem('preScanConsent', 'true');
        } catch (e) {}

        // Send original command with force:true and include consent flag when set
        if (socket && socket.readyState === WebSocket.OPEN) {
            const payload = { command: data.original_command, force: true };
            if (consentFlag) payload.consent = true;
            socket.send(JSON.stringify(payload));
            addOutput(`User confirmed forced scan for ${data.target}` + (consentFlag ? ' (consent saved for session)' : ''), 'warning');
        } else {
            addOutput('Unable to send force command — WebSocket disconnected', 'error');
        }
        hidePreScanModal();
    });

    newCancel.addEventListener('click', () => {
        addOutput(`Scan aborted by user for ${data.target}`, 'info');
        hidePreScanModal();
    });

    // Close modal on overlay click (optional)
    modal.addEventListener('click', (ev) => {
        if (ev.target === modal) hidePreScanModal();
    }, { once: true });
}

function hidePreScanModal() {
    const modal = document.getElementById('preScanModal');
    modal.classList.remove('flex');
    modal.classList.add('hidden');
}
