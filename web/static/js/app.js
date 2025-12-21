// Simplified app.js for streaming interface only

// DOM Elements
const outputDiv = document.getElementById('output');

// Add output to the terminal (kept for compatibility)
function addOutput(text, type = 'info') {
    if (!outputDiv) return;
    
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

// Execute a command (stub for compatibility)
function executeCommand(command) {
    console.log('Command execution is not available in streaming-only mode:', command);
}

// Update recent commands list (stub for compatibility)
function updateRecentCommands() {
    // Not applicable in streaming-only mode
}

// Show pre-scan modal (stub for compatibility)
function showPreScanModal(data) {
    // Not applicable in streaming-only mode
}

// Event Listeners
document.addEventListener('DOMContentLoaded', function() {
    // Initialize any components needed for the streaming interface
    console.log('Streaming interface initialized');
});