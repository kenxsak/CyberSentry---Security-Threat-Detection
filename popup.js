// popup.js - Handles the extension popup UI functionality

// DOM Elements
const elements = {
  loading: document.getElementById('loading'),
  mainContent: document.getElementById('mainContent'),
  statusDot: document.getElementById('statusDot'),
  statusText: document.getElementById('statusText'),
  scanTime: document.getElementById('scanTime'),
  connectionStatus: document.getElementById('connectionStatus'),
  contentStatus: document.getElementById('contentStatus'),
  privacyStatus: document.getElementById('privacyStatus'),
  domainStatus: document.getElementById('domainStatus'),
  threatDetails: document.getElementById('threatDetails'),
  threatsList: document.getElementById('threatsList'),
  detailsButton: document.getElementById('detailsButton'),
  reportButton: document.getElementById('reportButton'),
  tabButtons: document.querySelectorAll('.tab-button'),
  tabContents: document.querySelectorAll('.tab-content'),
  sitesVisited: document.getElementById('sitesVisited'),
  threatsBlocked: document.getElementById('threatsBlocked'),
  vulnerabilitiesFound: document.getElementById('vulnerabilitiesFound'),
  blockThreats: document.getElementById('blockThreats'),
  scanContent: document.getElementById('scanContent'),
  monitorScripts: document.getElementById('monitorScripts'),
  checkForms: document.getElementById('checkForms'),
  showNotifications: document.getElementById('showNotifications'),
  saveSettings: document.getElementById('saveSettings'),
  resetStats: document.getElementById('resetStats')
};

// Threat category display names
const THREAT_CATEGORY_NAMES = {
  'phishing': 'Phishing Attempt',
  'malware': 'Malware Risk',
  'crypto_mining': 'Crypto Mining Script',
  'data_leakage': 'Data Privacy Risk',
  'vulnerable_form': 'Insecure Form',
  'insecure_connection': 'Insecure Connection',
  'suspicious_redirect': 'Suspicious Redirect',
  'known_threat': 'Known Security Threat',
  'content_issue': 'Suspicious Content',
  'SUSPICIOUS_ELEMENT': 'Suspicious Element',
  'unknown': 'Security Risk'
};

// Initialize popup when DOM is loaded
document.addEventListener('DOMContentLoaded', async () => {
  // Show loading state
  showLoading(true);
  
  try {
    // Set up tab navigation
    elements.tabButtons.forEach(button => {
      button.addEventListener('click', () => {
        // Hide all tab contents
        elements.tabContents.forEach(content => {
          content.classList.remove('active');
        });
        
        // Deactivate all tab buttons
        elements.tabButtons.forEach(btn => {
          btn.classList.remove('active');
        });
        
        // Activate the clicked tab
        button.classList.add('active');
        
        // Show the corresponding tab content
        const tabId = button.getAttribute('data-tab');
        document.getElementById(tabId).classList.add('active');
      });
    });
    
    // Load data for the current tab
    await loadTabData();
    
    // Load statistics
    await loadStatistics();
    
    // Load settings
    await loadSettings();
    
    // Set up settings save button
    elements.saveSettings.addEventListener('click', saveSettings);
    
    // Set up reset stats button
    elements.resetStats.addEventListener('click', resetStats);
    
    // Hide loading state
    showLoading(false);
  } catch (error) {
    console.error('Error initializing popup:', error);
    showError('Failed to load security information. Please try again.');
  }
});

// Show or hide loading state
function showLoading(isLoading) {
  elements.loading.style.display = isLoading ? 'flex' : 'none';
  elements.mainContent.style.display = isLoading ? 'none' : 'block';
}

// Show error message
function showError(message) {
  // Hide loading state
  showLoading(false);
  
  // Create error message
  const errorElement = document.createElement('div');
  errorElement.className = 'error-message';
  errorElement.textContent = message;
  
  // Add retry button
  const retryButton = document.createElement('button');
  retryButton.textContent = 'Retry';
  retryButton.addEventListener('click', () => {
    // Remove error message
    errorElement.remove();
    
    // Reload popup
    location.reload();
  });
  
  errorElement.appendChild(retryButton);
  
  // Add to page
  document.body.appendChild(errorElement);
}

// Load security data for the current tab
async function loadTabData() {
  // Get the current tab
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const currentTab = tabs[0];
  
  if (!currentTab || !currentTab.url || !currentTab.url.startsWith('http')) {
    // Not a web page, show default state
    updateSecurityDisplay({ securityLevel: 'unknown' }, { vulnerabilities: [] }, 'Not a web page');
    return;
  }
  
  // Get security information from background script
  chrome.runtime.sendMessage({ action: 'getSecurityInfo', tabId: currentTab.id }, response => {
    if (response) {
      // Get vulnerability information
      chrome.runtime.sendMessage({ action: 'getVulnerabilityInfo', tabId: currentTab.id }, vulnResponse => {
        updateSecurityDisplay(response, vulnResponse || { vulnerabilities: [] }, currentTab.url);
      });
    } else {
      updateSecurityDisplay({ securityLevel: 'unknown' }, { vulnerabilities: [] }, currentTab.url);
    }
  });
}

// Update the security display with the provided data
function updateSecurityDisplay(securityData, vulnerabilityData, url) {
  // Set the scan time
  elements.scanTime.textContent = new Date().toLocaleTimeString();
  
  // Set the overall security status
  let statusText, statusColor;
  
  switch (securityData.securityLevel) {
    case 'dangerous':
      statusText = 'Dangerous';
      statusColor = '#FF0000'; // Red
      break;
    case 'suspicious':
      statusText = 'Suspicious';
      statusColor = '#FFA500'; // Orange
      break;
    case 'warning':
      statusText = 'Warning';
      statusColor = '#FFFF00'; // Yellow
      break;
    case 'safe':
      statusText = 'Safe';
      statusColor = '#00FF00'; // Green
      break;
    default:
      statusText = 'Unknown';
      statusColor = '#808080'; // Gray
  }
  
  // Update status indicators
  elements.statusDot.style.backgroundColor = statusColor;
  elements.statusText.textContent = statusText;
  
  // Set connection status
  if (url.startsWith('https:')) {
    elements.connectionStatus.textContent = 'Secure (HTTPS)';
    elements.connectionStatus.className = 'status-item secure';
  } else if (url.startsWith('http:')) {
    elements.connectionStatus.textContent = 'Not Secure (HTTP)';
    elements.connectionStatus.className = 'status-item warning';
  } else {
    elements.connectionStatus.textContent = 'Unknown';
    elements.connectionStatus.className = 'status-item unknown';
  }
  
  // Set content status based on content security level
  if (securityData.contentSecurityLevel) {
    switch (securityData.contentSecurityLevel) {
      case 'dangerous':
        elements.contentStatus.textContent = 'Dangerous Content';
        elements.contentStatus.className = 'status-item danger';
        break;
      case 'warning':
        elements.contentStatus.textContent = 'Suspicious Content';
        elements.contentStatus.className = 'status-item warning';
        break;
      case 'safe':
        elements.contentStatus.textContent = 'Safe Content';
        elements.contentStatus.className = 'status-item secure';
        break;
      default:
        elements.contentStatus.textContent = 'Unknown';
        elements.contentStatus.className = 'status-item unknown';
    }
  } else {
    elements.contentStatus.textContent = 'Not Scanned';
    elements.contentStatus.className = 'status-item unknown';
  }
  
  // Set privacy status based on detected threats
  const hasPrivacyThreats = securityData.contentThreats && 
                           securityData.contentThreats.some(threat => 
                             threat.category === 'data_leakage' || 
                             threat.category === 'crypto_mining');
  
  if (hasPrivacyThreats) {
    elements.privacyStatus.textContent = 'Privacy Issues';
    elements.privacyStatus.className = 'status-item danger';
  } else {
    elements.privacyStatus.textContent = 'No Privacy Issues';
    elements.privacyStatus.className = 'status-item secure';
  }
  
  // Set domain status
  if (securityData.threatCategory === 'phishing' || securityData.threatCategory === 'known_threat') {
    elements.domainStatus.textContent = 'Dangerous Domain';
    elements.domainStatus.className = 'status-item danger';
  } else if (securityData.threatCategory === 'suspicious_redirect') {
    elements.domainStatus.textContent = 'Suspicious Domain';
    elements.domainStatus.className = 'status-item warning';
  } else {
    elements.domainStatus.textContent = 'Domain OK';
    elements.domainStatus.className = 'status-item secure';
  }
  
  // Display threats if any
  displayThreats(securityData, vulnerabilityData);
}

// Display detected threats
function displayThreats(securityData, vulnerabilityData) {
  // Clear existing threats
  elements.threatsList.innerHTML = '';
  
  // Collect all threats
  const threats = [];
  
  // Add URL/domain threats
  if (securityData.threatCategory) {
    threats.push({
      category: securityData.threatCategory,
      details: securityData.threatDetails || 'Suspicious or dangerous URL detected'
    });
  }
  
  // Add content threats
  if (securityData.contentThreats && securityData.contentThreats.length > 0) {
    threats.push(...securityData.contentThreats);
  }
  
  // Add detected threats
  if (securityData.detectedThreats && securityData.detectedThreats.length > 0) {
    threats.push(...securityData.detectedThreats);
  }
  
  // Add vulnerabilities
  if (vulnerabilityData.vulnerabilities && vulnerabilityData.vulnerabilities.length > 0) {
    vulnerabilityData.vulnerabilities.forEach(vuln => {
      threats.push({
        category: 'vulnerable_form',
        details: vuln.details,
        severity: vuln.severity,
        location: vuln.location
      });
    });
  }
  
  // Show or hide the threats section
  if (threats.length > 0) {
    elements.threatDetails.style.display = 'block';
    
    // Create threat items
    threats.forEach(threat => {
      const threatItem = document.createElement('div');
      threatItem.className = 'threat-item';
      
      // Determine severity class
      let severityClass = 'medium';
      if (threat.severity === 'high' || 
          threat.category === 'phishing' || 
          threat.category === 'malware') {
        severityClass = 'high';
      } else if (threat.severity === 'low') {
        severityClass = 'low';
      }
      
      // Create threat content
      threatItem.innerHTML = `
        <div class="threat-severity ${severityClass}"></div>
        <div class="threat-info">
          <div class="threat-name">${THREAT_CATEGORY_NAMES[threat.category.toLowerCase()] || 'Security Issue'}</div>
          <div class="threat-description">${threat.details || 'No details available'}</div>
          ${threat.location ? `<div class="threat-location">Location: ${threat.location}</div>` : ''}
        </div>
      `;
      
      // Add to the list
      elements.threatsList.appendChild(threatItem);
    });
    
    // Set up details button
    elements.detailsButton.style.display = 'inline-block';
    elements.detailsButton.addEventListener('click', () => {
      chrome.tabs.create({ url: chrome.runtime.getURL('threat_details.html') });
    });
    
    // Set up report button
    elements.reportButton.style.display = 'inline-block';
    elements.reportButton.addEventListener('click', () => {
      // In a real extension, this would report to a security service
      alert('Thank you for reporting this threat. Our security team will investigate.');
    });
  } else {
    elements.threatDetails.style.display = 'none';
    elements.detailsButton.style.display = 'none';
    elements.reportButton.style.display = 'none';
  }
}

// Load security statistics
async function loadStatistics() {
  chrome.runtime.sendMessage({ action: 'getStats' }, response => {
    if (response) {
      // Update statistics display
      elements.sitesVisited.textContent = response.sitesVisited || 0;
      elements.threatsBlocked.textContent = response.threatsBlocked || 0;
      elements.vulnerabilitiesFound.textContent = response.vulnerabilitiesFound || 0;
      
      // In a real extension, we might display a chart of threats by category here
    } else {
      console.error('Failed to load statistics');
    }
  });
}

// Load user settings
async function loadSettings() {
  chrome.storage.local.get('securitySettings', data => {
    if (data.securitySettings) {
      const settings = data.securitySettings;
      
      // Update checkboxes
      elements.blockThreats.checked = settings.blockThreats !== false;
      elements.scanContent.checked = settings.scanContent !== false;
      elements.monitorScripts.checked = settings.monitorScripts !== false;
      elements.checkForms.checked = settings.checkForms !== false;
      elements.showNotifications.checked = settings.showNotifications !== false;
    } else {
      // Default all settings to enabled
      elements.blockThreats.checked = true;
      elements.scanContent.checked = true;
      elements.monitorScripts.checked = true;
      elements.checkForms.checked = true;
      elements.showNotifications.checked = true;
    }
  });
}

// Save user settings
async function saveSettings() {
  // Get settings from UI
  const settings = {
    blockThreats: elements.blockThreats.checked,
    scanContent: elements.scanContent.checked,
    monitorScripts: elements.monitorScripts.checked,
    checkForms: elements.checkForms.checked,
    showNotifications: elements.showNotifications.checked
  };
  
  // Save to storage
  chrome.storage.local.set({ securitySettings: settings }, () => {
    // Show success message
    const saveButton = elements.saveSettings;
    const originalText = saveButton.textContent;
    
    saveButton.textContent = 'Saved!';
    saveButton.disabled = true;
    
    // Reset button after a delay
    setTimeout(() => {
      saveButton.textContent = originalText;
      saveButton.disabled = false;
    }, 1500);
    
    // Notify background script of settings change
    chrome.runtime.sendMessage({ 
      action: 'settingsUpdated',
      settings: settings
    });
  });
}

// Reset statistics
async function resetStats() {
  if (confirm('Are you sure you want to reset all security statistics?')) {
    chrome.runtime.sendMessage({ action: 'resetStats' }, response => {
      if (response && response.success) {
        // Reload statistics
        loadStatistics();
        
        // Show success message
        const resetButton = elements.resetStats;
        const originalText = resetButton.textContent;
        
        resetButton.textContent = 'Reset Complete';
        resetButton.disabled = true;
        
        // Reset button after a delay
        setTimeout(() => {
          resetButton.textContent = originalText;
          resetButton.disabled = false;
        }, 1500);
      } else {
        console.error('Failed to reset statistics');
      }
    });
  }
} 