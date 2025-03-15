// background.js - Background Service Worker
// Handles API communication and core security analysis

// Configuration and API endpoints
const API_BASE_URL = 'https://api.cybersentry.example.com/v1';
const API_ENDPOINTS = {
  validateUrl: '/security/url/validate',
  scanContent: '/security/content/scan',
  checkVulnerabilities: '/security/vulnerabilities',
  reportThreat: '/reports/threat',
  userAuth: '/auth'
};

// Security threat categories
const THREAT_CATEGORIES = {
  PHISHING: 'phishing',
  MALWARE: 'malware',
  CRYPTO_MINING: 'crypto_mining',
  DATA_LEAKAGE: 'data_leakage',
  VULNERABLE_FORM: 'vulnerable_form',
  INSECURE_CONNECTION: 'insecure_connection',
  SUSPICIOUS_REDIRECT: 'suspicious_redirect',
  KNOWN_THREAT: 'known_threat'
};

// Authentication and API communication helper
class ApiService {
  constructor() {
    this.token = null;
    this.tokenExpiry = null;
    this.loadSavedCredentials();
  }

  async loadSavedCredentials() {
    const auth = await chrome.storage.local.get(['authToken', 'tokenExpiry']);
    if (auth.authToken && auth.tokenExpiry && new Date(auth.tokenExpiry) > new Date()) {
      this.token = auth.authToken;
      this.tokenExpiry = auth.tokenExpiry;
    }
  }

  async getAuthToken() {
    if (this.token && this.tokenExpiry && new Date(this.tokenExpiry) > new Date()) {
      return this.token;
    }
    
    // Token refresh logic would go here
    // For demo purposes, we're returning a simulated token
    const refreshResponse = await this.simulateTokenRefresh();
    
    if (refreshResponse.success) {
      this.token = refreshResponse.token;
      this.tokenExpiry = refreshResponse.expiry;
      
      // Save to storage
      await chrome.storage.local.set({
        authToken: this.token,
        tokenExpiry: this.tokenExpiry
      });
      
      return this.token;
    }
    
    return null;
  }
  
  async simulateTokenRefresh() {
    // In a real extension, this would be an actual API call
    return {
      success: true,
      token: 'simulated_jwt_token_' + Date.now(),
      expiry: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString() // 24 hours
    };
  }
  
  async makeApiRequest(endpoint, method = 'GET', data = null) {
    try {
      const token = await this.getAuthToken();
      
      // In a real extension, this would make actual API calls
      // For demo purposes, we're simulating responses
      return await this.simulateApiResponse(endpoint, method, data);
      
      /* Real implementation would be:
      const response = await fetch(API_BASE_URL + endpoint, {
        method,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: data ? JSON.stringify(data) : undefined
      });
      
      return await response.json();
      */
    } catch (error) {
      console.error('API request failed:', error);
      return { error: 'API request failed' };
    }
  }
  
  async simulateApiResponse(endpoint, method, data) {
    // Simulate API latency
    await new Promise(resolve => setTimeout(resolve, 300));
    
    // Return different simulated responses based on the endpoint
    if (endpoint === API_ENDPOINTS.validateUrl) {
      return this.simulateUrlValidation(data.url);
    } else if (endpoint === API_ENDPOINTS.scanContent) {
      return this.simulateContentScan(data.content, data.url);
    } else if (endpoint === API_ENDPOINTS.checkVulnerabilities) {
      return this.simulateVulnerabilityCheck(data);
    }
    
    return { success: true, data: {} };
  }
  
  simulateUrlValidation(url) {
    // Simulate security checks for the URL
    const urlObj = new URL(url);
    const domain = urlObj.hostname;
    
    // Check for known phishing domains (for demo purposes)
    const knownPhishingDomains = [
      'phishing-example.com',
      'secure-bank-login.example',
      'account-verify.example'
    ];
    
    // Check for suspicious URL patterns
    const hasSuspiciousPattern = /secure|login|account|verify|bank|paypal|wallet|crypto/i.test(url) && 
                                 /\d{5,}|[a-f0-9]{8,}|[.-]{2,}/i.test(url);
    
    // Determine security level
    let securityLevel = 'safe';
    let threatCategory = null;
    let threatDetails = null;
    
    if (knownPhishingDomains.includes(domain)) {
      securityLevel = 'dangerous';
      threatCategory = THREAT_CATEGORIES.PHISHING;
      threatDetails = 'Known phishing domain detected';
    } else if (hasSuspiciousPattern) {
      securityLevel = 'suspicious';
      threatCategory = THREAT_CATEGORIES.SUSPICIOUS_REDIRECT;
      threatDetails = 'URL contains suspicious patterns';
    } else if (!urlObj.protocol.includes('https')) {
      securityLevel = 'warning';
      threatCategory = THREAT_CATEGORIES.INSECURE_CONNECTION;
      threatDetails = 'Connection is not secure (HTTP)';
    }
    
    return {
      success: true,
      data: {
        url,
        securityLevel,
        threatCategory,
        threatDetails,
        timestamp: new Date().toISOString()
      }
    };
  }
  
  simulateContentScan(content, url) {
    // Simulate content security analysis
    
    // Check for suspicious scripts (for demo purposes)
    const hasCryptoMiner = /coinhive|cryptonight|miner\.start/i.test(content);
    const hasDataLeakage = /document\.cookie|localStorage|sessionStorage/i.test(content) && 
                           /fetch|xhr|ajax|post/i.test(content);
    const hasMalwarePattern = /eval\(unescape|String\.fromCharCode\([0-9,]+\)|document\.write\(unescape/i.test(content);
    
    // Determine content security
    let contentSecurityLevel = 'safe';
    let contentThreats = [];
    
    if (hasCryptoMiner) {
      contentSecurityLevel = 'dangerous';
      contentThreats.push({
        category: THREAT_CATEGORIES.CRYPTO_MINING,
        details: 'Potential cryptocurrency mining script detected'
      });
    }
    
    if (hasDataLeakage) {
      contentSecurityLevel = contentSecurityLevel === 'safe' ? 'warning' : contentSecurityLevel;
      contentThreats.push({
        category: THREAT_CATEGORIES.DATA_LEAKAGE,
        details: 'Potential data leakage script detected'
      });
    }
    
    if (hasMalwarePattern) {
      contentSecurityLevel = 'dangerous';
      contentThreats.push({
        category: THREAT_CATEGORIES.MALWARE,
        details: 'Potential malware script detected'
      });
    }
    
    return {
      success: true,
      data: {
        url,
        contentSecurityLevel,
        contentThreats,
        timestamp: new Date().toISOString()
      }
    };
  }
  
  simulateVulnerabilityCheck(data) {
    // Simulate vulnerability analysis
    const vulnerabilities = [];
    
    // Check for form issues
    if (data.formIssues && data.formIssues.length > 0) {
      data.formIssues.forEach(form => {
        if (form.hasPasswordField && !form.hasSecureConnection) {
          vulnerabilities.push({
            type: 'form',
            severity: 'high',
            details: 'Password form submitting to insecure destination',
            location: form.location
          });
        } else if (form.hasEmailField && !form.hasSecureConnection) {
          vulnerabilities.push({
            type: 'form',
            severity: 'medium',
            details: 'Email form submitting to insecure destination',
            location: form.location
          });
        }
      });
    }
    
    return {
      success: true,
      data: {
        url: data.url,
        vulnerabilities,
        timestamp: new Date().toISOString()
      }
    };
  }
}

// Security Manager - Handles URL and navigation security
class SecurityManager {
  constructor(apiService) {
    this.apiService = apiService;
    this.tabSecurityInfo = new Map();
    this.setupListeners();
  }
  
  setupListeners() {
    // Listen for tab updates
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
      if (changeInfo.status === 'loading' && tab.url && tab.url.startsWith('http')) {
        this.checkUrlSafety(tab.url, tabId);
      }
    });
    
    // Listen for content script messages
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message.action === 'scanContent') {
        this.scanPageContent(message.content, message.url, sender.tab?.id)
          .then(result => sendResponse(result))
          .catch(error => sendResponse({error: error.message}));
        return true; // Keep message channel open for async response
      }
      
      if (message.action === 'getSecurityInfo') {
        const securityInfo = this.tabSecurityInfo.get(sender.tab?.id) || { securityLevel: 'unknown' };
        sendResponse(securityInfo);
        return true;
      }
      
      if (message.action === 'threatDetected') {
        this.handleThreatDetection(message.threatCategory, message.details, sender.tab?.id);
        sendResponse({success: true});
        return true;
      }
    });
  }
  
  async checkUrlSafety(url, tabId) {
    try {
      // Get security information for the URL
      const response = await this.apiService.makeApiRequest(
        API_ENDPOINTS.validateUrl,
        'POST',
        { url }
      );
      
      if (response.success) {
        const securityInfo = response.data;
        
        // Update tab security information
        await this.updateTabSecurity(tabId, securityInfo);
        
        // Show notification for dangerous sites
        if (securityInfo.securityLevel === 'dangerous') {
          this.showThreatNotification(
            'Dangerous Website Blocked',
            `The website ${new URL(url).hostname} has been identified as ${securityInfo.threatCategory}.`,
            tabId
          );
          
          // Redirect to warning page for dangerous sites
          chrome.tabs.update(tabId, {
            url: chrome.runtime.getURL('warning.html') + `?url=${encodeURIComponent(url)}&threat=${securityInfo.threatCategory}`
          });
        } else if (securityInfo.securityLevel === 'suspicious') {
          this.showThreatNotification(
            'Suspicious Website Warning',
            `The website ${new URL(url).hostname} appears suspicious. Proceed with caution.`,
            tabId
          );
        }
        
        return securityInfo;
      }
    } catch (error) {
      console.error('Error checking URL safety:', error);
    }
    
    return { securityLevel: 'unknown' };
  }
  
  async scanPageContent(content, url, tabId) {
    try {
      // Get content security information
      const response = await this.apiService.makeApiRequest(
        API_ENDPOINTS.scanContent,
        'POST',
        { content, url }
      );
      
      if (response.success) {
        const contentSecurity = response.data;
        
        // Update tab content security information
        await this.updateTabContentSecurity(tabId, contentSecurity);
        
        // Show notification for dangerous content
        if (contentSecurity.contentSecurityLevel === 'dangerous' && contentSecurity.contentThreats.length > 0) {
          const threat = contentSecurity.contentThreats[0];
          this.showThreatNotification(
            'Dangerous Content Detected',
            `${threat.details} on ${new URL(url).hostname}.`,
            tabId
          );
        }
        
        return contentSecurity;
      }
    } catch (error) {
      console.error('Error scanning page content:', error);
    }
    
    return { contentSecurityLevel: 'unknown', contentThreats: [] };
  }
  
  async updateTabSecurity(tabId, securityInfo) {
    // Get existing security info for the tab
    const existingInfo = this.tabSecurityInfo.get(tabId) || {};
    
    // Update with new security info
    this.tabSecurityInfo.set(tabId, {
      ...existingInfo,
      securityLevel: securityInfo.securityLevel,
      threatCategory: securityInfo.threatCategory,
      threatDetails: securityInfo.threatDetails,
      url: securityInfo.url,
      timestamp: securityInfo.timestamp
    });
    
    // Update badge based on security level
    let badgeColor, badgeText;
    
    switch (securityInfo.securityLevel) {
      case 'dangerous':
        badgeColor = '#FF0000'; // Red
        badgeText = '!';
        break;
      case 'suspicious':
        badgeColor = '#FFA500'; // Orange
        badgeText = '?';
        break;
      case 'warning':
        badgeColor = '#FFFF00'; // Yellow
        badgeText = '!';
        break;
      case 'safe':
        badgeColor = '#00FF00'; // Green
        badgeText = '✓';
        break;
      default:
        badgeColor = '#808080'; // Gray
        badgeText = '';
    }
    
    chrome.action.setBadgeBackgroundColor({ color: badgeColor, tabId });
    chrome.action.setBadgeText({ text: badgeText, tabId });
  }
  
  async updateTabContentSecurity(tabId, contentSecurity) {
    // Get existing security info for the tab
    const existingInfo = this.tabSecurityInfo.get(tabId) || {};
    
    // Update with new content security info
    this.tabSecurityInfo.set(tabId, {
      ...existingInfo,
      contentSecurityLevel: contentSecurity.contentSecurityLevel,
      contentThreats: contentSecurity.contentThreats
    });
    
    // If content security is worse than URL security, update badge
    if (contentSecurity.contentSecurityLevel === 'dangerous' && existingInfo.securityLevel !== 'dangerous') {
      chrome.action.setBadgeBackgroundColor({ color: '#FF0000', tabId });
      chrome.action.setBadgeText({ text: '!', tabId });
    }
  }
  
  handleThreatDetection(threatCategory, details, tabId) {
    // Get existing security info for the tab
    const existingInfo = this.tabSecurityInfo.get(tabId) || {};
    const url = details.url || existingInfo.url;
    
    // Update threat information
    this.tabSecurityInfo.set(tabId, {
      ...existingInfo,
      securityLevel: 'dangerous',
      threatCategory: threatCategory,
      threatDetails: details,
      detectedThreats: [...(existingInfo.detectedThreats || []), {
        category: threatCategory,
        details: details,
        timestamp: new Date().toISOString()
      }]
    });
    
    // Update badge
    chrome.action.setBadgeBackgroundColor({ color: '#FF0000', tabId });
    chrome.action.setBadgeText({ text: '!', tabId });
    
    // Show notification
    let title, message;
    
    switch (threatCategory) {
      case THREAT_CATEGORIES.PHISHING:
        title = 'Phishing Attempt Detected';
        message = `The website ${new URL(url).hostname} appears to be a phishing attempt.`;
        break;
      case THREAT_CATEGORIES.MALWARE:
        title = 'Malware Risk Detected';
        message = `Potential malware detected on ${new URL(url).hostname}.`;
        break;
      case THREAT_CATEGORIES.CRYPTO_MINING:
        title = 'Crypto Mining Detected';
        message = `Cryptocurrency mining script detected on ${new URL(url).hostname}.`;
        break;
      case THREAT_CATEGORIES.VULNERABLE_FORM:
        title = 'Insecure Form Detected';
        message = `A form on ${new URL(url).hostname} is submitting sensitive data insecurely.`;
        break;
      default:
        title = 'Security Threat Detected';
        message = `A security threat was detected on ${new URL(url).hostname}.`;
    }
    
    this.showThreatNotification(title, message, tabId);
  }
  
  showThreatNotification(title, message, tabId) {
    // Show notification
    chrome.notifications.create(`threat_${Date.now()}`, {
      type: 'basic',
      iconUrl: 'icons/warning_icon.svg',
      title: title,
      message: message,
      priority: 2,
      buttons: [
        { title: 'View Details' },
        { title: 'Ignore' }
      ]
    });
    
    // Listen for notification clicks
    chrome.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
      if (buttonIndex === 0) { // View Details
        chrome.tabs.create({
          url: chrome.runtime.getURL('threat_details.html') + `?tabId=${tabId}`
        });
      }
    });
  }
}

// Content Security Manager
class ContentSecurityManager {
  constructor(apiService) {
    this.apiService = apiService;
    this.setupListeners();
  }
  
  setupListeners() {
    // Listen for content script messages about vulnerability checks
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message.action === 'checkVulnerabilities') {
        this.checkVulnerabilities(message.data, sender.tab?.id)
          .then(result => sendResponse(result))
          .catch(error => sendResponse({error: error.message}));
        return true; // Keep message channel open for async response
      }
      
      if (message.action === 'reportThreat') {
        this.reportThreat(message.data, sender.tab?.id)
          .then(result => sendResponse(result))
          .catch(error => sendResponse({error: error.message}));
        return true;
      }
    });
  }
  
  async checkVulnerabilities(data, tabId) {
    try {
      // Check for vulnerabilities in the page
      const response = await this.apiService.makeApiRequest(
        API_ENDPOINTS.checkVulnerabilities,
        'POST',
        data
      );
      
      if (response.success && response.data.vulnerabilities.length > 0) {
        // Get the security manager to handle the threat
        const securityManager = extensionManager.securityManager;
        
        // Report each vulnerability as a threat
        response.data.vulnerabilities.forEach(vulnerability => {
          securityManager.handleThreatDetection(
            THREAT_CATEGORIES.VULNERABLE_FORM,
            {
              url: data.url,
              details: vulnerability.details,
              severity: vulnerability.severity,
              location: vulnerability.location
            },
            tabId
          );
        });
      }
      
      return response;
    } catch (error) {
      console.error('Error checking vulnerabilities:', error);
      return { error: error.message };
    }
  }
  
  async reportThreat(data, tabId) {
    try {
      // In a real extension, this would send the threat report to the server
      // For demo purposes, we'll just log it and update the security manager
      console.log('Threat reported:', data);
      
      // Get the security manager to handle the threat
      const securityManager = extensionManager.securityManager;
      securityManager.handleThreatDetection(
        data.threatCategory,
        {
          url: data.url,
          details: data.details
        },
        tabId
      );
      
      // Update statistics
      extensionManager.statisticsTracker.recordThreat(data.threatCategory);
      
      return { success: true };
    } catch (error) {
      console.error('Error reporting threat:', error);
      return { error: error.message };
    }
  }
}

// Security Statistics Tracker
class SecurityStatisticsTracker {
  constructor() {
    this.stats = {
      sitesVisited: 0,
      threatsBlocked: 0,
      vulnerabilitiesFound: 0,
      threatsByCategory: {},
      lastReset: new Date().toISOString()
    };
    
    this.initializeStats();
    this.setupListeners();
  }
  
  async initializeStats() {
    try {
      // Load saved statistics
      const savedStats = await chrome.storage.local.get('securityStats');
      
      if (savedStats.securityStats) {
        this.stats = savedStats.securityStats;
      } else {
        // Initialize with default values
        this.stats = {
          sitesVisited: 0,
          threatsBlocked: 0,
          vulnerabilitiesFound: 0,
          threatsByCategory: {},
          lastReset: new Date().toISOString()
        };
        
        // Save initial stats
        await this.saveStats();
      }
    } catch (error) {
      console.error('Error initializing statistics:', error);
    }
  }
  
  setupListeners() {
    // Track site visits
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
      if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
        this.incrementStat('sitesVisited');
      }
    });
    
    // Listen for messages from popup
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message.action === 'getStats') {
        this.getStats()
          .then(stats => sendResponse(stats))
          .catch(error => sendResponse({error: error.message}));
        return true; // Keep message channel open for async response
      }
      
      if (message.action === 'resetStats') {
        this.resetStats()
          .then(result => sendResponse(result))
          .catch(error => sendResponse({error: error.message}));
        return true;
      }
    });
    
    // Listen for threat detections to update statistics
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message.action === 'threatDetected') {
        this.recordThreat(message.threatCategory);
        sendResponse({success: true});
      }
    });
  }
  
  async incrementStat(statName) {
    this.stats[statName]++;
    await this.saveStats();
  }
  
  async recordThreat(threatCategory) {
    // Increment threats blocked
    this.stats.threatsBlocked++;
    
    // Increment category-specific counter
    if (!this.stats.threatsByCategory[threatCategory]) {
      this.stats.threatsByCategory[threatCategory] = 0;
    }
    this.stats.threatsByCategory[threatCategory]++;
    
    // If it's a vulnerability, increment that counter too
    if (threatCategory === THREAT_CATEGORIES.VULNERABLE_FORM) {
      this.stats.vulnerabilitiesFound++;
    }
    
    // Save updated stats
    await this.saveStats();
  }
  
  async getStats() {
    return this.stats;
  }
  
  async resetStats() {
    // Reset all statistics
    this.stats = {
      sitesVisited: 0,
      threatsBlocked: 0,
      vulnerabilitiesFound: 0,
      threatsByCategory: {},
      lastReset: new Date().toISOString()
    };
    
    // Save reset stats
    await this.saveStats();
    
    return { success: true };
  }
  
  async saveStats() {
    try {
      await chrome.storage.local.set({ securityStats: this.stats });
    } catch (error) {
      console.error('Error saving statistics:', error);
    }
  }
}

// Extension Manager - Main controller for the extension
class ExtensionManager {
  constructor() {
    // Initialize services
    this.apiService = new ApiService();
    this.securityManager = new SecurityManager(this.apiService);
    this.contentSecurityManager = new ContentSecurityManager(this.apiService);
    this.statisticsTracker = new SecurityStatisticsTracker();
    
    // Load settings
    this.loadSettings();
  }
  
  async loadSettings() {
    try {
      const settings = await chrome.storage.local.get('securitySettings');
      
      if (!settings.securitySettings) {
        // Initialize with default settings
        const defaultSettings = {
          blockThreats: true,
          scanContent: true,
          monitorScripts: true,
          checkForms: true,
          showNotifications: true
        };
        
        await chrome.storage.local.set({ securitySettings: defaultSettings });
      }
    } catch (error) {
      console.error('Error loading settings:', error);
    }
  }
}

// Initialize the extension
const extensionManager = new ExtensionManager();

// Make extension manager available globally for debugging
window.extensionManager = extensionManager; 