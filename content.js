// content.js - Content script that runs on all web pages

// Configuration
const SCRIPT_ANALYSIS_ENABLED = true;
const FORM_ANALYSIS_ENABLED = true;
const DOM_MUTATION_MONITORING = true;
const INITIAL_SCAN_DELAY = 1000; // Wait 1 second before initial scan

// Track if this is the first load
let isInitialPageLoad = true;

// Initialize content security when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  setTimeout(performInitialScan, INITIAL_SCAN_DELAY);
});

// Perform the initial security scan of the page
async function performInitialScan() {
  console.log('[CyberSentry] Performing initial security scan');
  
  // Send the current URL for validation
  validateCurrentUrl();
  
  // Get a simplified version of the page content
  const pageContent = extractPageContent();
  
  // Send page content for scanning
  scanPageContent(pageContent);
  
  // Set up dynamic content monitoring if enabled
  if (DOM_MUTATION_MONITORING) {
    setupMutationObserver();
  }
  
  // Analyze scripts if enabled
  if (SCRIPT_ANALYSIS_ENABLED) {
    analyzePageScripts();
  }
  
  // Analyze forms if enabled
  if (FORM_ANALYSIS_ENABLED) {
    analyzePageForms();
  }
  
  // Mark initial load as complete
  isInitialPageLoad = false;
}

// Validate the current URL with the background service
function validateCurrentUrl() {
  chrome.runtime.sendMessage({
    action: 'validateUrl',
    url: window.location.href
  }, response => {
    if (response && response.securityLevel === 'dangerous') {
      // The background script will handle dangerous URLs
      console.log('[CyberSentry] Dangerous URL detected');
    }
  });
}

// Extract relevant content from the page for security scanning
function extractPageContent() {
  // Get all scripts
  const scripts = Array.from(document.querySelectorAll('script')).map(script => {
    return {
      type: script.type,
      src: script.src,
      inline: script.innerText.substring(0, 500) // Limit inline script content
    };
  });
  
  // Get all forms
  const forms = Array.from(document.querySelectorAll('form')).map(form => {
    return {
      action: form.action,
      method: form.method,
      hasPassword: form.querySelector('input[type="password"]') !== null,
      hasEmail: form.querySelector('input[type="email"]') !== null || 
                form.querySelector('input[name*="email"]') !== null
    };
  });
  
  // Return a summary of the page content
  return {
    url: window.location.href,
    title: document.title,
    scripts,
    forms,
    links: Array.from(document.querySelectorAll('a')).length,
    iframes: Array.from(document.querySelectorAll('iframe')).length
  };
}

// Send page content to background script for scanning
function scanPageContent(contentSummary) {
  chrome.runtime.sendMessage({
    action: 'scanContent',
    content: JSON.stringify(contentSummary),
    url: window.location.href
  }, response => {
    if (response && response.contentSecurityLevel === 'dangerous') {
      console.log('[CyberSentry] Dangerous content detected');
      // The background script will handle notifications
    }
  });
}

// Set up mutation observer to monitor DOM changes
function setupMutationObserver() {
  // Create a MutationObserver to watch for DOM changes
  const observer = new MutationObserver(mutations => {
    mutations.forEach(mutation => {
      // Check for added nodes
      if (mutation.addedNodes && mutation.addedNodes.length > 0) {
        mutation.addedNodes.forEach(node => {
          // Only process element nodes
          if (node.nodeType === Node.ELEMENT_NODE) {
            analyzeDynamicElement(node);
          }
        });
      }
      
      // Check for attribute changes on scripts and iframes
      if (mutation.type === 'attributes') {
        const target = mutation.target;
        
        // If a script src or content changed
        if (target.tagName === 'SCRIPT' && 
            (mutation.attributeName === 'src' || mutation.attributeName === 'type')) {
          console.log('[CyberSentry] Script attribute changed:', target);
          analyzeScript(target);
        }
        
        // If an iframe src changed
        if (target.tagName === 'IFRAME' && mutation.attributeName === 'src') {
          console.log('[CyberSentry] Iframe src changed:', target.src);
          
          // Check for suspicious iframes
          if (target.src && !target.src.startsWith('https:')) {
            reportSuspiciousElement('insecure_iframe', target);
          }
        }
        
        // If a form action changed
        if (target.tagName === 'FORM' && mutation.attributeName === 'action') {
          console.log('[CyberSentry] Form action changed:', target.action);
          analyzeForm(target);
        }
      }
    });
  });
  
  // Start observing the document with the configured parameters
  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['src', 'type', 'action']
  });
  
  console.log('[CyberSentry] DOM mutation observer started');
}

// Analyze dynamically added elements
function analyzeDynamicElement(element) {
  // Check if it's a script
  if (element.tagName === 'SCRIPT') {
    analyzeScript(element);
  }
  
  // Check if it's an iframe
  if (element.tagName === 'IFRAME') {
    // Check for suspicious iframes
    if (element.src && !element.src.startsWith('https:')) {
      reportSuspiciousElement('insecure_iframe', element);
    }
  }
  
  // Check if it's a form
  if (element.tagName === 'FORM') {
    analyzeForm(element);
  }
  
  // Recursively check children
  if (element.children && element.children.length > 0) {
    Array.from(element.children).forEach(child => {
      analyzeDynamicElement(child);
    });
  }
}

// Analyze scripts on the page
function analyzePageScripts() {
  const scripts = document.querySelectorAll('script');
  
  scripts.forEach(script => {
    analyzeScript(script);
  });
}

// Analyze a single script element
function analyzeScript(script) {
  // Check for suspicious patterns in inline scripts
  if (script.innerText) {
    const scriptContent = script.innerText;
    
    // Check for potential cryptocurrency miners
    if (/coinhive|cryptonight|miner\.start/i.test(scriptContent)) {
      reportSuspiciousElement('crypto_miner', script);
    }
    
    // Check for potential data exfiltration
    if (/document\.cookie|localStorage|sessionStorage/i.test(scriptContent) && 
        /fetch|xhr|ajax|post/i.test(scriptContent)) {
      reportSuspiciousElement('data_exfiltration', script);
    }
    
    // Check for obfuscated code
    if (/eval\(unescape|String\.fromCharCode\([0-9,]+\)|document\.write\(unescape/i.test(scriptContent)) {
      reportSuspiciousElement('obfuscated_code', script);
    }
  }
  
  // Check external scripts
  if (script.src) {
    // Check if the script is loaded over HTTPS
    if (!script.src.startsWith('https:')) {
      reportSuspiciousElement('insecure_script', script);
    }
    
    // Check for known malicious domains (simplified example)
    const suspiciousDomains = [
      'evil-script.example',
      'malware-cdn.example',
      'stats-collector.example'
    ];
    
    try {
      const scriptDomain = new URL(script.src).hostname;
      if (suspiciousDomains.includes(scriptDomain)) {
        reportSuspiciousElement('known_malicious_domain', script);
      }
    } catch (e) {
      // Invalid URL, could be suspicious
      reportSuspiciousElement('invalid_script_url', script);
    }
  }
}

// Analyze forms on the page
function analyzePageForms() {
  const forms = document.querySelectorAll('form');
  
  forms.forEach(form => {
    analyzeForm(form);
  });
}

// Analyze a single form element
function analyzeForm(form) {
  // Check if the form has password or email fields
  const hasPasswordField = form.querySelector('input[type="password"]') !== null;
  const hasEmailField = form.querySelector('input[type="email"]') !== null || 
                        form.querySelector('input[name*="email"]') !== null;
  
  // Check if the form is submitting to a secure destination
  const formAction = form.action || window.location.href;
  const isSecureAction = formAction.startsWith('https:');
  
  // Track insecure forms for reporting
  const insecureForms = [];
  
  // Check for insecure form submission
  if ((hasPasswordField || hasEmailField) && !isSecureAction) {
    // Report the insecure form
    insecureForms.push({
      hasPasswordField,
      hasEmailField,
      hasSecureConnection: isSecureAction,
      location: getElementPath(form),
      fields: Array.from(form.querySelectorAll('input')).map(input => input.type)
    });
    
    // Add form submission listener to detect potential data exfiltration
    form.addEventListener('submit', (event) => {
      // Check if the form submission might be risky
      if ((hasPasswordField || hasEmailField) && !isSecureAction) {
        // Prevent the submission
        event.preventDefault();
        
        // Notify the user
        chrome.runtime.sendMessage({
          action: 'threatDetected',
          threatCategory: 'VULNERABLE_FORM',
          details: {
            url: window.location.href,
            formAction: formAction,
            hasPasswordField
          }
        });
        
        // Show in-page warning
        showSecurityWarning('This form is submitting sensitive information insecurely. Submission has been blocked for your protection.');
      }
    });
  }
  
  // Report insecure forms if found
  if (insecureForms.length > 0) {
    checkVulnerabilities({
      url: window.location.href,
      formIssues: insecureForms
    });
  }
}

// Show a security warning directly in the page
function showSecurityWarning(message) {
  // Create a warning banner
  const banner = document.createElement('div');
  banner.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    background-color: #ff4444;
    color: white;
    padding: 10px;
    font-family: Arial, sans-serif;
    font-size: 14px;
    text-align: center;
    z-index: 2147483647;
    box-shadow: 0 2px 4px rgba(0,0,0,0.2);
  `;
  
  // Add warning message
  banner.textContent = message;
  
  // Add close button
  const closeButton = document.createElement('button');
  closeButton.textContent = '×';
  closeButton.style.cssText = `
    background: none;
    border: none;
    color: white;
    font-size: 20px;
    font-weight: bold;
    cursor: pointer;
    position: absolute;
    right: 10px;
    top: 5px;
  `;
  
  closeButton.addEventListener('click', () => {
    document.body.removeChild(banner);
  });
  
  banner.appendChild(closeButton);
  
  // Add to the page
  document.body.appendChild(banner);
}

// Report suspicious elements to the background script
function reportSuspiciousElement(type, element) {
  chrome.runtime.sendMessage({
    action: 'reportThreat',
    data: {
      threatCategory: type.toUpperCase(),
      url: window.location.href,
      details: {
        elementType: element.tagName,
        elementInfo: getElementInfo(element),
        location: getElementPath(element)
      }
    }
  });
  
  // Also report to the vulnerability checker
  reportThreatDetection(type.toUpperCase());
}

// Get the DOM path of an element for reporting
function getElementPath(element) {
  const path = [];
  let currentElement = element;
  
  while (currentElement && currentElement !== document.documentElement) {
    let selector = currentElement.tagName.toLowerCase();
    
    if (currentElement.id) {
      selector += `#${currentElement.id}`;
    } else if (currentElement.className) {
      selector += `.${currentElement.className.split(' ')[0]}`;
    } else {
      // Add position among siblings
      let position = 1;
      let sibling = currentElement.previousElementSibling;
      
      while (sibling) {
        if (sibling.tagName === currentElement.tagName) {
          position++;
        }
        sibling = sibling.previousElementSibling;
      }
      
      selector += `:nth-child(${position})`;
    }
    
    path.unshift(selector);
    currentElement = currentElement.parentElement;
  }
  
  return path.join(' > ');
}

// Get basic information about an element
function getElementInfo(element) {
  const info = {
    tagName: element.tagName
  };
  
  // Add relevant attributes based on tag type
  if (element.tagName === 'SCRIPT') {
    info.src = element.src;
    info.type = element.type;
  } else if (element.tagName === 'IFRAME') {
    info.src = element.src;
  } else if (element.tagName === 'FORM') {
    info.action = element.action;
    info.method = element.method;
  }
  
  return info;
}

// Check for vulnerabilities in the page
function checkVulnerabilities(data) {
  chrome.runtime.sendMessage({
    action: 'checkVulnerabilities',
    data: data
  }, response => {
    if (response && response.success) {
      console.log('[CyberSentry] Vulnerability check completed');
      
      // If vulnerabilities were found, they will be handled by the background script
      if (response.data && response.data.vulnerabilities && response.data.vulnerabilities.length > 0) {
        console.log('[CyberSentry] Vulnerabilities found:', response.data.vulnerabilities.length);
      }
    } else {
      console.error('[CyberSentry] Vulnerability check failed:', response?.error);
    }
  });
}

// Report a threat detection to update statistics
function reportThreatDetection(threatCategory) {
  chrome.runtime.sendMessage({
    action: 'threatDetected',
    threatCategory: threatCategory,
    details: {
      url: window.location.href,
      timestamp: new Date().toISOString()
    }
  });
} 