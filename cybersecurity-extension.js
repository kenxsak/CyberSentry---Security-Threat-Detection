// manifest.json - Chrome Extension Configuration
{
  "manifest_version": 3,
  "name": "CyberSentry - Security & Threat Detection",
  "version": "1.0.0",
  "description": "A comprehensive cybersecurity extension that monitors browsing for potential threats, phishing attempts, and vulnerabilities",
  "permissions": [
    "webNavigation",
    "webRequest",
    "storage",
    "tabs",
    "notifications",
    "scripting",
    "cookies"
  ],
  "host_permissions": [
    "http://*/*",
    "https://*/*"
  ],
  "action": {
    "default_popup": "popup.html",
    "default_icon": {
      "16": "icons/icon16.png",
      "48": "icons/icon48.png",
      "128": "icons/icon128.png"
    }
  },
  "icons": {
    "16": "icons/icon16.png",
    "48": "icons/icon48.png",
    "128": "icons/icon128.png"
  },
  "background": {
    "service_worker": "background.js"
  },
  "content_scripts": [
    {
      "matches": ["http://*/*", "https://*/*"],
      "js": ["content.js"],
      "run_at": "document_start"
    }
  ],
  "web_accessible_resources": [
    {
      "resources": ["icons/*", "assets/*"],
      "matches": ["<all_urls>"]
    }
  ]
}
