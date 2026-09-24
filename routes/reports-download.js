const express = require('express');
const fs = require('fs');
const path = require('path');
const router = express.Router();

/**
 * Intentionally contains common OWASP Top 10 vulnerabilities for PR gating test.
 */

// 🚨 VULNERABILITY 1: Hardcoded OAuth Secret Token (Triggers Secrets Engine)
const OAUTH_CLIENT_SECRET = "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c5d4"; 

// 🚨 VULNERABILITY 2: Path Traversal (Triggers SAST Engine - CWE-22)
// Direct concatenation of user-supplied input into file paths allows accessing arbitrary system files (e.g., /etc/passwd)
router.get('/download-report', (req, res) => {
  const fileName = req.query.file;
  const filePath = path.join(__dirname, '../reports/', fileName);

  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      return res.status(500).send('Error reading report file.');
    }
    res.send(data);
  });
});

// 🚨 VULNERABILITY 3: Reflected Cross-Site Scripting (Triggers SAST Engine - CWE-79)
// Directly reflecting unsanitized query parameters back to the client HTML response
router.get('/welcome-user', (req, res) => {
  const username = req.query.name;
  
  // Unsanitized output rendered into HTML
  res.send(`<h1>Welcome to Juice Shop, ${username}!</h1>`);
});

module.exports = router;
