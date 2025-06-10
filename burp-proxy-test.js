// Minimal Electron app to test Burp Suite interception.
// Run with: npx electron c:\Users\CyberGhost\Desktop\latest\burp-proxy-test.js

const { app, BrowserWindow, session } = require('electron');

app.commandLine.appendSwitch('ignore-certificate-errors');

app.whenReady().then(() => {
  session.defaultSession.setProxy({
    proxyRules: 'http=127.0.0.1:8080;https=127.0.0.1:8080'
  }).then(() => {
    const win = new BrowserWindow({
      width: 800,
      height: 600,
      webPreferences: {
        nodeIntegration: false,
        contextIsolation: true
      }
    });
    win.loadURL('http://example.com');
  });
});
