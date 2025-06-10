// Listen for F12 or Ctrl+Shift+I and send a message to the host
const { ipcRenderer, contextBridge } = require('electron');
window.addEventListener('keydown', (e) => {
  if ((e.key === 'F12') || (e.ctrlKey && e.shiftKey && e.key.toLowerCase() === 'i')) {
    ipcRenderer.sendToHost('webview-open-devtools');
    e.preventDefault();
  }
}, true);