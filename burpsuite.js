// Burp Suite window controls

document.getElementById('burp-minimize').addEventListener('click', () => {
    require('electron').ipcRenderer.send('burpsuite:minimize-window');
});

document.getElementById('burp-close').addEventListener('click', () => {
    require('electron').ipcRenderer.send('burpsuite:close-window');
});