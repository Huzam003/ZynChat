const { app, BrowserWindow } = require('electron');
const path = require('path');

// ─── Configuration ────────────────────────────────────────────────────────────
// All platforms connect to the same cloud server for sync
const CLOUD_SERVER = 'https://nexachat-aj89.onrender.com';

let mainWindow;

function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    title: 'NexaChat Enterprise',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
    },
    icon: path.join(__dirname, 'public', 'favicon.ico'),
  });

  // Load the cloud server directly — all platforms share the same server & database
  mainWindow.loadURL(CLOUD_SERVER);

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// ─── Lifecycle ────────────────────────────────────────────────────────────────

app.on('ready', () => {
  console.log('[Electron] Connecting to NexaChat Cloud:', CLOUD_SERVER);
  createMainWindow();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (mainWindow === null) {
    createMainWindow();
  }
});
