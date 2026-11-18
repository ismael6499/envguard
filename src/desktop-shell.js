'use strict';

const { execFileSync, spawn, spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { ensureDirSync, getEnvguardHome, loadConfig } = require('./crypto-vault');

const ASSETS_DIR = path.resolve(__dirname, '..', 'assets');
const ICON_PATH = path.join(ASSETS_DIR, 'envguard.ico');
const VBS_LAUNCHER_PATH = path.resolve(__dirname, '..', 'bin', 'envguard-app.vbs');

function ensureIconFile() {
  ensureDirSync(ASSETS_DIR);
  if (fs.existsSync(ICON_PATH)) {
    return ICON_PATH;
  }

  if (process.platform === 'win32') {
    const ps = `
Add-Type -AssemblyName System.Drawing
$bmp = New-Object System.Drawing.Bitmap(32, 32)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.Clear([System.Drawing.Color]::Transparent)

$bgBrush = New-Object System.Drawing.SolidBrush([System.Drawing.ColorTranslator]::FromHtml('#1d4ed8'))
$borderPen = New-Object System.Drawing.Pen([System.Drawing.ColorTranslator]::FromHtml('#60a5fa'), 2)
$pts = @(
  (New-Object System.Drawing.Point(16, 2)),
  (New-Object System.Drawing.Point(29, 7)),
  (New-Object System.Drawing.Point(27, 20)),
  (New-Object System.Drawing.Point(16, 30)),
  (New-Object System.Drawing.Point(5, 20)),
  (New-Object System.Drawing.Point(3, 7))
)
$g.FillPolygon($bgBrush, $pts)
$g.DrawPolygon($borderPen, $pts)

$keyBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
$g.FillEllipse($keyBrush, 12, 10, 8, 8)
$g.FillRectangle($keyBrush, 14, 16, 4, 8)
$g.Dispose()

$ms = New-Object System.IO.MemoryStream
$bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
$pngBytes = $ms.ToArray()
$ms.Dispose()
$bmp.Dispose()

$fs = [System.IO.File]::Create($env:ENVGUARD_ICON_OUT)
$bw = New-Object System.IO.BinaryWriter($fs)
$bw.Write([UInt16]0)
$bw.Write([UInt16]1)
$bw.Write([UInt16]1)
$bw.Write([Byte]32)
$bw.Write([Byte]32)
$bw.Write([Byte]0)
$bw.Write([Byte]0)
$bw.Write([UInt16]1)
$bw.Write([UInt16]32)
$bw.Write([UInt32]$pngBytes.Length)
$bw.Write([UInt32]22)
$bw.Write($pngBytes)
$bw.Close()
$fs.Close()
`;
    execFileSync(
      'powershell.exe',
      ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps],
      { env: { ...process.env, ENVGUARD_ICON_OUT: ICON_PATH }, windowsHide: true }
    );
  }
  return ICON_PATH;
}

function findAppBrowserWindows() {
  const candidates = [
    path.join(process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)', 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
    path.join(process.env.ProgramFiles || 'C:\\Program Files', 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
    path.join(process.env.ProgramFiles || 'C:\\Program Files', 'Google', 'Chrome', 'Application', 'chrome.exe'),
    path.join(process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)', 'Google', 'Chrome', 'Application', 'chrome.exe'),
    path.join(process.env.LOCALAPPDATA || '', 'Google', 'Chrome', 'Application', 'chrome.exe'),
  ];
  return candidates.find((p) => p && fs.existsSync(p)) || null;
}

function findAppBrowserLinux() {
  const bins = ['google-chrome', 'chromium', 'chromium-browser', 'microsoft-edge'];
  for (const b of bins) {
    const res = spawnSync('which', [b], { encoding: 'utf8' });
    if (res.status === 0 && res.stdout.trim()) {
      return res.stdout.trim();
    }
  }
  return null;
}

function buildWindowArgs(url, profileDir) {
  const bounds = loadConfig().windowBounds;
  const args = [
    `--app=${url}`,
    `--user-data-dir=${profileDir}`,
    '--new-window',
    '--no-first-run',
    '--disable-features=Translate',
  ];
  if (bounds && typeof bounds === 'object') {
    if (Number.isFinite(bounds.x) && Number.isFinite(bounds.y)) {
      args.push(`--window-position=${Math.round(bounds.x)},${Math.round(bounds.y)}`);
    }
    if (bounds.maximized) {
      args.push('--start-maximized');
    } else if (Number.isFinite(bounds.width) && Number.isFinite(bounds.height)) {
      args.push(`--window-size=${Math.max(400, Math.round(bounds.width))},${Math.max(300, Math.round(bounds.height))}`);
    } else {
      args.push('--window-size=1240,840');
    }
  } else {
    args.push('--window-size=1240,840');
  }
  return args;
}

function openDesktopAppWindow(url) {
  const profileDir = path.join(getEnvguardHome(), 'app-window');
  ensureDirSync(profileDir);
  const windowArgs = buildWindowArgs(url, profileDir);

  if (process.platform === 'win32') {
    const browserExe = findAppBrowserWindows();
    if (browserExe) {
      spawn(browserExe, windowArgs, { detached: true, stdio: 'ignore', windowsHide: false }).unref();
      return { mode: 'app-window', executable: browserExe };
    }
    spawn('cmd', ['/c', 'start', '', url], { detached: true, stdio: 'ignore', windowsHide: true }).unref();
    return { mode: 'browser-fallback', executable: 'default' };
  }

  if (process.platform === 'darwin') {
    spawn('open', [url], { detached: true, stdio: 'ignore' }).unref();
    return { mode: 'browser-fallback', executable: 'open' };
  }

  const linuxBrowser = findAppBrowserLinux();
  if (linuxBrowser) {
    spawn(linuxBrowser, windowArgs, { detached: true, stdio: 'ignore' }).unref();
    return { mode: 'app-window', executable: linuxBrowser };
  }
  spawn('xdg-open', [url], { detached: true, stdio: 'ignore' }).unref();
  return { mode: 'browser-fallback', executable: 'xdg-open' };
}

function buildTrayAgentScript() {
  return `
param(
  [int]$Port,
  [string]$IconPath,
  [string]$VltScript,
  [string]$NodeExe,
  [string]$DaemonJson
)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Threading
[System.Windows.Forms.Application]::EnableVisualStyles()

$createdNew = $false
$mutex = New-Object System.Threading.Mutex($false, 'Local\\EnvGuardTrayMutex', [ref]$createdNew)
if (-not $createdNew) {
  exit 0
}

$tray = New-Object System.Windows.Forms.NotifyIcon
if (Test-Path $IconPath) {
  $tray.Icon = New-Object System.Drawing.Icon($IconPath)
} else {
  $tray.Icon = [System.Drawing.SystemIcons]::Shield
}
$tray.Text = 'EnvGuard — Encrypted Vault'
$tray.Visible = $true

function Open-EnvGuardApp {
  Start-Process -FilePath $NodeExe -ArgumentList ('"' + $VltScript + '" app-window') -WindowStyle Hidden
}

function Invoke-DaemonPost([string]$Path, [string]$BodyJson) {
  try {
    Invoke-RestMethod -Method Post -Uri ("http://127.0.0.1:" + $Port + $Path) -ContentType 'application/json' -Body $BodyJson -TimeoutSec 3 | Out-Null
  } catch {}
}

$menu = New-Object System.Windows.Forms.ContextMenuStrip

$miOpen = $menu.Items.Add('Open EnvGuard App')
$miOpen.Font = New-Object System.Drawing.Font($miOpen.Font, [System.Drawing.FontStyle]::Bold)
$miOpen.Add_Click({ Open-EnvGuardApp })

[void]$menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))

$miT15 = $menu.Items.Add('AI Turbo: 15 min')
$miT15.Add_Click({ Invoke-DaemonPost '/api/turbo' '{"minutes":15}' })

$miT30 = $menu.Items.Add('AI Turbo: 30 min')
$miT30.Add_Click({ Invoke-DaemonPost '/api/turbo' '{"minutes":30}' })

$miT60 = $menu.Items.Add('AI Turbo: 1 hour')
$miT60.Add_Click({ Invoke-DaemonPost '/api/turbo' '{"minutes":60}' })

$miTOff = $menu.Items.Add('AI Turbo: OFF')
$miTOff.Add_Click({ Invoke-DaemonPost '/api/turbo' '{"minutes":0}' })

[void]$menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))

$miLock = $menu.Items.Add('Lock Vault Now')
$miLock.Add_Click({ Invoke-DaemonPost '/api/lock' '{}' })

$miExit = $menu.Items.Add('Exit EnvGuard')
$miExit.Add_Click({
  $tray.Visible = $false
  $tray.Dispose()
  if (Test-Path $DaemonJson) {
    try {
      $d = Get-Content $DaemonJson -Raw | ConvertFrom-Json
      if ($d.pid) { Stop-Process -Id ([int]$d.pid) -Force -ErrorAction SilentlyContinue }
      Remove-Item $DaemonJson -Force -ErrorAction SilentlyContinue
    } catch {}
  }
  [System.Windows.Forms.Application]::Exit()
})

$tray.ContextMenuStrip = $menu
$tray.Add_DoubleClick({ Open-EnvGuardApp })

[System.Windows.Forms.Application]::Run()
$mutex.ReleaseMutex()
$mutex.Dispose()
`;
}

function ensureTrayAgentRunning(port) {
  if (process.platform !== 'win32') {
    return { supported: false };
  }
  const icoPath = ensureIconFile();
  const home = getEnvguardHome();
  ensureDirSync(home);
  const trayScript = path.join(home, 'tray-agent.ps1');
  fs.writeFileSync(trayScript, buildTrayAgentScript(), 'utf8');

  const vltScript = path.resolve(__dirname, '..', 'bin', 'vlt.js');
  const daemonJson = path.join(home, 'daemon.json');

  spawn(
    'powershell.exe',
    [
      '-WindowStyle', 'Hidden',
      '-NoProfile',
      '-STA',
      '-ExecutionPolicy', 'Bypass',
      '-File', trayScript,
      '-Port', String(port),
      '-IconPath', icoPath,
      '-VltScript', vltScript,
      '-NodeExe', process.execPath,
      '-DaemonJson', daemonJson,
    ],
    { detached: true, stdio: 'ignore', windowsHide: true }
  ).unref();

  return { supported: true, iconPath: icoPath };
}

function installDesktopShortcuts() {
  const icoPath = ensureIconFile();
  const vltScript = path.resolve(__dirname, '..', 'bin', 'vlt.js');
  const appExePath = path.resolve(__dirname, '..', 'dist', 'EnvGuard.exe');

  if (process.platform === 'win32') {
    const useExe = fs.existsSync(appExePath);
    if (!useExe) {
      const vbsContent = `Set WshShell = CreateObject("WScript.Shell")\r\nWshShell.Run """${process.execPath}"" ""${vltScript}"" ui", 0, False\r\n`;
      fs.writeFileSync(VBS_LAUNCHER_PATH, vbsContent, 'utf8');
    }

    const ps = `
$shell = New-Object -ComObject WScript.Shell
$desktop = [Environment]::GetFolderPath('Desktop')
$programs = [Environment]::GetFolderPath('Programs')
$targets = @(
  (Join-Path $desktop 'EnvGuard.lnk'),
  (Join-Path $programs 'EnvGuard.lnk')
)
foreach ($lnkPath in $targets) {
  $sc = $shell.CreateShortcut($lnkPath)
  if ($env:ENVGUARD_USE_EXE -eq '1') {
    $sc.TargetPath = $env:ENVGUARD_EXE_PATH
    $sc.Arguments = ''
  } else {
    $sc.TargetPath = 'wscript.exe'
    $sc.Arguments = '//B //Nologo "' + $env:ENVGUARD_VBS_PATH + '"'
  }
  $sc.WorkingDirectory = $env:ENVGUARD_WORKDIR
  $sc.IconLocation = $env:ENVGUARD_ICO_PATH + ',0'
  $sc.Description = 'EnvGuard — Encrypted Secret & Environment Vault'
  $sc.Save()
}
$targets | ConvertTo-Json -Compress
`;
    const out = execFileSync(
      'powershell.exe',
      ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps],
      {
        env: {
          ...process.env,
          ENVGUARD_USE_EXE: useExe ? '1' : '0',
          ENVGUARD_EXE_PATH: appExePath,
          ENVGUARD_VBS_PATH: VBS_LAUNCHER_PATH,
          ENVGUARD_WORKDIR: path.resolve(__dirname, '..'),
          ENVGUARD_ICO_PATH: icoPath,
        },
        encoding: 'utf8',
        windowsHide: true,
      }
    ).trim();
    return { shortcuts: JSON.parse(out), iconPath: icoPath, launcher: useExe ? appExePath : VBS_LAUNCHER_PATH };
  }

  const appsDir = path.join(os.homedir(), '.local', 'share', 'applications');
  ensureDirSync(appsDir);
  const desktopFile = path.join(appsDir, 'envguard.desktop');
  const content = [
    '[Desktop Entry]',
    'Type=Application',
    'Name=EnvGuard',
    'Comment=Encrypted Secret & Environment Vault',
    `Exec=${process.execPath} "${vltScript}" ui`,
    'Terminal=false',
    'Categories=Utility;Security;',
  ].join('\n');
  fs.writeFileSync(desktopFile, content, 'utf8');
  return { shortcuts: [desktopFile], iconPath: icoPath, launcher: vltScript };
}

module.exports = {
  ICON_PATH,
  ensureIconFile,
  openDesktopAppWindow,
  ensureTrayAgentRunning,
  installDesktopShortcuts,
};
