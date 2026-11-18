'use strict';

const { execFileSync, spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { setProjectVar } = require('./crypto-vault');

const SENSITIVE_NAME_RX = /(KEY|SECRET|TOKEN|PASS|PWD|AWS|AUTH|CRED|PRIVATE|API|DATABASE_URL|MONGO|REDIS|PGPASSWORD|STRIPE|OPENAI|GEMINI|GH_|GITHUB|GITLAB|NPM_)/i;
const IGNORED_OS_VARS = new Set([
  'PATH', 'PATHEXT', 'TEMP', 'TMP', 'ONEDRIVE', 'ONEDRIVECONSUMER',
  'NUMBER_OF_PROCESSORS', 'OS', 'PROCESSOR_ARCHITECTURE', 'COMSPEC',
  'SYSTEMROOT', 'WINDIR', 'USERPROFILE', 'HOME', 'HOMEDRIVE', 'HOMEPATH',
  'APPDATA', 'LOCALAPPDATA', 'PROGRAMFILES', 'PROGRAMDATA', 'SHELL', 'TERM',
  'LANG', 'LC_ALL', 'PWD', 'OLDPWD', 'SHLVL', 'PS1', 'VSCODE_GIT_ASKPASS_NODE',
]);

function maskSecret(val) {
  const s = String(val || '');
  if (!s) return '';
  if (s.length <= 6) return '••••••';
  return `${s.slice(0, 3)}••••••${s.slice(-3)}`;
}

function parseIniSections(content) {
  const sections = {};
  let current = null;
  for (const rawLine of String(content || '').split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || line.startsWith(';')) continue;
    const secMatch = line.match(/^\[([^\]]+)\]$/);
    if (secMatch) {
      current = secMatch[1].trim();
      if (!sections[current]) sections[current] = {};
      continue;
    }
    if (current) {
      const eq = line.indexOf('=');
      if (eq > 0) {
        const k = line.slice(0, eq).trim();
        const v = line.slice(eq + 1).trim();
        sections[current][k] = v;
      }
    }
  }
  return sections;
}

function getAwsPaths() {
  const awsDir = path.join(os.homedir(), '.aws');
  return {
    awsDir,
    credentialsPath: path.join(awsDir, 'credentials'),
    configPath: path.join(awsDir, 'config'),
  };
}

function readAwsRawMap() {
  const { credentialsPath, configPath } = getAwsPaths();
  const creds = fs.existsSync(credentialsPath) ? parseIniSections(fs.readFileSync(credentialsPath, 'utf8')) : {};
  const configs = fs.existsSync(configPath) ? parseIniSections(fs.readFileSync(configPath, 'utf8')) : {};
  const names = new Set();
  for (const k of Object.keys(creds)) names.add(k);
  for (const k of Object.keys(configs)) {
    names.add(k.startsWith('profile ') ? k.slice(8).trim() : k);
  }
  const result = {};
  for (const name of names) {
    const credSec = creds[name] || {};
    const cfgSec = configs[name === 'default' ? 'default' : `profile ${name}`] || configs[name] || {};
    result[name] = {
      accessKeyId: credSec.aws_access_key_id || '',
      secretAccessKey: credSec.aws_secret_access_key || '',
      sessionToken: credSec.aws_session_token || '',
      region: cfgSec.region || credSec.region || 'us-east-1',
      credentialProcess: cfgSec.credential_process || '',
    };
  }
  return { credentialsExists: fs.existsSync(credentialsPath), configExists: fs.existsSync(configPath), profiles: result };
}

function scanAwsFiles() {
  const raw = readAwsRawMap();
  const profiles = Object.entries(raw.profiles).map(([name, data]) => ({
    name,
    accessKeyIdMasked: maskSecret(data.accessKeyId),
    hasAccessKey: Boolean(data.accessKeyId),
    hasSecretKey: Boolean(data.secretAccessKey),
    region: data.region,
    usesCredentialProcess: Boolean(data.credentialProcess),
    credentialProcessCmd: data.credentialProcess || '',
  }));
  return {
    credentialsExists: raw.credentialsExists,
    configExists: raw.configExists,
    profiles,
  };
}

function importAwsProfilesToVault(vaultData, profileNames = null) {
  const raw = readAwsRawMap();
  const targets = Array.isArray(profileNames) && profileNames.length > 0
    ? profileNames
    : Object.keys(raw.profiles);
  const imported = [];
  for (const name of targets) {
    const p = raw.profiles[name];
    if (!p || (!p.accessKeyId && !p.secretAccessKey)) continue;
    vaultData.awsProfiles[name] = {
      accessKeyId: p.accessKeyId,
      secretAccessKey: p.secretAccessKey,
      sessionToken: p.sessionToken || '',
      region: p.region || 'us-east-1',
      accountId: vaultData.awsProfiles[name]?.accountId || '',
      policy: vaultData.awsProfiles[name]?.policy || 'confirm',
      critical: Boolean(vaultData.awsProfiles[name]?.critical),
      updatedAt: new Date().toISOString(),
    };
    imported.push(name);
  }
  return imported;
}

function configureAwsCredentialProcess(profileName, vltCommand) {
  const { awsDir, configPath } = getAwsPaths();
  if (!fs.existsSync(awsDir)) {
    fs.mkdirSync(awsDir, { recursive: true });
  }
  const sectionHeader = profileName === 'default' ? '[default]' : `[profile ${profileName}]`;
  const cmdLine = `credential_process = ${vltCommand} aws-cred --profile ${profileName}`;

  let content = '';
  if (fs.existsSync(configPath)) {
    content = fs.readFileSync(configPath, 'utf8');
    fs.copyFileSync(configPath, `${configPath}.envguard.bak`);
  }

  const lines = content ? content.split(/\r?\n/) : [];
  let inTarget = false;
  let foundSection = false;
  let replacedKey = false;
  const out = [];

  for (const line of lines) {
    const trimmed = line.trim();
    if (/^\[.+\]$/.test(trimmed)) {
      if (inTarget && !replacedKey) {
        out.push(cmdLine);
        replacedKey = true;
      }
      inTarget = trimmed === sectionHeader;
      if (inTarget) foundSection = true;
      out.push(line);
      continue;
    }
    if (inTarget && /^credential_process\s*=/.test(trimmed)) {
      out.push(cmdLine);
      replacedKey = true;
      continue;
    }
    out.push(line);
  }

  if (inTarget && !replacedKey) {
    out.push(cmdLine);
  } else if (!foundSection) {
    if (out.length > 0 && out[out.length - 1].trim() !== '') out.push('');
    out.push(sectionHeader);
    out.push(cmdLine);
  }

  fs.writeFileSync(configPath, out.join('\n').replace(/\n+$/, '\n'), 'utf8');
  return { configPath, sectionHeader, credentialProcess: cmdLine };
}

function removeAwsPlaintextProfile(profileName) {
  const { credentialsPath } = getAwsPaths();
  if (!fs.existsSync(credentialsPath)) return false;
  const content = fs.readFileSync(credentialsPath, 'utf8');
  fs.copyFileSync(credentialsPath, `${credentialsPath}.envguard.bak`);
  const lines = content.split(/\r?\n/);
  const targetHeader = `[${profileName}]`;
  const out = [];
  let skipping = false;
  let removed = false;
  for (const line of lines) {
    const trimmed = line.trim();
    if (/^\[.+\]$/.test(trimmed)) {
      skipping = trimmed === targetHeader;
      if (skipping) {
        removed = true;
        continue;
      }
    }
    if (!skipping) out.push(line);
  }
  fs.writeFileSync(credentialsPath, out.join('\n').replace(/\n+$/, '\n'), 'utf8');
  return removed;
}

function getGitHelperStatus() {
  const res = spawnSync('git', ['config', '--global', '--get-all', 'credential.helper'], { encoding: 'utf8' });
  const helpers = res.status === 0
    ? res.stdout.split(/\r?\n/).map((s) => s.trim()).filter(Boolean)
    : [];
  const gitCredsPath = path.join(os.homedir(), '.git-credentials');
  const hasPlaintextFile = fs.existsSync(gitCredsPath);
  const plaintextCount = hasPlaintextFile
    ? fs.readFileSync(gitCredsPath, 'utf8').split(/\r?\n/).filter((l) => l.trim() && !l.trim().startsWith('#')).length
    : 0;
  return {
    helpers,
    usesEnvGuard: helpers.some((h) => /envguard|vlt|git-cred/i.test(h)),
    hasPlaintextFile,
    plaintextCount,
  };
}

function configureGitCredentialHelper(enable, vltCommand) {
  if (enable) {
    const normalizedCmd = String(vltCommand).replace(/\\/g, '/');
    const helperVal = `!${normalizedCmd} git-cred`;
    execFileSync('git', ['config', '--global', 'credential.helper', helperVal], { encoding: 'utf8' });
    return { enabled: true, helper: helperVal };
  }
  spawnSync('git', ['config', '--global', '--unset-all', 'credential.helper'], { encoding: 'utf8' });
  return { enabled: false, helper: null };
}

function readWindowsUserEnvMap() {
  if (process.platform !== 'win32') return {};
  try {
    const out = execFileSync(
      'powershell.exe',
      [
        '-NoProfile',
        '-ExecutionPolicy',
        'Bypass',
        '-Command',
        '[Environment]::GetEnvironmentVariables("User") | ConvertTo-Json -Compress',
      ],
      { encoding: 'utf8', windowsHide: true }
    ).trim();
    if (!out) return {};
    return JSON.parse(out);
  } catch {
    return {};
  }
}

function readLinuxUserEnvMap() {
  const map = {};
  const candidates = ['.bashrc', '.zshrc', '.profile'].map((f) => path.join(os.homedir(), f));
  for (const file of candidates) {
    if (!fs.existsSync(file)) continue;
    const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/);
    for (const line of lines) {
      const m = line.match(/^\s*export\s+([A-Za-z_][A-Za-z0-9_]*)=(.+)$/);
      if (m) {
        let val = m[2].trim();
        if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
          val = val.slice(1, -1);
        }
        map[m[1]] = { value: val, source: path.basename(file) };
      }
    }
  }
  return map;
}

function scanUserOsEnv() {
  const items = [];
  if (process.platform === 'win32') {
    const envMap = readWindowsUserEnvMap();
    for (const [name, value] of Object.entries(envMap)) {
      if (IGNORED_OS_VARS.has(name.toUpperCase())) continue;
      items.push({
        name,
        maskedValue: maskSecret(value),
        length: String(value || '').length,
        suspicious: SENSITIVE_NAME_RX.test(name),
        source: 'Windows User (HKCU\\Environment)',
      });
    }
  } else {
    const linuxMap = readLinuxUserEnvMap();
    for (const [name, info] of Object.entries(linuxMap)) {
      if (IGNORED_OS_VARS.has(name.toUpperCase())) continue;
      items.push({
        name,
        maskedValue: maskSecret(info.value),
        length: String(info.value || '').length,
        suspicious: SENSITIVE_NAME_RX.test(name),
        source: info.source,
      });
    }
  }
  items.sort((a, b) => Number(b.suspicious) - Number(a.suspicious) || a.name.localeCompare(b.name));
  return { platform: process.platform, items };
}

function setWindowsUserEnvVar(name, valueOrNull) {
  const psScript = valueOrNull === null
    ? '[Environment]::SetEnvironmentVariable($env:ENVGUARD_VAR_NAME, $null, "User")'
    : '[Environment]::SetEnvironmentVariable($env:ENVGUARD_VAR_NAME, $env:ENVGUARD_VAR_VAL, "User")';
  execFileSync(
    'powershell.exe',
    ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', psScript],
    {
      env: {
        ...process.env,
        ENVGUARD_VAR_NAME: String(name),
        ENVGUARD_VAR_VAL: valueOrNull === null ? '' : String(valueOrNull),
      },
      windowsHide: true,
    }
  );
}

function migrateOsEnvToVault(vaultData, varNames, targetProject, targetEnv, removeFromOs = false) {
  const migrated = [];
  if (process.platform === 'win32') {
    const envMap = readWindowsUserEnvMap();
    for (const name of varNames) {
      if (!Object.prototype.hasOwnProperty.call(envMap, name)) continue;
      const val = String(envMap[name]);
      vaultData.osEnvBackups[name] = {
        originalValue: val,
        scope: 'User',
        migratedAt: new Date().toISOString(),
        projectTarget: targetProject,
        envTarget: targetEnv,
        removedFromOs: Boolean(removeFromOs),
      };
      setProjectVar(vaultData, targetProject, targetEnv, name, val, { note: 'migrated_from_os_env' });
      if (removeFromOs) {
        setWindowsUserEnvVar(name, null);
      }
      migrated.push(name);
    }
  } else {
    const linuxMap = readLinuxUserEnvMap();
    for (const name of varNames) {
      if (!Object.prototype.hasOwnProperty.call(linuxMap, name)) continue;
      const val = String(linuxMap[name].value);
      vaultData.osEnvBackups[name] = {
        originalValue: val,
        scope: linuxMap[name].source,
        migratedAt: new Date().toISOString(),
        projectTarget: targetProject,
        envTarget: targetEnv,
        removedFromOs: false,
      };
      setProjectVar(vaultData, targetProject, targetEnv, name, val, { note: 'migrated_from_os_env' });
      migrated.push(name);
    }
  }
  return migrated;
}

function restoreOsEnvFromBackup(vaultData, varName) {
  const backup = vaultData.osEnvBackups?.[varName];
  if (!backup) {
    const err = new Error('BACKUP_NOT_FOUND');
    err.code = 'BACKUP_NOT_FOUND';
    throw err;
  }
  if (process.platform === 'win32') {
    setWindowsUserEnvVar(varName, backup.originalValue);
    backup.removedFromOs = false;
    backup.restoredAt = new Date().toISOString();
    return { restored: true, scope: 'Windows User Env' };
  }
  return { restored: false, value: backup.originalValue, scope: backup.scope };
}

function getOsAutoStartStatus() {
  if (process.platform === 'win32') {
    const res = spawnSync(
      'reg',
      ['query', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', '/v', 'EnvGuardDaemon'],
      { encoding: 'utf8', windowsHide: true }
    );
    return res.status === 0;
  }
  const desktopFile = path.join(os.homedir(), '.config', 'autostart', 'envguard.desktop');
  return fs.existsSync(desktopFile);
}

function setOsAutoStart(enable, daemonScriptPath) {
  if (process.platform === 'win32') {
    const regKey = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run';
    if (enable) {
      const nodeExe = process.execPath;
      const cmd = `powershell.exe -WindowStyle Hidden -NoProfile -Command "Start-Process -FilePath '${nodeExe}' -ArgumentList '\\"${daemonScriptPath}\\"' -WindowStyle Hidden"`;
      execFileSync('reg', ['add', regKey, '/v', 'EnvGuardDaemon', '/t', 'REG_SZ', '/d', cmd, '/f'], { windowsHide: true });
      return true;
    }
    spawnSync('reg', ['delete', regKey, '/v', 'EnvGuardDaemon', '/f'], { windowsHide: true });
    return false;
  }

  const autostartDir = path.join(os.homedir(), '.config', 'autostart');
  const desktopFile = path.join(autostartDir, 'envguard.desktop');
  if (enable) {
    if (!fs.existsSync(autostartDir)) fs.mkdirSync(autostartDir, { recursive: true });
    const content = [
      '[Desktop Entry]',
      'Type=Application',
      'Name=EnvGuard Daemon',
      `Exec=${process.execPath} ${daemonScriptPath}`,
      'Hidden=false',
      'NoDisplay=true',
      'X-GNOME-Autostart-enabled=true',
    ].join('\n');
    fs.writeFileSync(desktopFile, content, 'utf8');
    return true;
  }
  if (fs.existsSync(desktopFile)) fs.unlinkSync(desktopFile);
  return false;
}

const HOOK_START = '# >>> EnvGuard Auto-Hook >>>';
const HOOK_END = '# <<< EnvGuard Auto-Hook <<<';

function getShellProfilePaths() {
  if (process.platform === 'win32') {
    const docs = path.join(os.homedir(), 'Documents');
    return [
      path.join(docs, 'PowerShell', 'Microsoft.PowerShell_profile.ps1'),
      path.join(docs, 'WindowsPowerShell', 'Microsoft.PowerShell_profile.ps1'),
    ];
  }
  return [
    path.join(os.homedir(), '.bashrc'),
    path.join(os.homedir(), '.zshrc'),
  ];
}

function buildShellHookBlock() {
  if (process.platform === 'win32') {
    return `${HOOK_START}
function Invoke-EnvGuardAutoWrap {
  param([string]$ToolName, [object[]]$ToolArgs)
  if (-not $env:ENVGUARD_ACTIVE) {
    $null = & vlt is-linked $PWD.Path 2>$null
    if ($LASTEXITCODE -eq 0) {
      & vlt run -- $ToolName @ToolArgs
      return
    }
  }
  $realCmd = Get-Command $ToolName -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($realCmd) {
    & $realCmd.Source @ToolArgs
  } else {
    Write-Error "Command not found: $ToolName"
  }
}
foreach ($t in @('mvn','gradle','java','npm','pnpm','yarn','node','python','dotnet')) {
  Set-Item -Path "Function:global:$t" -Value ([scriptblock]::Create("Invoke-EnvGuardAutoWrap '$t' " + '$args'))
}
${HOOK_END}`;
  }

  return `${HOOK_START}
_envguard_wrap() {
  local tool="$1"; shift
  if [ -z "$ENVGUARD_ACTIVE" ] && command -v vlt >/dev/null 2>&1; then
    if vlt is-linked "$PWD" >/dev/null 2>&1; then
      vlt run -- "$tool" "$@"
      return $?
    fi
  fi
  command "$tool" "$@"
}
for _t in mvn gradle java npm pnpm yarn node python python3 dotnet; do
  eval "$_t() { _envguard_wrap $_t \"\\$@\"; }"
done
${HOOK_END}`;
}

function getShellAutoHookStatus() {
  const paths = getShellProfilePaths();
  let installed = false;
  for (const p of paths) {
    if (fs.existsSync(p) && fs.readFileSync(p, 'utf8').includes(HOOK_START)) {
      installed = true;
    }
  }
  return { installed, profiles: paths };
}

function stripHookBlock(content) {
  const rx = new RegExp(`\\r?\\n?${HOOK_START}[\\s\\S]*?${HOOK_END}\\r?\\n?`, 'g');
  return content.replace(rx, '\n').trimEnd();
}

function installShellAutoHook() {
  const block = buildShellHookBlock();
  const updated = [];
  for (const p of getShellProfilePaths()) {
    const dir = path.dirname(p);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const prev = fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : '';
    const cleaned = stripHookBlock(prev);
    const next = cleaned ? `${cleaned}\n\n${block}\n` : `${block}\n`;
    fs.writeFileSync(p, next, 'utf8');
    updated.push(p);
  }
  return { installed: true, profiles: updated };
}

function removeShellAutoHook() {
  const updated = [];
  for (const p of getShellProfilePaths()) {
    if (!fs.existsSync(p)) continue;
    const prev = fs.readFileSync(p, 'utf8');
    if (prev.includes(HOOK_START)) {
      const cleaned = stripHookBlock(prev);
      fs.writeFileSync(p, cleaned ? `${cleaned}\n` : '', 'utf8');
      updated.push(p);
    }
  }
  return { installed: false, profiles: updated };
}

module.exports = {
  maskSecret,
  parseIniSections,
  getAwsPaths,
  scanAwsFiles,
  importAwsProfilesToVault,
  configureAwsCredentialProcess,
  removeAwsPlaintextProfile,
  getGitHelperStatus,
  configureGitCredentialHelper,
  scanUserOsEnv,
  migrateOsEnvToVault,
  restoreOsEnvFromBackup,
  getOsAutoStartStatus,
  setOsAutoStart,
  getShellAutoHookStatus,
  installShellAutoHook,
  removeShellAutoHook,
};
