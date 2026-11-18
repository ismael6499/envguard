'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const MAGIC_HEADER = 'VLT2\n';
const PACK_HEADER = 'VLTPACK1:';
const SCRYPT_OPTS = { N: 16384, r: 8, p: 1 };
const MAX_VAR_HISTORY = 5;
const MAX_BACKUPS = 10;
const MAX_AUDIT_LOGS = 500;

const POLICY_LEVELS = {
  session: 1,
  confirm: 2,
  pin_confirm: 3,
  blocked: 4,
};

const LEVEL_TO_POLICY = {
  1: 'session',
  2: 'confirm',
  3: 'pin_confirm',
  4: 'blocked',
};

function getEnvguardHome() {
  if (process.env.ENVGUARD_HOME) {
    return path.resolve(process.env.ENVGUARD_HOME);
  }
  return path.join(os.homedir(), '.envguard');
}

function getConfigPath() {
  return path.join(getEnvguardHome(), 'config.json');
}

function getBackupsDir() {
  return path.join(getEnvguardHome(), 'backups');
}

function ensureDirSync(dirPath) {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true, mode: 0o700 });
  }
}

function loadConfig() {
  const home = getEnvguardHome();
  ensureDirSync(home);
  const cfgPath = getConfigPath();
  const defaults = {
    vaultPath: path.join(home, 'vault.vlt'),
    port: Number(process.env.ENVGUARD_PORT) || 47831,
    autoStartOs: false,
    popupTimeoutSeconds: 30,
    windowBounds: null,
    popupBounds: null,
    linkedDirHints: [],
  };
  if (!fs.existsSync(cfgPath)) {
    return defaults;
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
    return {
      ...defaults,
      ...parsed,
      port: Number(process.env.ENVGUARD_PORT) || Number(parsed.port) || 47831,
      popupTimeoutSeconds: parsed.popupTimeoutSeconds !== undefined
        ? Math.max(0, Number(parsed.popupTimeoutSeconds))
        : 30,
    };
  } catch {
    return defaults;
  }
}

function saveConfig(partialCfg) {
  const current = loadConfig();
  const merged = { ...current, ...partialCfg };
  ensureDirSync(getEnvguardHome());
  fs.writeFileSync(getConfigPath(), JSON.stringify(merged, null, 2), { encoding: 'utf8', mode: 0o600 });
  return merged;
}

function generateRecoveryKey() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const groups = [];
  for (let g = 0; g < 4; g += 1) {
    const bytes = crypto.randomBytes(4);
    let chunk = '';
    for (let i = 0; i < 4; i += 1) {
      chunk += alphabet[bytes[i] % alphabet.length];
    }
    groups.push(chunk);
  }
  return `EVG-${groups.join('-')}`;
}

function normalizeRecoveryKey(keyStr) {
  return String(keyStr || '').trim().toUpperCase().replace(/\s+/g, '');
}

function wrapKeyWithSecret(masterKeyBuffer, secretStr) {
  const salt = crypto.randomBytes(16);
  const derived = crypto.scryptSync(String(secretStr), salt, 32, SCRYPT_OPTS);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', derived, iv);
  const ciphertext = Buffer.concat([cipher.update(masterKeyBuffer), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    salt: salt.toString('hex'),
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
    ciphertext: ciphertext.toString('hex'),
  };
}

function unwrapKeyWithSecret(slot, secretStr, errorCode = 'INVALID_SECRET') {
  try {
    const salt = Buffer.from(slot.salt, 'hex');
    const iv = Buffer.from(slot.iv, 'hex');
    const tag = Buffer.from(slot.tag, 'hex');
    const ciphertext = Buffer.from(slot.ciphertext, 'hex');
    const derived = crypto.scryptSync(String(secretStr), salt, 32, SCRYPT_OPTS);
    const decipher = crypto.createDecipheriv('aes-256-gcm', derived, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    const err = new Error(errorCode);
    err.code = errorCode;
    throw err;
  }
}

function encryptDataWithMasterKey(dataObj, masterKeyBuffer) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', masterKeyBuffer, iv);
  const plaintext = Buffer.from(JSON.stringify(dataObj), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
    ciphertext: ciphertext.toString('hex'),
  };
}

function decryptDataWithMasterKey(dataSlot, masterKeyBuffer) {
  try {
    const iv = Buffer.from(dataSlot.iv, 'hex');
    const tag = Buffer.from(dataSlot.tag, 'hex');
    const ciphertext = Buffer.from(dataSlot.ciphertext, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', masterKeyBuffer, iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return JSON.parse(plaintext.toString('utf8'));
  } catch {
    const err = new Error('VAULT_CORRUPTED_OR_KEY_MISMATCH');
    err.code = 'VAULT_CORRUPTED_OR_KEY_MISMATCH';
    throw err;
  }
}

function serializeEnvelope(envelopeObj) {
  return Buffer.from(MAGIC_HEADER + JSON.stringify(envelopeObj), 'utf8');
}

function parseEnvelope(bufferOrStr) {
  const text = Buffer.isBuffer(bufferOrStr) ? bufferOrStr.toString('utf8') : String(bufferOrStr);
  if (!text.startsWith(MAGIC_HEADER)) {
    const err = new Error('INVALID_VAULT_FORMAT');
    err.code = 'INVALID_VAULT_FORMAT';
    throw err;
  }
  return JSON.parse(text.slice(MAGIC_HEADER.length));
}

function createDefaultVaultData(initialSettings = {}) {
  return {
    schemaVersion: 2,
    settings: {
      defaultTtlMinutes: 240,
      language: 'en',
      requirePinOnStartup: true,
      popupTimeoutSeconds: 30,
      revealPinTtlMinutes: 5,
      ...initialSettings,
    },
    projects: {},
    awsProfiles: {},
    gitCredentials: {},
    linkedDirs: {},
    osEnvBackups: {},
    auditLog: [],
  };
}

function createNewVaultEnvelope(pin, initialSettings = {}) {
  if (!pin || String(pin).length < 4) {
    const err = new Error('PIN_TOO_SHORT');
    err.code = 'PIN_TOO_SHORT';
    throw err;
  }
  const masterKey = crypto.randomBytes(32);
  const recoveryKey = generateRecoveryKey();
  const vaultData = createDefaultVaultData(initialSettings);
  const envelope = {
    version: 2,
    pinSlot: wrapKeyWithSecret(masterKey, String(pin)),
    recoverySlot: wrapKeyWithSecret(masterKey, normalizeRecoveryKey(recoveryKey)),
    dataSlot: encryptDataWithMasterKey(vaultData, masterKey),
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  return {
    envelopeBuffer: serializeEnvelope(envelope),
    envelope,
    recoveryKey,
    masterKey,
    vaultData,
  };
}

function unlockVaultWithPin(envelopeBuffer, pin) {
  const envelope = parseEnvelope(envelopeBuffer);
  const masterKey = unwrapKeyWithSecret(envelope.pinSlot, String(pin), 'INVALID_PIN');
  const vaultData = decryptDataWithMasterKey(envelope.dataSlot, masterKey);
  return { masterKey, vaultData, envelope };
}

function recoverVaultWithKey(envelopeBuffer, recoveryKey, newPin) {
  if (!newPin || String(newPin).length < 4) {
    const err = new Error('PIN_TOO_SHORT');
    err.code = 'PIN_TOO_SHORT';
    throw err;
  }
  const envelope = parseEnvelope(envelopeBuffer);
  const masterKey = unwrapKeyWithSecret(
    envelope.recoverySlot,
    normalizeRecoveryKey(recoveryKey),
    'INVALID_RECOVERY_KEY'
  );
  const vaultData = decryptDataWithMasterKey(envelope.dataSlot, masterKey);
  const updatedEnvelope = {
    ...envelope,
    pinSlot: wrapKeyWithSecret(masterKey, String(newPin)),
    updatedAt: new Date().toISOString(),
  };
  return {
    envelopeBuffer: serializeEnvelope(updatedEnvelope),
    envelope: updatedEnvelope,
    masterKey,
    vaultData,
  };
}

function changeVaultPin(envelopeBuffer, currentPin, newPin) {
  if (!newPin || String(newPin).length < 4) {
    const err = new Error('PIN_TOO_SHORT');
    err.code = 'PIN_TOO_SHORT';
    throw err;
  }
  const { masterKey, vaultData, envelope } = unlockVaultWithPin(envelopeBuffer, currentPin);
  const updatedEnvelope = {
    ...envelope,
    pinSlot: wrapKeyWithSecret(masterKey, String(newPin)),
    updatedAt: new Date().toISOString(),
  };
  return {
    envelopeBuffer: serializeEnvelope(updatedEnvelope),
    envelope: updatedEnvelope,
    masterKey,
    vaultData,
  };
}

function updateVaultData(envelopeBuffer, masterKey, newVaultData) {
  const envelope = parseEnvelope(envelopeBuffer);
  const updatedEnvelope = {
    ...envelope,
    dataSlot: encryptDataWithMasterKey(newVaultData, masterKey),
    updatedAt: new Date().toISOString(),
  };
  return serializeEnvelope(updatedEnvelope);
}

function writeVaultWithBackup(vaultPath, envelopeBuffer) {
  const dir = path.dirname(vaultPath);
  ensureDirSync(dir);
  const backupsDir = getBackupsDir();
  ensureDirSync(backupsDir);

  if (fs.existsSync(vaultPath)) {
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupFile = path.join(backupsDir, `vault-${stamp}.vlt.bak`);
    fs.copyFileSync(vaultPath, backupFile);
    const allBackups = fs
      .readdirSync(backupsDir)
      .filter((f) => f.endsWith('.vlt.bak'))
      .sort();
    while (allBackups.length > MAX_BACKUPS) {
      const oldest = allBackups.shift();
      try {
        fs.unlinkSync(path.join(backupsDir, oldest));
      } catch {
        // Ignore cleanup failure on locked backup file
      }
    }
  }

  const tmpPath = `${vaultPath}.tmp.${process.pid}`;
  fs.writeFileSync(tmpPath, envelopeBuffer, { mode: 0o600 });
  fs.renameSync(tmpPath, vaultPath);
}

function listBackups() {
  const backupsDir = getBackupsDir();
  if (!fs.existsSync(backupsDir)) {
    return [];
  }
  return fs
    .readdirSync(backupsDir)
    .filter((f) => f.endsWith('.vlt.bak'))
    .sort()
    .reverse()
    .map((filename) => {
      const fullPath = path.join(backupsDir, filename);
      const stat = fs.statSync(fullPath);
      return {
        filename,
        sizeBytes: stat.size,
        createdAt: stat.mtime.toISOString(),
      };
    });
}

function ensureProjectEnv(vaultData, project, env, defaultPolicy = 'confirm') {
  if (!vaultData.projects[project]) {
    vaultData.projects[project] = { description: '', environments: {} };
  }
  if (!vaultData.projects[project].environments[env]) {
    vaultData.projects[project].environments[env] = {
      policy: defaultPolicy,
      critical: env === 'prod' || env === 'production',
      vars: {},
    };
  }
  return vaultData.projects[project].environments[env];
}

function setProjectVar(vaultData, project, env, key, newValue, options = {}) {
  const envObj = ensureProjectEnv(vaultData, project, env);
  const now = new Date().toISOString();
  const existing = envObj.vars[key];

  if (existing) {
    const history = Array.isArray(existing.history) ? [...existing.history] : [];
    if (existing.value !== String(newValue)) {
      history.unshift({
        value: existing.value,
        updatedAt: existing.updatedAt || now,
        note: options.note || '',
      });
      if (history.length > MAX_VAR_HISTORY) {
        history.length = MAX_VAR_HISTORY;
      }
    }
    envObj.vars[key] = {
      value: String(newValue),
      policy: options.policy !== undefined ? options.policy : (existing.policy || 'inherit'),
      critical: options.critical !== undefined ? Boolean(options.critical) : Boolean(existing.critical),
      description: options.description !== undefined ? options.description : (existing.description || ''),
      updatedAt: now,
      history,
    };
  } else {
    envObj.vars[key] = {
      value: String(newValue),
      policy: options.policy || 'inherit',
      critical: Boolean(options.critical),
      description: options.description || '',
      updatedAt: now,
      history: [],
    };
  }
  return envObj.vars[key];
}

function rollbackProjectVar(vaultData, project, env, key, historyIndex = 0) {
  const envObj = vaultData.projects?.[project]?.environments?.[env];
  if (!envObj || !envObj.vars?.[key]) {
    const err = new Error('VAR_NOT_FOUND');
    err.code = 'VAR_NOT_FOUND';
    throw err;
  }
  const current = envObj.vars[key];
  const history = Array.isArray(current.history) ? [...current.history] : [];
  if (historyIndex < 0 || historyIndex >= history.length) {
    const err = new Error('HISTORY_INDEX_OUT_OF_RANGE');
    err.code = 'HISTORY_INDEX_OUT_OF_RANGE';
    throw err;
  }
  const targetEntry = history.splice(historyIndex, 1)[0];
  const now = new Date().toISOString();
  history.unshift({
    value: current.value,
    updatedAt: current.updatedAt || now,
    note: 'rollback_prev',
  });
  if (history.length > MAX_VAR_HISTORY) {
    history.length = MAX_VAR_HISTORY;
  }
  envObj.vars[key] = {
    ...current,
    value: targetEntry.value,
    updatedAt: now,
    history,
  };
  return envObj.vars[key];
}

function resolveEffectivePolicy(envObj, requestedKeys = null, callerContext = {}, aiTurboActive = false) {
  const basePolicy = envObj?.policy && POLICY_LEVELS[envObj.policy] ? envObj.policy : 'confirm';
  let maxLevel = POLICY_LEVELS[basePolicy];
  let critical = Boolean(envObj?.critical);
  const criticalKeys = [];
  const pinRequiredKeys = [];
  const blockedKeys = [];

  const vars = envObj?.vars || {};
  const keysToEvaluate = Array.isArray(requestedKeys) && requestedKeys.length > 0
    ? requestedKeys
    : Object.keys(vars);

  for (const k of keysToEvaluate) {
    const entry = vars[k];
    if (!entry) continue;
    if (entry.critical) {
      critical = true;
      criticalKeys.push(k);
    }
    const keyPolicy = entry.policy && entry.policy !== 'inherit' ? entry.policy : basePolicy;
    const lvl = POLICY_LEVELS[keyPolicy] || POLICY_LEVELS.confirm;
    if (lvl > maxLevel) {
      maxLevel = lvl;
    }
    if (keyPolicy === 'pin_confirm') {
      pinRequiredKeys.push(k);
    }
    if (keyPolicy === 'blocked') {
      blockedKeys.push(k);
    }
  }

  let effectivePolicy = LEVEL_TO_POLICY[maxLevel] || 'confirm';
  const isAutomated = Boolean(callerContext.isAiAgent || callerContext.isSuspiciousCommand);
  let escalatedByAi = false;
  let turboBypass = false;

  if (isAutomated) {
    if (aiTurboActive && (effectivePolicy === 'session' || effectivePolicy === 'confirm')) {
      turboBypass = true;
    } else if (!aiTurboActive && effectivePolicy === 'session') {
      effectivePolicy = 'confirm';
      escalatedByAi = true;
    }
  }

  return {
    policy: effectivePolicy,
    critical,
    criticalKeys,
    pinRequiredKeys,
    blockedKeys,
    escalatedByAi,
    turboBypass,
  };
}

function normalizeDirKey(dirPath) {
  const resolved = path.resolve(dirPath).replace(/[\\/]+$/, '');
  return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
}

function linkDirectory(vaultData, dirPath, project, env) {
  if (!vaultData.linkedDirs) vaultData.linkedDirs = {};
  const key = normalizeDirKey(dirPath);
  vaultData.linkedDirs[key] = {
    displayPath: path.resolve(dirPath),
    project,
    env,
    linkedAt: new Date().toISOString(),
  };
  return vaultData.linkedDirs[key];
}

function unlinkDirectory(vaultData, dirPath) {
  if (!vaultData.linkedDirs) return false;
  const key = normalizeDirKey(dirPath);
  if (vaultData.linkedDirs[key]) {
    delete vaultData.linkedDirs[key];
    return true;
  }
  return false;
}

function resolveLinkedDirectory(vaultData, cwd) {
  if (!vaultData.linkedDirs) return null;
  let current = path.resolve(cwd);
  while (true) {
    const key = normalizeDirKey(current);
    if (vaultData.linkedDirs[key]) {
      return { key, ...vaultData.linkedDirs[key] };
    }
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return null;
}

function appendAuditLog(vaultData, entry) {
  if (!Array.isArray(vaultData.auditLog)) {
    vaultData.auditLog = [];
  }
  vaultData.auditLog.unshift({
    id: crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(8).toString('hex'),
    timestamp: new Date().toISOString(),
    ...entry,
  });
  if (vaultData.auditLog.length > MAX_AUDIT_LOGS) {
    vaultData.auditLog.length = MAX_AUDIT_LOGS;
  }
}

function parseEnvString(content) {
  const result = {};
  const lines = String(content || '').split(/\r?\n/);
  for (const rawLine of lines) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const withoutExport = trimmed.startsWith('export ') ? trimmed.slice(7).trim() : trimmed;
    const eqIndex = withoutExport.indexOf('=');
    if (eqIndex <= 0) continue;
    const key = withoutExport.slice(0, eqIndex).trim();
    let val = withoutExport.slice(eqIndex + 1).trim();
    if (
      (val.startsWith('"') && val.endsWith('"') && val.length >= 2) ||
      (val.startsWith("'") && val.endsWith("'") && val.length >= 2)
    ) {
      const quoteChar = val[0];
      val = val.slice(1, -1);
      if (quoteChar === '"') {
        val = val.replace(/\\n/g, '\n').replace(/\\r/g, '\r').replace(/\\"/g, '"');
      }
    } else {
      const hashIdx = val.indexOf(' #');
      if (hashIdx !== -1) {
        val = val.slice(0, hashIdx).trim();
      }
    }
    if (key) {
      result[key] = val;
    }
  }
  return result;
}

function computeImportDiff(existingVarsObj = {}, incomingVarsMap = {}) {
  const added = [];
  const modified = [];
  const unchanged = [];

  for (const [key, newValue] of Object.entries(incomingVarsMap)) {
    const strVal = String(newValue);
    if (!Object.prototype.hasOwnProperty.call(existingVarsObj, key)) {
      added.push({ key, newValue: strVal });
    } else {
      const oldValue = String(existingVarsObj[key].value ?? '');
      if (oldValue !== strVal) {
        modified.push({ key, oldValue, newValue: strVal });
      } else {
        unchanged.push({ key, value: strVal });
      }
    }
  }
  return { added, modified, unchanged };
}

function formatEnvValue(val) {
  const str = String(val ?? '');
  if (str === '') return '';
  if (/[\s#"'\n\r]/.test(str)) {
    return `"${str.replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '\\r')}"`;
  }
  return str;
}

function formatEnvOutput(varsObj, mode, project = '', env = '') {
  const entries = Object.entries(varsObj || {});
  const lines = [];
  for (const [key, entry] of entries) {
    if (mode === 'example') {
      lines.push(`${key}=`);
    } else if (mode === 'tpl') {
      lines.push(`${key}=vlt://${project}/${env}/${key}`);
    } else {
      lines.push(`${key}=${formatEnvValue(entry.value)}`);
    }
  }
  return lines.join('\n') + (lines.length ? '\n' : '');
}

function exportVltPack(payload, transferPassword) {
  if (!transferPassword || String(transferPassword).length < 4) {
    const err = new Error('TRANSFER_PASSWORD_TOO_SHORT');
    err.code = 'TRANSFER_PASSWORD_TOO_SHORT';
    throw err;
  }
  const salt = crypto.randomBytes(16);
  const derived = crypto.scryptSync(String(transferPassword), salt, 32, SCRYPT_OPTS);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', derived, iv);
  const plaintext = Buffer.from(JSON.stringify(payload), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  const packObj = {
    v: 1,
    salt: salt.toString('hex'),
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
    ciphertext: ciphertext.toString('hex'),
  };
  return PACK_HEADER + Buffer.from(JSON.stringify(packObj), 'utf8').toString('base64');
}

function importVltPack(packedStr, transferPassword) {
  const raw = String(packedStr || '').trim();
  if (!raw.startsWith(PACK_HEADER)) {
    const err = new Error('INVALID_VLTPACK_FORMAT');
    err.code = 'INVALID_VLTPACK_FORMAT';
    throw err;
  }
  try {
    const jsonStr = Buffer.from(raw.slice(PACK_HEADER.length), 'base64').toString('utf8');
    const packObj = JSON.parse(jsonStr);
    const salt = Buffer.from(packObj.salt, 'hex');
    const iv = Buffer.from(packObj.iv, 'hex');
    const tag = Buffer.from(packObj.tag, 'hex');
    const ciphertext = Buffer.from(packObj.ciphertext, 'hex');
    const derived = crypto.scryptSync(String(transferPassword), salt, 32, SCRYPT_OPTS);
    const decipher = crypto.createDecipheriv('aes-256-gcm', derived, iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return JSON.parse(plaintext.toString('utf8'));
  } catch {
    const err = new Error('INVALID_TRANSFER_PASSWORD_OR_PACK');
    err.code = 'INVALID_TRANSFER_PASSWORD_OR_PACK';
    throw err;
  }
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function generateSelfDecryptingHtml(project, env, varsToShare, transferPassword) {
  if (!transferPassword || String(transferPassword).length < 4) {
    const err = new Error('TRANSFER_PASSWORD_TOO_SHORT');
    err.code = 'TRANSFER_PASSWORD_TOO_SHORT';
    throw err;
  }
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(String(transferPassword), salt, 100000, 32, 'sha256');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plaintext = Buffer.from(JSON.stringify({ project, env, vars: varsToShare, exportedAt: new Date().toISOString() }), 'utf8');
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  // Web Crypto AES-GCM expects tag appended to ciphertext
  const combined = Buffer.concat([encrypted, tag]);

  const payload = {
    project: escapeHtml(project),
    env: escapeHtml(env),
    count: Object.keys(varsToShare || {}).length,
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    data: combined.toString('base64'),
  };

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>EnvGuard Encrypted Share — ${payload.project} (${payload.env})</title>
<style>
  :root { --bg: #0f172a; --card: #1e293b; --border: #334155; --text: #f8fafc; --muted: #94a3b8; --accent: #3b82f6; --ok: #10b981; --err: #ef4444; }
  * { box-sizing: border-box; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; }
  body { margin: 0; min-height: 100vh; background: var(--bg); color: var(--text); display: flex; align-items: center; justify-content: center; padding: 24px; }
  .card { width: 100%; max-width: 720px; background: var(--card); border: 1px solid var(--border); border-radius: 14px; padding: 28px; box-shadow: 0 20px 50px rgba(0,0,0,0.45); }
  .header { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 18px; }
  .title { font-size: 20px; font-weight: 700; margin: 0; }
  .badge { background: rgba(59,130,246,0.18); color: #93c5fd; border: 1px solid rgba(59,130,246,0.35); padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; }
  .muted { color: var(--muted); font-size: 14px; margin: 0 0 18px 0; }
  .row { display: flex; gap: 10px; flex-wrap: wrap; }
  input[type="password"] { flex: 1; min-width: 220px; padding: 11px 14px; border-radius: 8px; border: 1px solid var(--border); background: #0b1220; color: var(--text); font-size: 15px; }
  button { padding: 10px 16px; border-radius: 8px; border: 1px solid transparent; background: var(--accent); color: #fff; font-weight: 600; cursor: pointer; font-size: 14px; }
  button.secondary { background: #334155; }
  button.success { background: var(--ok); color: #052e16; }
  button:hover { filter: brightness(1.08); }
  .err { color: #fca5a5; background: rgba(239,68,68,0.15); border: 1px solid rgba(239,68,68,0.4); padding: 10px 12px; border-radius: 8px; margin-top: 12px; display: none; font-size: 14px; }
  table { width: 100%; border-collapse: collapse; margin-top: 18px; }
  th, td { text-align: left; padding: 10px; border-bottom: 1px solid var(--border); font-size: 13px; }
  th { color: var(--muted); font-weight: 600; }
  code { font-family: ui-monospace, Consolas, monospace; background: #0b1220; padding: 3px 6px; border-radius: 5px; word-break: break-all; }
  .actions { display: flex; gap: 8px; margin-top: 16px; flex-wrap: wrap; }
  .hidden { display: none; }
</style>
</head>
<body>
<div class="card">
  <div class="header">
    <div>
      <h1 class="title" id="tTitle">EnvGuard Encrypted Secret Share</h1>
      <span class="badge">${payload.project} / ${payload.env} (${payload.count} vars)</span>
    </div>
    <button class="secondary" id="langBtn" type="button">ES / EN</button>
  </div>
  <p class="muted" id="tDesc">Enter the transfer password shared separately with you to decrypt these variables locally in your browser.</p>
  <form id="unlockForm" class="row">
    <input type="password" id="passInput" placeholder="Transfer password..." required />
    <button type="submit" id="tDecryptBtn">Decrypt Secrets</button>
  </form>
  <div id="errBox" class="err"></div>
  <div id="resultBox" class="hidden">
    <div class="actions">
      <button type="button" class="success" id="downloadBtn">Download .env</button>
      <button type="button" class="secondary" id="copyAllBtn">Copy .env</button>
      <button type="button" class="secondary" id="toggleAllBtn">Show / Hide Values</button>
    </div>
    <table>
      <thead><tr><th id="tKeyCol">Key</th><th id="tValCol">Value</th><th></th></tr></thead>
      <tbody id="varsBody"></tbody>
    </table>
  </div>
</div>
<script>
const PAYLOAD = ${JSON.stringify(payload)};
const I18N = {
  en: {
    title: 'EnvGuard Encrypted Secret Share',
    desc: 'Enter the transfer password shared separately with you to decrypt these variables locally in your browser.',
    passPh: 'Transfer password...',
    decrypt: 'Decrypt Secrets',
    badPass: 'Incorrect transfer password or corrupted payload.',
    download: 'Download .env',
    copyAll: 'Copy .env',
    copied: 'Copied!',
    toggle: 'Show / Hide Values',
    keyCol: 'Key',
    valCol: 'Value',
    copy: 'Copy'
  },
  es: {
    title: 'EnvGuard — Paquete de Secretos Cifrado',
    desc: 'Ingresá la contraseña de transferencia que te pasaron aparte para descifrar estas variables localmente en tu navegador.',
    passPh: 'Contraseña de transferencia...',
    decrypt: 'Descifrar Secretos',
    badPass: 'Contraseña incorrecta o archivo dañado.',
    download: 'Descargar .env',
    copyAll: 'Copiar .env',
    copied: '¡Copiado!',
    toggle: 'Mostrar / Ocultar Valores',
    keyCol: 'Variable',
    valCol: 'Valor',
    copy: 'Copiar'
  }
};
let lang = (navigator.language || '').startsWith('es') ? 'es' : 'en';
let decryptedVars = null;
let showValues = false;

function applyLang() {
  const s = I18N[lang];
  document.getElementById('tTitle').textContent = s.title;
  document.getElementById('tDesc').textContent = s.desc;
  document.getElementById('passInput').placeholder = s.passPh;
  document.getElementById('tDecryptBtn').textContent = s.decrypt;
  document.getElementById('downloadBtn').textContent = s.download;
  document.getElementById('copyAllBtn').textContent = s.copyAll;
  document.getElementById('toggleAllBtn').textContent = s.toggle;
  document.getElementById('tKeyCol').textContent = s.keyCol;
  document.getElementById('tValCol').textContent = s.valCol;
  if (decryptedVars) renderTable();
}

function b64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function formatEnvLine(k, v) {
  const s = String(v ?? '');
  if (/[\\s#"'\\n\\r]/.test(s)) return k + '="' + s.replace(/"/g, '\\\\"').replace(/\\n/g, '\\\\n') + '"';
  return k + '=' + s;
}

function buildEnvText() {
  return Object.entries(decryptedVars).map(([k, v]) => formatEnvLine(k, v)).join('\\n') + '\\n';
}

function renderTable() {
  const tbody = document.getElementById('varsBody');
  tbody.innerHTML = '';
  const s = I18N[lang];
  for (const [k, v] of Object.entries(decryptedVars)) {
    const tr = document.createElement('tr');
    const tdK = document.createElement('td');
    const codeK = document.createElement('code');
    codeK.textContent = k;
    tdK.appendChild(codeK);
    const tdV = document.createElement('td');
    const codeV = document.createElement('code');
    codeV.textContent = showValues ? String(v) : '••••••••••••';
    tdV.appendChild(codeV);
    const tdA = document.createElement('td');
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'secondary';
    btn.textContent = s.copy;
    btn.onclick = async () => {
      await navigator.clipboard.writeText(String(v));
      btn.textContent = s.copied;
      setTimeout(() => { btn.textContent = s.copy; }, 1200);
    };
    tdA.appendChild(btn);
    tr.appendChild(tdK);
    tr.appendChild(tdV);
    tr.appendChild(tdA);
    tbody.appendChild(tr);
  }
}

document.getElementById('langBtn').onclick = () => {
  lang = lang === 'en' ? 'es' : 'en';
  applyLang();
};

document.getElementById('toggleAllBtn').onclick = () => {
  showValues = !showValues;
  renderTable();
};

document.getElementById('copyAllBtn').onclick = async (e) => {
  if (!decryptedVars) return;
  await navigator.clipboard.writeText(buildEnvText());
  const btn = e.target;
  btn.textContent = I18N[lang].copied;
  setTimeout(() => { btn.textContent = I18N[lang].copyAll; }, 1200);
};

document.getElementById('downloadBtn').onclick = () => {
  if (!decryptedVars) return;
  const blob = new Blob([buildEnvText()], { type: 'text/plain;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = '.env.' + PAYLOAD.env;
  a.click();
};

document.getElementById('unlockForm').onsubmit = async (e) => {
  e.preventDefault();
  const errBox = document.getElementById('errBox');
  errBox.style.display = 'none';
  try {
    const pass = document.getElementById('passInput').value;
    const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveKey']);
    const aesKey = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: b64ToBytes(PAYLOAD.salt), iterations: 100000, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
    const plainBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64ToBytes(PAYLOAD.iv) },
      aesKey,
      b64ToBytes(PAYLOAD.data)
    );
    const parsed = JSON.parse(new TextDecoder().decode(plainBuf));
    decryptedVars = parsed.vars || {};
    document.getElementById('resultBox').classList.remove('hidden');
    renderTable();
  } catch {
    errBox.textContent = I18N[lang].badPass;
    errBox.style.display = 'block';
  }
};
applyLang();
</script>
</body>
</html>
`;
}

module.exports = {
  POLICY_LEVELS,
  LEVEL_TO_POLICY,
  getEnvguardHome,
  getConfigPath,
  getBackupsDir,
  ensureDirSync,
  loadConfig,
  saveConfig,
  generateRecoveryKey,
  normalizeRecoveryKey,
  createDefaultVaultData,
  createNewVaultEnvelope,
  unlockVaultWithPin,
  recoverVaultWithKey,
  changeVaultPin,
  updateVaultData,
  writeVaultWithBackup,
  listBackups,
  ensureProjectEnv,
  setProjectVar,
  rollbackProjectVar,
  resolveEffectivePolicy,
  normalizeDirKey,
  linkDirectory,
  unlinkDirectory,
  resolveLinkedDirectory,
  appendAuditLog,
  parseEnvString,
  computeImportDiff,
  formatEnvOutput,
  exportVltPack,
  importVltPack,
  generateSelfDecryptingHtml,
};
