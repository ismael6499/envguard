'use strict';

const fs = require('fs');
const http = require('http');
const path = require('path');
const {
  POLICY_LEVELS,
  LEVEL_TO_POLICY,
  getEnvguardHome,
  ensureDirSync,
  loadConfig,
  saveConfig,
  createNewVaultEnvelope,
  unlockVaultWithPin,
  recoverVaultWithKey,
  changeVaultPin,
  updateVaultData,
  writeVaultWithBackup,
  listBackups,
  getBackupsDir,
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
} = require('./crypto-vault');
const { inspectCallerProcess, requestUserAuthorization } = require('./native-popup');
const {
  maskSecret,
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
} = require('./integrations');

function getDaemonInfoPath() {
  return path.join(getEnvguardHome(), 'daemon.json');
}

function createDaemonState() {
  return {
    masterKey: null,
    sessionExpiresAt: null,
    revealUnlockedUntil: 0,
    aiTurboUntil: 0,
    scopeApprovals: new Map(),
    pendingAuditEvents: [],
    lastLanguage: 'en',
  };
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > 5 * 1024 * 1024) {
        reject(new Error('PAYLOAD_TOO_LARGE'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (chunks.length === 0) return resolve({});
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(new Error('INVALID_JSON'));
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res, statusCode, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(body);
}

function sendStaticFile(res, filePath, contentType) {
  if (!fs.existsSync(filePath)) {
    res.writeHead(404);
    res.end('Not Found');
    return;
  }
  const content = fs.readFileSync(filePath);
  res.writeHead(200, {
    'Content-Type': contentType,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(content);
}

function formatJavaProperties(varsMap) {
  return Object.entries(varsMap || {})
    .map(([k, v]) => {
      const escaped = String(v ?? '')
        .replace(/\\/g, '\\\\')
        .replace(/\r/g, '\\r')
        .replace(/\n/g, '\\n');
      return `${k}=${escaped}`;
    })
    .join('\n') + '\n';
}

function startServer(portOverride = null) {
  const state = createDaemonState();

  function lockSession() {
    if (state.masterKey) {
      state.masterKey.fill(0);
    }
    state.masterKey = null;
    state.sessionExpiresAt = null;
    state.revealUnlockedUntil = 0;
    state.aiTurboUntil = 0;
    state.scopeApprovals.clear();
  }

  function isRevealAuthorized(vaultData) {
    if (!state.masterKey || !vaultData) return false;
    const ttl = Number(vaultData.settings?.revealPinTtlMinutes ?? 5);
    if (ttl === -1) return true;
    if (ttl === 0) return false;
    return Date.now() < state.revealUnlockedUntil;
  }

  function isSessionValid() {
    if (!state.masterKey) return false;
    if (state.sessionExpiresAt === Infinity) return true;
    if (typeof state.sessionExpiresAt === 'number' && Date.now() < state.sessionExpiresAt) {
      return true;
    }
    lockSession();
    return false;
  }

  function applySessionTtl(ttlMinutes) {
    const mins = Number(ttlMinutes);
    if (mins === -1) {
      state.sessionExpiresAt = Infinity;
    } else if (mins === 0) {
      state.sessionExpiresAt = Date.now() + 5000;
    } else {
      state.sessionExpiresAt = Date.now() + Math.max(1, mins) * 60000;
    }
  }

  function isAiTurboActive() {
    return isSessionValid() && state.aiTurboUntil > Date.now();
  }

  function getVaultEnvelopeBuffer() {
    const cfg = loadConfig();
    if (!fs.existsSync(cfg.vaultPath)) return null;
    return fs.readFileSync(cfg.vaultPath);
  }

  function readUnlockedVault(masterKeyOverride = null) {
    const cfg = loadConfig();
    const buf = getVaultEnvelopeBuffer();
    if (!buf) {
      const err = new Error('VAULT_NOT_INITIALIZED');
      err.code = 'VAULT_NOT_INITIALIZED';
      throw err;
    }
    const key = masterKeyOverride || (isSessionValid() ? state.masterKey : null);
    if (!key) {
      const err = new Error('VAULT_LOCKED');
      err.code = 'VAULT_LOCKED';
      throw err;
    }
    // Decrypt envelope using update-compatible parse
    const crypto = require('crypto');
    const text = buf.toString('utf8');
    const envObj = JSON.parse(text.slice(5));
    const slot = envObj.dataSlot;
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(slot.iv, 'hex'));
    decipher.setAuthTag(Buffer.from(slot.tag, 'hex'));
    const plain = Buffer.concat([
      decipher.update(Buffer.from(slot.ciphertext, 'hex')),
      decipher.final(),
    ]);
    const vaultData = JSON.parse(plain.toString('utf8'));
    if (vaultData?.settings?.language) {
      state.lastLanguage = vaultData.settings.language;
    }
    flushPendingAuditEvents(vaultData);
    return { cfg, buf, vaultData };
  }

  function flushPendingAuditEvents(vaultData) {
    if (state.pendingAuditEvents.length > 0) {
      for (const ev of state.pendingAuditEvents.reverse()) {
        appendAuditLog(vaultData, ev);
      }
      state.pendingAuditEvents = [];
    }
  }

  function persistVaultData(vaultData, masterKeyOverride = null) {
    const cfg = loadConfig();
    const buf = getVaultEnvelopeBuffer();
    const key = masterKeyOverride || state.masterKey;
    const updatedBuf = updateVaultData(buf, key, vaultData);
    writeVaultWithBackup(cfg.vaultPath, updatedBuf);
  }

  function recordAudit(vaultData, entry, persist = true) {
    if (vaultData && state.masterKey) {
      appendAuditLog(vaultData, entry);
      if (persist) persistVaultData(vaultData);
    } else {
      state.pendingAuditEvents.unshift({
        id: Math.random().toString(16).slice(2),
        timestamp: new Date().toISOString(),
        ...entry,
      });
      if (state.pendingAuditEvents.length > 100) {
        state.pendingAuditEvents.length = 100;
      }
    }
  }

  function getStatusPayload() {
    const cfg = loadConfig();
    const initialized = fs.existsSync(cfg.vaultPath);
    const unlocked = isSessionValid();
    let remainingSeconds = 0;
    if (unlocked) {
      remainingSeconds = state.sessionExpiresAt === Infinity
        ? -1
        : Math.max(0, Math.floor((state.sessionExpiresAt - Date.now()) / 1000));
    }
    const turboRemainingSeconds = isAiTurboActive()
      ? Math.max(0, Math.floor((state.aiTurboUntil - Date.now()) / 1000))
      : 0;

    let summary = {
      defaultTtlMinutes: 240,
      popupTimeoutSeconds: cfg.popupTimeoutSeconds ?? 30,
      revealPinTtlMinutes: 5,
      revealAuthorized: false,
      language: state.lastLanguage || 'en',
      projectCount: 0,
      awsCount: 0,
      gitCount: 0,
    };

    if (initialized && unlocked) {
      try {
        const { vaultData } = readUnlockedVault();
        summary = {
          defaultTtlMinutes: vaultData.settings?.defaultTtlMinutes ?? 240,
          popupTimeoutSeconds: vaultData.settings?.popupTimeoutSeconds ?? cfg.popupTimeoutSeconds ?? 30,
          revealPinTtlMinutes: vaultData.settings?.revealPinTtlMinutes ?? 5,
          revealAuthorized: isRevealAuthorized(vaultData),
          language: vaultData.settings?.language || 'en',
          projectCount: Object.keys(vaultData.projects || {}).length,
          awsCount: Object.keys(vaultData.awsProfiles || {}).length,
          gitCount: Object.keys(vaultData.gitCredentials || {}).length,
        };
      } catch {
        // Ignore if unreadable
      }
    }

    return {
      initialized,
      unlocked,
      remainingSeconds,
      untilLocked: state.sessionExpiresAt === Infinity,
      aiTurboActive: turboRemainingSeconds > 0,
      aiTurboRemainingSeconds: turboRemainingSeconds,
      vaultPath: cfg.vaultPath,
      port: cfg.port,
      autoStartOs: getOsAutoStartStatus(),
      ...summary,
    };
  }

  function sanitizeProjectsForUi(vaultData) {
    return vaultData.projects || {};
  }

  function resolveSingleResourcePolicy(itemPolicy, itemCritical, callerCtx, turboActive) {
    const base = POLICY_LEVELS[itemPolicy] ? itemPolicy : 'confirm';
    let effective = base;
    let escalatedByAi = false;
    let turboBypass = false;
    const isAutomated = Boolean(callerCtx.isAiAgent || callerCtx.isSuspiciousCommand);

    if (isAutomated) {
      if (turboActive && (effective === 'session' || effective === 'confirm')) {
        turboBypass = true;
      } else if (!turboActive && effective === 'session') {
        effective = 'confirm';
        escalatedByAi = true;
      }
    }
    return {
      policy: effective,
      critical: Boolean(itemCritical),
      criticalKeys: [],
      escalatedByAi,
      turboBypass,
    };
  }

  async function executeAuthorizeAndFetch(body) {
    const buf = getVaultEnvelopeBuffer();
    if (!buf) {
      return { status: 400, body: { error: 'VAULT_NOT_INITIALIZED' } };
    }

    const resourceType = body.resourceType || 'env';
    const callerCommand = body.callerCommand || 'vlt';
    const cwd = body.cwd || process.cwd();
    const callerCtx = await inspectCallerProcess(body.callerPid, callerCommand, body.envHints || {});

    let promptedAbove = false;
    let oneShotLockAfter = false;
    let vaultData = null;

    let initialResourceLabel = '';
    if (resourceType === 'aws') {
      initialResourceLabel = `AWS Profile: ${body.profile || 'default'}`;
    } else if (resourceType === 'git') {
      initialResourceLabel = `Git Host: ${body.host || 'unknown'}`;
    } else {
      initialResourceLabel = body.project ? `${body.project} (${body.env || 'dev'})` : `Linked Dir (${cwd})`;
    }

    if (!isSessionValid()) {
      const cfg = loadConfig();
      promptedAbove = true;
      const auth = await requestUserAuthorization({
        isVaultLocked: true,
        effectivePolicy: 'pin_confirm',
        critical: false,
        criticalKeys: [],
        callerCommand,
        processChain: callerCtx.chainText,
        cwd,
        resourceLabel: initialResourceLabel,
        isAiAgent: callerCtx.isAiAgent,
        isSuspiciousCommand: callerCtx.isSuspiciousCommand,
        defaultTtlMinutes: 240,
        timeoutSeconds: cfg.popupTimeoutSeconds ?? 30,
        popupBounds: cfg.popupBounds || null,
        lang: state.lastLanguage,
      });

      if (typeof auth.popupX === 'number' && typeof auth.popupY === 'number') {
        saveConfig({ popupBounds: { x: auth.popupX, y: auth.popupY } });
      }

      if (!auth.approved) {
        recordAudit(null, {
          callerCommand,
          processChain: callerCtx.chainText,
          cwd,
          resourceType,
          resourceName: initialResourceLabel,
          effectivePolicy: 'pin_confirm',
          critical: false,
          isAiAgent: callerCtx.isAiAgent,
          decision: 'DENIED',
          reason: auth.timedOut ? 'popup_timeout_while_locked' : 'user_cancelled_while_locked',
        }, false);
        return { status: 403, body: { error: auth.timedOut ? 'POPUP_TIMEOUT' : 'ACCESS_DENIED' } };
      }

      try {
        const unlocked = unlockVaultWithPin(buf, auth.pin || '');
        state.masterKey = unlocked.masterKey;
        vaultData = unlocked.vaultData;
        const chosenTtl = Number(auth.ttlMinutes ?? vaultData.settings?.defaultTtlMinutes ?? 240);
        if (chosenTtl === 0) {
          oneShotLockAfter = true;
          state.sessionExpiresAt = Date.now() + 15000;
        } else {
          applySessionTtl(chosenTtl);
          if (auth.enableTurboMinutes > 0) {
            state.aiTurboUntil = Date.now() + Number(auth.enableTurboMinutes) * 60000;
          }
        }
      } catch {
        recordAudit(null, {
          callerCommand,
          processChain: callerCtx.chainText,
          cwd,
          resourceType,
          resourceName: initialResourceLabel,
          effectivePolicy: 'pin_confirm',
          critical: false,
          isAiAgent: callerCtx.isAiAgent,
          decision: 'DENIED',
          reason: 'invalid_pin',
        }, false);
        return { status: 401, body: { error: 'INVALID_PIN' } };
      }
    } else {
      vaultData = readUnlockedVault().vaultData;
    }

    flushPendingAuditEvents(vaultData);
    const turboActive = isAiTurboActive();
    let project = body.project;
    let env = body.env;

    if (resourceType === 'env' && !project) {
      const linked = resolveLinkedDirectory(vaultData, cwd);
      if (linked) {
        project = linked.project;
        env = env || linked.env;
      }
    }
    if (resourceType === 'env' && project && !env) {
      const envNames = Object.keys(vaultData.projects?.[project]?.environments || {});
      env = envNames.includes('dev') ? 'dev' : (envNames[0] || 'dev');
    }

    let evalResult;
    let scopeKey = '';
    let resourceLabel = initialResourceLabel;
    let resultData = null;

    if (resourceType === 'env') {
      const envObj = vaultData.projects?.[project]?.environments?.[env];
      if (!envObj) {
        if (oneShotLockAfter) lockSession();
        return { status: 404, body: { error: 'ENV_NOT_FOUND', project, env } };
      }
      resourceLabel = `${project} (${env})`;
      scopeKey = `env:${project}:${env}`;
      const requestedKeys = Array.isArray(body.keys) && body.keys.length > 0 ? body.keys : null;
      evalResult = resolveEffectivePolicy(envObj, requestedKeys, callerCtx, turboActive);
      const varsOut = {};
      const keysList = requestedKeys || Object.keys(envObj.vars || {});
      for (const k of keysList) {
        if (envObj.vars[k]) varsOut[k] = envObj.vars[k].value;
      }
      resultData = { project, env, vars: varsOut };
    } else if (resourceType === 'aws') {
      const profileName = body.profile || 'default';
      const prof = vaultData.awsProfiles?.[profileName];
      if (!prof) {
        if (oneShotLockAfter) lockSession();
        return { status: 404, body: { error: 'AWS_PROFILE_NOT_FOUND', profile: profileName } };
      }
      resourceLabel = `AWS Profile: ${profileName}`;
      scopeKey = `aws:${profileName}`;
      evalResult = resolveSingleResourcePolicy(prof.policy, prof.critical, callerCtx, turboActive);
      resultData = {
        Version: 1,
        AccessKeyId: prof.accessKeyId,
        SecretAccessKey: prof.secretAccessKey,
        ...(prof.sessionToken ? { SessionToken: prof.sessionToken } : {}),
        Region: prof.region || 'us-east-1',
      };
    } else if (resourceType === 'git') {
      const host = String(body.host || '').toLowerCase();
      const creds = Object.values(vaultData.gitCredentials || {});
      const match = creds.find((c) => {
        const hostMatch = String(c.host || '').toLowerCase() === host;
        if (!hostMatch) return false;
        if (body.username && c.username && c.username !== body.username) return false;
        return true;
      });
      if (!match) {
        if (oneShotLockAfter) lockSession();
        return { status: 404, body: { error: 'GIT_CREDENTIAL_NOT_FOUND', host } };
      }
      resourceLabel = `Git: ${match.host} (${match.username})`;
      scopeKey = `git:${match.host}`;
      evalResult = resolveSingleResourcePolicy(match.policy, match.critical, callerCtx, turboActive);
      resultData = {
        protocol: match.protocol || 'https',
        host: match.host,
        username: match.username,
        password: match.token,
      };
    } else {
      if (oneShotLockAfter) lockSession();
      return { status: 400, body: { error: 'UNKNOWN_RESOURCE_TYPE' } };
    }

    if (evalResult.policy === 'blocked') {
      recordAudit(vaultData, {
        callerCommand,
        processChain: callerCtx.chainText,
        cwd,
        resourceType,
        resourceName: resourceLabel,
        effectivePolicy: 'blocked',
        critical: evalResult.critical,
        isAiAgent: callerCtx.isAiAgent,
        decision: 'DENIED',
        reason: 'policy_blocked',
      });
      if (oneShotLockAfter) lockSession();
      return { status: 403, body: { error: 'POLICY_BLOCKED' } };
    }

    const scopeExp = state.scopeApprovals.get(scopeKey);
    const scopeValid = scopeExp === Infinity || (typeof scopeExp === 'number' && scopeExp > Date.now());
    const needsSecondaryPopup = !promptedAbove && (
      evalResult.policy === 'pin_confirm' ||
      (evalResult.policy === 'confirm' && !evalResult.turboBypass && !scopeValid)
    );

    let decisionReason = evalResult.turboBypass
      ? 'ai_turbo_bypass'
      : (promptedAbove ? 'pin_unlocked_and_approved' : (scopeValid ? 'scope_cache' : 'session_pass'));

    if (needsSecondaryPopup) {
      const cfg = loadConfig();
      const timeoutSeconds = vaultData.settings?.popupTimeoutSeconds !== undefined
        ? Number(vaultData.settings.popupTimeoutSeconds)
        : (cfg.popupTimeoutSeconds ?? 30);
      const auth = await requestUserAuthorization({
        isVaultLocked: false,
        effectivePolicy: evalResult.policy,
        critical: evalResult.critical,
        criticalKeys: evalResult.criticalKeys,
        callerCommand,
        processChain: callerCtx.chainText,
        cwd,
        resourceLabel,
        isAiAgent: callerCtx.isAiAgent,
        isSuspiciousCommand: callerCtx.isSuspiciousCommand,
        defaultTtlMinutes: vaultData.settings?.defaultTtlMinutes ?? 240,
        timeoutSeconds,
        popupBounds: cfg.popupBounds || null,
        lang: vaultData.settings?.language || state.lastLanguage,
      });

      if (typeof auth.popupX === 'number' && typeof auth.popupY === 'number') {
        saveConfig({ popupBounds: { x: auth.popupX, y: auth.popupY } });
      }

      if (!auth.approved) {
        recordAudit(vaultData, {
          callerCommand,
          processChain: callerCtx.chainText,
          cwd,
          resourceType,
          resourceName: resourceLabel,
          effectivePolicy: evalResult.policy,
          critical: evalResult.critical,
          isAiAgent: callerCtx.isAiAgent,
          decision: 'DENIED',
          reason: auth.timedOut ? 'popup_timeout' : 'user_cancelled',
        });
        return { status: 403, body: { error: auth.timedOut ? 'POPUP_TIMEOUT' : 'ACCESS_DENIED' } };
      }

      if (evalResult.policy === 'pin_confirm') {
        try {
          unlockVaultWithPin(buf, auth.pin || '');
          decisionReason = 'pin_confirmed';
        } catch {
          recordAudit(vaultData, {
            callerCommand,
            processChain: callerCtx.chainText,
            cwd,
            resourceType,
            resourceName: resourceLabel,
            effectivePolicy: 'pin_confirm',
            critical: evalResult.critical,
            isAiAgent: callerCtx.isAiAgent,
            decision: 'DENIED',
            reason: 'invalid_pin',
          });
          return { status: 401, body: { error: 'INVALID_PIN' } };
        }
      } else {
        decisionReason = 'user_confirmed';
        const ttlMins = Number(auth.ttlMinutes ?? 0);
        if (ttlMins === -1) {
          state.scopeApprovals.set(scopeKey, Infinity);
        } else if (ttlMins > 0) {
          state.scopeApprovals.set(scopeKey, Date.now() + ttlMins * 60000);
        }
      }

      if (auth.enableTurboMinutes > 0) {
        state.aiTurboUntil = Date.now() + Number(auth.enableTurboMinutes) * 60000;
      }
    }

    recordAudit(vaultData, {
      callerCommand,
      processChain: callerCtx.chainText,
      cwd,
      resourceType,
      resourceName: resourceLabel,
      effectivePolicy: evalResult.policy,
      critical: evalResult.critical,
      isAiAgent: callerCtx.isAiAgent,
      decision: evalResult.turboBypass ? 'ALLOWED (AI Turbo)' : 'ALLOWED',
      reason: decisionReason,
    });

    if (oneShotLockAfter) {
      lockSession();
    }

    return {
      status: 200,
      body: {
        ok: true,
        policy: evalResult.policy,
        critical: evalResult.critical,
        turboBypass: evalResult.turboBypass,
        data: resultData,
      },
    };
  }

  const uiDir = path.join(__dirname, 'ui');
  const localesDir = path.join(__dirname, 'i18n', 'locales');

  const server = http.createServer(async (req, res) => {
    const reqUrl = new URL(req.url, 'http://127.0.0.1');
    const pathname = reqUrl.pathname;
    const method = req.method.toUpperCase();

    try {
      // Static UI & Locales
      if (method === 'GET' && (pathname === '/' || pathname === '/index.html')) {
        return sendStaticFile(res, path.join(uiDir, 'index.html'), 'text/html; charset=utf-8');
      }
      if (method === 'GET' && pathname === '/styles.css') {
        return sendStaticFile(res, path.join(uiDir, 'styles.css'), 'text/css; charset=utf-8');
      }
      if (method === 'GET' && pathname === '/app.js') {
        return sendStaticFile(res, path.join(uiDir, 'app.js'), 'application/javascript; charset=utf-8');
      }
      if (method === 'GET' && pathname === '/locales/en.json') {
        return sendStaticFile(res, path.join(localesDir, 'en.json'), 'application/json; charset=utf-8');
      }
      if (method === 'GET' && pathname === '/locales/es.json') {
        return sendStaticFile(res, path.join(localesDir, 'es.json'), 'application/json; charset=utf-8');
      }

      // Public Status & Auth endpoints
      if (method === 'GET' && pathname === '/api/status') {
        return sendJson(res, 200, getStatusPayload());
      }

      if (method === 'GET' && pathname === '/api/window-bounds') {
        return sendJson(res, 200, { windowBounds: loadConfig().windowBounds || null });
      }

      if (method === 'GET' && pathname === '/api/check-linked') {
        const cwdParam = reqUrl.searchParams.get('cwd') || '';
        if (!cwdParam) return sendJson(res, 200, { linked: false });
        if (isSessionValid()) {
          try {
            const { vaultData } = readUnlockedVault();
            const match = resolveLinkedDirectory(vaultData, cwdParam);
            return sendJson(res, 200, match ? { linked: true, project: match.project, env: match.env } : { linked: false });
          } catch {
            return sendJson(res, 200, { linked: false });
          }
        }
        const hints = new Set(loadConfig().linkedDirHints || []);
        let cur = path.resolve(cwdParam);
        while (true) {
          if (hints.has(normalizeDirKey(cur))) {
            return sendJson(res, 200, { linked: true, locked: true });
          }
          const parent = path.dirname(cur);
          if (parent === cur) break;
          cur = parent;
        }
        return sendJson(res, 200, { linked: false });
      }

      if (method === 'GET' && pathname.startsWith('/spring/')) {
        const parts = pathname.slice(8).split('/').filter(Boolean).map((p) => decodeURIComponent(p));
        if (parts.length < 2) return sendJson(res, 400, { error: 'INVALID_SPRING_URL' });
        const project = parts[0];
        const env = parts[1].replace(/\.(properties|env|yml|yaml)$/i, '');
        const ua = req.headers['user-agent'] || 'Spring/Java HTTP';
        const result = await executeAuthorizeAndFetch({
          resourceType: 'env',
          project,
          env,
          cwd: process.cwd(),
          callerCommand: `HTTP GET /spring/${project}/${parts[1]} (${String(ua).slice(0, 60)})`,
          envHints: {},
        });
        if (result.status !== 200) {
          return sendJson(res, result.status, result.body);
        }
        res.writeHead(200, {
          'Content-Type': 'text/plain; charset=utf-8',
          'Cache-Control': 'no-store',
          'X-Content-Type-Options': 'nosniff',
        });
        return res.end(formatJavaProperties(result.body.data?.vars || {}));
      }

      if (method === 'GET' && pathname.startsWith('/env/')) {
        const parts = pathname.slice(5).split('/').filter(Boolean).map((p) => decodeURIComponent(p));
        if (parts.length < 2) return sendJson(res, 400, { error: 'INVALID_ENV_URL' });
        const project = parts[0];
        const env = parts[1];
        const singleKey = parts[2] || null;
        const fmt = reqUrl.searchParams.get('format') || '';
        const ua = req.headers['user-agent'] || 'HTTP Client';
        const result = await executeAuthorizeAndFetch({
          resourceType: 'env',
          project,
          env,
          keys: singleKey ? [singleKey] : undefined,
          cwd: process.cwd(),
          callerCommand: `HTTP GET /env/${project}/${env}${singleKey ? '/' + singleKey : ''} (${String(ua).slice(0, 50)})`,
          envHints: {},
        });
        if (result.status !== 200) {
          return sendJson(res, result.status, result.body);
        }
        const vars = result.body.data?.vars || {};
        if (singleKey) {
          if (!Object.prototype.hasOwnProperty.call(vars, singleKey)) {
            return sendJson(res, 404, { error: 'KEY_NOT_FOUND' });
          }
          if (fmt === 'json') {
            return sendJson(res, 200, { key: singleKey, value: vars[singleKey] });
          }
          res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
          return res.end(String(vars[singleKey]));
        }
        if (fmt === 'dotenv' || fmt === 'env' || fmt === 'properties') {
          res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
          return res.end(formatJavaProperties(vars));
        }
        return sendJson(res, 200, vars);
      }

      if (method === 'POST' && pathname === '/api/window-bounds') {
        const body = await readJsonBody(req);
        const wb = {
          x: Number.isFinite(Number(body.x)) ? Math.round(Number(body.x)) : 80,
          y: Number.isFinite(Number(body.y)) ? Math.round(Number(body.y)) : 60,
          width: Number.isFinite(Number(body.width)) ? Math.max(400, Math.round(Number(body.width))) : 1240,
          height: Number.isFinite(Number(body.height)) ? Math.max(300, Math.round(Number(body.height))) : 840,
          maximized: Boolean(body.maximized),
        };
        saveConfig({ windowBounds: wb });
        return sendJson(res, 200, { ok: true, windowBounds: wb });
      }

      if (method === 'POST' && pathname === '/api/init') {
        const body = await readJsonBody(req);
        const cfg = loadConfig();
        if (fs.existsSync(cfg.vaultPath) && !body.overwrite) {
          return sendJson(res, 409, { error: 'VAULT_ALREADY_EXISTS' });
        }
        const revTtl = body.revealPinTtlMinutes !== undefined ? Number(body.revealPinTtlMinutes) : 5;
        const popupTimeout = body.popupTimeoutSeconds !== undefined ? Math.max(0, Number(body.popupTimeoutSeconds)) : 30;
        const created = createNewVaultEnvelope(body.pin, {
          defaultTtlMinutes: Number(body.defaultTtlMinutes ?? 240),
          revealPinTtlMinutes: revTtl,
          popupTimeoutSeconds: popupTimeout,
          language: body.language || 'en',
        });
        writeVaultWithBackup(cfg.vaultPath, created.envelopeBuffer);
        saveConfig({ popupTimeoutSeconds: popupTimeout, linkedDirHints: [] });
        state.masterKey = created.masterKey;
        applySessionTtl(body.ttlMinutes ?? created.vaultData.settings.defaultTtlMinutes);
        state.revealUnlockedUntil = revTtl > 0 ? Date.now() + revTtl * 60000 : 0;
        state.lastLanguage = created.vaultData.settings.language;
        return sendJson(res, 200, {
          ok: true,
          recoveryKey: created.recoveryKey,
          status: getStatusPayload(),
        });
      }

      if (method === 'POST' && pathname === '/api/unlock') {
        const body = await readJsonBody(req);
        const buf = getVaultEnvelopeBuffer();
        if (!buf) return sendJson(res, 400, { error: 'VAULT_NOT_INITIALIZED' });
        try {
          const unlocked = unlockVaultWithPin(buf, body.pin || '');
          state.masterKey = unlocked.masterKey;
          const ttl = body.ttlMinutes !== undefined
            ? Number(body.ttlMinutes)
            : Number(unlocked.vaultData.settings?.defaultTtlMinutes ?? 240);
          applySessionTtl(ttl);
          const revTtl = Number(unlocked.vaultData.settings?.revealPinTtlMinutes ?? 5);
          state.revealUnlockedUntil = revTtl > 0 ? Date.now() + revTtl * 60000 : 0;
          state.lastLanguage = unlocked.vaultData.settings?.language || 'en';
          flushPendingAuditEvents(unlocked.vaultData);
          persistVaultData(unlocked.vaultData, unlocked.masterKey);
          saveConfig({ linkedDirHints: Object.keys(unlocked.vaultData.linkedDirs || {}) });
          return sendJson(res, 200, { ok: true, status: getStatusPayload() });
        } catch {
          return sendJson(res, 401, { error: 'INVALID_PIN' });
        }
      }

      if (method === 'POST' && pathname === '/api/recover') {
        const body = await readJsonBody(req);
        const cfg = loadConfig();
        const buf = getVaultEnvelopeBuffer();
        if (!buf) return sendJson(res, 400, { error: 'VAULT_NOT_INITIALIZED' });
        try {
          const recovered = recoverVaultWithKey(buf, body.recoveryKey || '', body.newPin || '');
          writeVaultWithBackup(cfg.vaultPath, recovered.envelopeBuffer);
          state.masterKey = recovered.masterKey;
          applySessionTtl(recovered.vaultData.settings?.defaultTtlMinutes ?? 240);
          return sendJson(res, 200, { ok: true, status: getStatusPayload() });
        } catch (err) {
          return sendJson(res, 401, { error: err.code || 'RECOVERY_FAILED' });
        }
      }

      if (method === 'POST' && pathname === '/api/lock') {
        lockSession();
        return sendJson(res, 200, { ok: true, status: getStatusPayload() });
      }

      if (method === 'POST' && pathname === '/api/authorize-and-fetch') {
        const body = await readJsonBody(req);
        const result = await executeAuthorizeAndFetch(body);
        return sendJson(res, result.status, result.body);
      }

      // Read-only OS/AWS/Git scans work cleanly even before unlock, or when unlocked
      if (method === 'GET' && pathname === '/api/aws/scan') {
        return sendJson(res, 200, scanAwsFiles());
      }
      if (method === 'GET' && pathname === '/api/git/status') {
        return sendJson(res, 200, getGitHelperStatus());
      }
      if (method === 'GET' && pathname === '/api/os-env/scan') {
        return sendJson(res, 200, scanUserOsEnv());
      }

      // All endpoints below require unlocked vault
      if (!isSessionValid()) {
        return sendJson(res, 401, { error: 'VAULT_LOCKED' });
      }

      if (method === 'POST' && pathname === '/api/turbo') {
        const body = await readJsonBody(req);
        const mins = Number(body.minutes || 0);
        if (mins <= 0) {
          state.aiTurboUntil = 0;
        } else {
          state.aiTurboUntil = Date.now() + mins * 60000;
        }
        const { vaultData } = readUnlockedVault();
        recordAudit(vaultData, {
          callerCommand: 'UI / CLI',
          processChain: 'EnvGuard',
          cwd: process.cwd(),
          resourceType: 'system',
          resourceName: 'AI Turbo Mode',
          effectivePolicy: 'session',
          critical: false,
          isAiAgent: false,
          decision: mins > 0 ? `ENABLED (${mins}m)` : 'DISABLED',
          reason: 'user_toggle',
        });
        return sendJson(res, 200, { ok: true, status: getStatusPayload() });
      }

      if (method === 'POST' && pathname === '/api/session/ttl') {
        const body = await readJsonBody(req);
        applySessionTtl(Number(body.ttlMinutes ?? 240));
        return sendJson(res, 200, { ok: true, status: getStatusPayload() });
      }

      // Projects & Environments CRUD
      if (method === 'GET' && pathname === '/api/projects') {
        const { vaultData } = readUnlockedVault();
        return sendJson(res, 200, {
          projects: sanitizeProjectsForUi(vaultData),
          linkedDirs: vaultData.linkedDirs || {},
        });
      }

      if (method === 'POST' && pathname === '/api/projects/create') {
        const body = await readJsonBody(req);
        const project = String(body.project || '').trim();
        const env = String(body.env || 'dev').trim();
        if (!project) return sendJson(res, 400, { error: 'PROJECT_NAME_REQUIRED' });
        const { vaultData } = readUnlockedVault();
        ensureProjectEnv(vaultData, project, env, body.policy || 'confirm');
        if (body.description !== undefined) {
          vaultData.projects[project].description = String(body.description);
        }
        persistVaultData(vaultData);
        return sendJson(res, 200, { ok: true, projects: sanitizeProjectsForUi(vaultData) });
      }

      if (method === 'POST' && pathname === '/api/projects/env-policy') {
        const body = await readJsonBody(req);
        const { project, env, policy, critical } = body;
        const { vaultData } = readUnlockedVault();
        const envObj = ensureProjectEnv(vaultData, project, env);
        if (policy && POLICY_LEVELS[policy]) envObj.policy = policy;
        if (critical !== undefined) envObj.critical = Boolean(critical);
        persistVaultData(vaultData);
        return sendJson(res, 200, { ok: true, env: envObj });
      }

      if (method === 'POST' && pathname === '/api/projects/var') {
        const body = await readJsonBody(req);
        const { project, env, key, value, policy, critical, description } = body;
        if (!project || !env || !key) return sendJson(res, 400, { error: 'MISSING_FIELDS' });
        const { vaultData } = readUnlockedVault();
        const updated = setProjectVar(vaultData, project, env, String(key).trim(), value ?? '', {
          policy,
          critical,
          description,
        });
        persistVaultData(vaultData);
        return sendJson(res, 200, { ok: true, variable: updated });
      }

      if (method === 'DELETE' && pathname === '/api/projects/var') {
        const body = await readJsonBody(req);
        const { project, env, key } = body;
        const { vaultData } = readUnlockedVault();
        if (vaultData.projects?.[project]?.environments?.[env]?.vars?.[key]) {
          delete vaultData.projects[project].environments[env].vars[key];
          persistVaultData(vaultData);
        }
        return sendJson(res, 200, { ok: true });
      }

      if (method === 'POST' && pathname === '/api/projects/rollback') {
        const body = await readJsonBody(req);
        const { project, env, key, historyIndex } = body;
        const { vaultData } = readUnlockedVault();
        const restored = rollbackProjectVar(vaultData, project, env, key, Number(historyIndex || 0));
        persistVaultData(vaultData);
        return sendJson(res, 200, { ok: true, variable: restored });
      }

      // Directory Linking
      if (method === 'POST' && pathname === '/api/links') {
        const body = await readJsonBody(req);
        const { dirPath, project, env } = body;
        if (!dirPath || !project || !env) return sendJson(res, 400, { error: 'MISSING_FIELDS' });
        const { vaultData } = readUnlockedVault();
        const link = linkDirectory(vaultData, dirPath, project, env);
        persistVaultData(vaultData);
        saveConfig({ linkedDirHints: Object.keys(vaultData.linkedDirs || {}) });
        return sendJson(res, 200, { ok: true, link, linkedDirs: vaultData.linkedDirs });
      }

      if (method === 'DELETE' && pathname === '/api/links') {
        const body = await readJsonBody(req);
        const { vaultData } = readUnlockedVault();
        unlinkDirectory(vaultData, body.dirPath || '');
        persistVaultData(vaultData);
        saveConfig({ linkedDirHints: Object.keys(vaultData.linkedDirs || {}) });
        return sendJson(res, 200, { ok: true, linkedDirs: vaultData.linkedDirs });
      }

      // Share / Export & Import Diff
      if (method === 'POST' && pathname === '/api/export') {
        const body = await readJsonBody(req);
        const { project, env, format, keys, transferPassword } = body;
        const { vaultData } = readUnlockedVault();
        const envObj = vaultData.projects?.[project]?.environments?.[env];
        if (!envObj) return sendJson(res, 404, { error: 'ENV_NOT_FOUND' });

        const selectedVars = {};
        const targetKeys = Array.isArray(keys) && keys.length > 0 ? keys : Object.keys(envObj.vars || {});
        for (const k of targetKeys) {
          if (envObj.vars[k]) selectedVars[k] = envObj.vars[k];
        }

        if (format === 'html') {
          const flat = {};
          for (const [k, v] of Object.entries(selectedVars)) flat[k] = v.value;
          const content = generateSelfDecryptingHtml(project, env, flat, transferPassword);
          return sendJson(res, 200, { ok: true, filename: `${project}-${env}-share.html`, mime: 'text/html', content });
        }
        if (format === 'vltpack') {
          const flat = {};
          for (const [k, v] of Object.entries(selectedVars)) flat[k] = { value: v.value, critical: v.critical, policy: v.policy };
          const content = exportVltPack({ project, env, vars: flat, exportedAt: new Date().toISOString() }, transferPassword);
          return sendJson(res, 200, { ok: true, filename: `${project}-${env}.vltpack`, mime: 'text/plain', content });
        }
        const content = formatEnvOutput(selectedVars, format || 'env', project, env);
        const ext = format === 'tpl' ? '.env.tpl' : (format === 'example' ? '.env.example' : `.env.${env}`);
        return sendJson(res, 200, { ok: true, filename: ext, mime: 'text/plain', content });
      }

      if (method === 'POST' && pathname === '/api/import-diff') {
        const body = await readJsonBody(req);
        const { project, env, rawContent, transferPassword } = body;
        const { vaultData } = readUnlockedVault();
        const existingVars = vaultData.projects?.[project]?.environments?.[env]?.vars || {};
        let incomingMap = {};
        if (String(rawContent || '').trim().startsWith('VLTPACK1:')) {
          const pack = importVltPack(rawContent, transferPassword || '');
          for (const [k, v] of Object.entries(pack.vars || {})) {
            incomingMap[k] = typeof v === 'object' && v !== null ? String(v.value ?? '') : String(v);
          }
        } else {
          incomingMap = parseEnvString(rawContent || '');
        }
        const diff = computeImportDiff(existingVars, incomingMap);
        return sendJson(res, 200, { ok: true, incomingMap, diff });
      }

      if (method === 'POST' && pathname === '/api/import-apply') {
        const body = await readJsonBody(req);
        const { project, env, incomingMap, mode } = body;
        if (!project || !env || !incomingMap) return sendJson(res, 400, { error: 'MISSING_FIELDS' });
        const { vaultData } = readUnlockedVault();
        const envObj = ensureProjectEnv(vaultData, project, env);
        if (mode === 'overwrite') {
          for (const existingKey of Object.keys(envObj.vars)) {
            if (!Object.prototype.hasOwnProperty.call(incomingMap, existingKey)) {
              delete envObj.vars[existingKey];
            }
          }
        }
        for (const [k, val] of Object.entries(incomingMap)) {
          setProjectVar(vaultData, project, env, k, String(val), { note: 'imported' });
        }
        persistVaultData(vaultData);
        return sendJson(res, 200, { ok: true, env: envObj });
      }

      // AWS Profiles CRUD & Integration
      if (method === 'GET' && pathname === '/api/aws') {
        const { vaultData } = readUnlockedVault();
        return sendJson(res, 200, {
          profiles: vaultData.awsProfiles || {},
          diskScan: scanAwsFiles(),
        });
      }

      if (method === 'POST' && pathname === '/api/aws/profile') {
        const body = await readJsonBody(req);
        const name = String(body.name || '').trim();
        if (!name) return sendJson(res, 400, { error: 'PROFILE_NAME_REQUIRED' });
        const { vaultData } = readUnlockedVault();
        const prev = vaultData.awsProfiles[name] || {};
        vaultData.awsProfiles[name] = {
          accessKeyId: body.accessKeyId ?? prev.accessKeyId ?? '',
          secretAccessKey: body.secretAccessKey ?? prev.secretAccessKey ?? '',
          sessionToken: body.sessionToken ?? prev.sessionToken ?? '',
          region: body.region || prev.region || 'us-east-1',
          accountId: body.accountId ?? prev.accountId ?? '',
          policy: POLICY_LEVELS[body.policy] ? body.policy : (prev.policy || 'confirm'),
          critical: body.critical !== undefined ? Boolean(body.critical) : Boolean(prev.critical),
          updatedAt: new Date().toISOString(),
        };
        persistVaultData(vaultData);
        return sendJson(res, 200, { ok: true, profiles: vaultData.awsProfiles });
      }

      if (method === 'DELETE' && pathname === '/api/aws/profile') {
        const body = await readJsonBody(req);
        const { vaultData } = readUnlockedVault();
        if (vaultData.awsProfiles?.[body.name]) {
          delete vaultData.awsProfiles[body.name];
          persistVaultData(vaultData);
        }
        return sendJson(res, 200, { ok: true });
      }

      if (method === 'POST' && pathname === '/api/aws/import-disk') {
        const body = await readJsonBody(req);
        const { vaultData } = readUnlockedVault();
        const imported = importAwsProfilesToVault(vaultData, body.profiles || null);
        persistVaultData(vaultData);
        return sendJson(res, 200, { ok: true, imported, profiles: vaultData.awsProfiles });
      }

      if (method === 'POST' && pathname === '/api/aws/activate-process') {
        const body = await readJsonBody(req);
        const vltCmd = `"${process.execPath}" "${path.resolve(__dirname, '..', 'bin', 'vlt.js')}"`;
        const info = configureAwsCredentialProcess(body.profile || 'default', vltCmd);
        return sendJson(res, 200, { ok: true, ...info });
      }

      if (method === 'POST' && pathname === '/api/aws/remove-plaintext') {
        const body = await readJsonBody(req);
        const removed = removeAwsPlaintextProfile(body.profile || 'default');
        return sendJson(res, 200, { ok: true, removed });
      }

      // Git Credentials CRUD & Integration
      if (method === 'GET' && pathname === '/api/git') {
        const { vaultData } = readUnlockedVault();
        return sendJson(res, 200, {
          credentials: vaultData.gitCredentials || {},
          helperStatus: getGitHelperStatus(),
        });
      }

      if (method === 'POST' && pathname === '/api/git/credential') {
        const body = await readJsonBody(req);
        const host = String(body.host || '').trim().toLowerCase();
        const username = String(body.username || '').trim();
        if (!host) return sendJson(res, 400, { error: 'HOST_REQUIRED' });
        const id = body.id || `${host}:${username || 'default'}`;
        const { vaultData } = readUnlockedVault();
        const prev = vaultData.gitCredentials[id] || {};
        vaultData.gitCredentials[id] = {
          id,
          host,
          username: username || prev.username || '',
          token: body.token ?? prev.token ?? '',
          protocol: body.protocol || prev.protocol || 'https',
          policy: POLICY_LEVELS[body.policy] ? body.policy : (prev.policy || 'confirm'),
          critical: body.critical !== undefined ? Boolean(body.critical) : Boolean(prev.critical),
          updatedAt: new Date().toISOString(),
        };
        persistVaultData(vaultData);
        return sendJson(res, 200, { ok: true, credentials: vaultData.gitCredentials });
      }

      if (method === 'DELETE' && pathname === '/api/git/credential') {
        const body = await readJsonBody(req);
        const { vaultData } = readUnlockedVault();
        if (vaultData.gitCredentials?.[body.id]) {
          delete vaultData.gitCredentials[body.id];
          persistVaultData(vaultData);
        }
        return sendJson(res, 200, { ok: true });
      }

      if (method === 'POST' && pathname === '/api/git/helper') {
        const body = await readJsonBody(req);
        const vltCmd = `"${process.execPath.replace(/\\/g, '/')}" "${path.resolve(__dirname, '..', 'bin', 'vlt.js').replace(/\\/g, '/')}"`;
        const info = configureGitCredentialHelper(Boolean(body.enable), vltCmd);
        return sendJson(res, 200, { ok: true, ...info });
      }

      // OS Env Cleaner & Backups
      if (method === 'GET' && pathname === '/api/os-env/backups') {
        const { vaultData } = readUnlockedVault();
        const safeBackups = {};
        for (const [k, b] of Object.entries(vaultData.osEnvBackups || {})) {
          safeBackups[k] = {
            ...b,
            originalValue: maskSecret(b.originalValue),
          };
        }
        return sendJson(res, 200, { backups: safeBackups });
      }

      if (method === 'POST' && pathname === '/api/os-env/migrate') {
        const body = await readJsonBody(req);
        const { varNames, project, env, removeFromOs } = body;
        if (!Array.isArray(varNames) || varNames.length === 0 || !project || !env) {
          return sendJson(res, 400, { error: 'MISSING_FIELDS' });
        }
        const { vaultData } = readUnlockedVault();
        const migrated = migrateOsEnvToVault(vaultData, varNames, project, env, Boolean(removeFromOs));
        persistVaultData(vaultData);
        return sendJson(res, 200, { ok: true, migrated });
      }

      if (method === 'POST' && pathname === '/api/os-env/restore') {
        const body = await readJsonBody(req);
        const { vaultData } = readUnlockedVault();
        const resRestore = restoreOsEnvFromBackup(vaultData, body.varName);
        persistVaultData(vaultData);
        return sendJson(res, 200, { ok: true, ...resRestore });
      }

      // Audit Log, Settings, Pin Change, Vault Path & Backups
      if (method === 'GET' && pathname === '/api/audit') {
        const { vaultData } = readUnlockedVault();
        return sendJson(res, 200, { auditLog: vaultData.auditLog || [] });
      }

      if (method === 'GET' && pathname === '/api/settings') {
        const cfg = loadConfig();
        const { vaultData } = readUnlockedVault();
        return sendJson(res, 200, {
          settings: vaultData.settings,
          popupTimeoutSeconds: vaultData.settings?.popupTimeoutSeconds ?? cfg.popupTimeoutSeconds ?? 30,
          revealPinTtlMinutes: vaultData.settings?.revealPinTtlMinutes ?? 5,
          vaultPath: cfg.vaultPath,
          autoStartOs: getOsAutoStartStatus(),
          shellHookInstalled: getShellAutoHookStatus().installed,
          backups: listBackups(),
          backupsDir: getBackupsDir(),
        });
      }

      if (method === 'POST' && pathname === '/api/settings') {
        const body = await readJsonBody(req);
        const cfg = loadConfig();
        const { vaultData } = readUnlockedVault();
        if (body.language) {
          vaultData.settings.language = body.language === 'es' ? 'es' : 'en';
          state.lastLanguage = vaultData.settings.language;
        }
        if (body.defaultTtlMinutes !== undefined) {
          vaultData.settings.defaultTtlMinutes = Number(body.defaultTtlMinutes);
        }
        if (body.popupTimeoutSeconds !== undefined) {
          const secs = Math.max(0, Number(body.popupTimeoutSeconds));
          vaultData.settings.popupTimeoutSeconds = secs;
          saveConfig({ popupTimeoutSeconds: secs });
        }
        if (body.revealPinTtlMinutes !== undefined) {
          const revTtl = Number(body.revealPinTtlMinutes);
          vaultData.settings.revealPinTtlMinutes = revTtl;
          if (revTtl === 0) state.revealUnlockedUntil = 0;
          else if (revTtl > 0) state.revealUnlockedUntil = Date.now() + revTtl * 60000;
        }
        persistVaultData(vaultData);

        if (body.vaultPath && path.resolve(body.vaultPath) !== path.resolve(cfg.vaultPath)) {
          const newPath = path.resolve(body.vaultPath);
          ensureDirSync(path.dirname(newPath));
          fs.copyFileSync(cfg.vaultPath, newPath);
          saveConfig({ vaultPath: newPath });
        }
        if (body.autoStartOs !== undefined) {
          const daemonScript = path.resolve(__dirname, 'daemon.js');
          const enabled = setOsAutoStart(Boolean(body.autoStartOs), daemonScript);
          saveConfig({ autoStartOs: enabled });
        }
        if (body.shellAutoHook !== undefined) {
          if (body.shellAutoHook) installShellAutoHook();
          else removeShellAutoHook();
        }
        return sendJson(res, 200, { ok: true, status: getStatusPayload() });
      }

      if (method === 'POST' && pathname === '/api/change-pin') {
        const body = await readJsonBody(req);
        const cfg = loadConfig();
        const buf = getVaultEnvelopeBuffer();
        const changed = changeVaultPin(buf, body.currentPin || '', body.newPin || '');
        writeVaultWithBackup(cfg.vaultPath, changed.envelopeBuffer);
        state.masterKey = changed.masterKey;
        return sendJson(res, 200, { ok: true });
      }

      if (method === 'POST' && pathname === '/api/verify-reveal-pin') {
        const body = await readJsonBody(req);
        const buf = getVaultEnvelopeBuffer();
        if (!buf) return sendJson(res, 400, { error: 'VAULT_NOT_INITIALIZED' });
        try {
          const verified = unlockVaultWithPin(buf, body.pin || '');
          const revTtl = Number(verified.vaultData.settings?.revealPinTtlMinutes ?? 5);
          if (revTtl > 0) {
            state.revealUnlockedUntil = Date.now() + revTtl * 60000;
          } else {
            state.revealUnlockedUntil = 0;
          }
          return sendJson(res, 200, {
            ok: true,
            revealAuthorized: revTtl !== 0,
            oneShot: revTtl === 0,
            status: getStatusPayload(),
          });
        } catch {
          return sendJson(res, 401, { error: 'INVALID_PIN' });
        }
      }

      if (method === 'POST' && pathname === '/api/reset-vault') {
        const cfg = loadConfig();
        if (fs.existsSync(cfg.vaultPath)) {
          ensureDirSync(getBackupsDir());
          const stamp = new Date().toISOString().replace(/[:.]/g, '-');
          fs.copyFileSync(cfg.vaultPath, path.join(getBackupsDir(), `vault-reset-${stamp}.vlt.bak`));
          fs.unlinkSync(cfg.vaultPath);
        }
        lockSession();
        return sendJson(res, 200, { ok: true, status: getStatusPayload() });
      }

      if (method === 'GET' && pathname === '/api/vault/download-backup') {
        const buf = getVaultEnvelopeBuffer();
        if (!buf) return sendJson(res, 404, { error: 'VAULT_NOT_INITIALIZED' });
        res.writeHead(200, {
          'Content-Type': 'application/octet-stream',
          'Content-Disposition': 'attachment; filename="envguard-vault-backup.vlt"',
          'Cache-Control': 'no-store',
        });
        return res.end(buf);
      }

      return sendJson(res, 404, { error: 'NOT_FOUND' });
    } catch (err) {
      return sendJson(res, err.code === 'VAULT_LOCKED' ? 401 : 500, {
        error: err.code || err.message || 'INTERNAL_ERROR',
      });
    }
  });

  const cfg = loadConfig();
  const targetPort = portOverride !== null ? Number(portOverride) : cfg.port;

  return new Promise((resolve, reject) => {
    const startListening = (portToBind, allowFallback) => {
      server.once('error', (err) => {
        if (err.code === 'EADDRINUSE' && allowFallback) {
          startListening(0, false);
          return;
        }
        reject(err);
      });
      server.listen(portToBind, '127.0.0.1', () => {
        const addr = server.address();
        const actualPort = typeof addr === 'object' && addr ? addr.port : portToBind;
        ensureDirSync(getEnvguardHome());
        fs.writeFileSync(
          getDaemonInfoPath(),
          JSON.stringify({ pid: process.pid, port: actualPort, startedAt: new Date().toISOString() }, null, 2),
          'utf8'
        );
        resolve({ server, port: actualPort, state, lockSession });
      });
    };
    startListening(targetPort, portOverride === null);
  });
}

if (require.main === module) {
  startServer()
    .then(({ port }) => {
      const cleanup = () => {
        try { fs.unlinkSync(getDaemonInfoPath()); } catch { /* ignore */ }
        process.exit(0);
      };
      process.on('SIGINT', cleanup);
      process.on('SIGTERM', cleanup);
      if (process.env.ENVGUARD_LOG_STARTUP) {
        console.log(`EnvGuard daemon listening on http://127.0.0.1:${port}`);
      }
    })
    .catch((err) => {
      console.error('Failed to start EnvGuard daemon:', err);
      process.exit(1);
    });
}

module.exports = {
  startServer,
  getDaemonInfoPath,
};
