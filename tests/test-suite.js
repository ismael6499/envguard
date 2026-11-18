'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

// Isolate ENVGUARD_HOME to a clean temp folder before importing project modules
const TEST_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'envguard-test-'));
process.env.ENVGUARD_HOME = TEST_HOME;

const {
  createNewVaultEnvelope,
  unlockVaultWithPin,
  recoverVaultWithKey,
  changeVaultPin,
  updateVaultData,
  writeVaultWithBackup,
  listBackups,
  setProjectVar,
  rollbackProjectVar,
  resolveEffectivePolicy,
  linkDirectory,
  resolveLinkedDirectory,
  parseEnvString,
  computeImportDiff,
  formatEnvOutput,
  exportVltPack,
  importVltPack,
  generateSelfDecryptingHtml,
} = require('../src/crypto-vault');
const { startServer } = require('../src/daemon');

function runCliAsync(cmdArgs, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, cmdArgs, { env, encoding: 'utf8' });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => { stdout += c.toString('utf8'); });
    child.stderr.on('data', (c) => { stderr += c.toString('utf8'); });
    child.on('error', reject);
    child.on('close', (status) => resolve({ status, stdout, stderr }));
  });
}

function reqJson(port, method, reqPath, bodyObj = null) {
  return new Promise((resolve, reject) => {
    const payload = bodyObj ? JSON.stringify(bodyObj) : null;
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path: reqPath,
        method,
        headers: payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : undefined,
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let json = {};
          try { json = JSON.parse(text || '{}'); } catch { /* ignore */ }
          resolve({ status: res.statusCode, data: json, raw: text });
        });
      }
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function runTests() {
  console.log('Running EnvGuard automated test suite...');

  // 1. Envelope Encryption, PIN Unlock, Tamper/Wrong-PIN Rejection, Recovery Key & Backups
  const created = createNewVaultEnvelope('1234');
  assert(created.recoveryKey.startsWith('EVG-'), 'Recovery key must start with EVG-');
  assert.throws(() => unlockVaultWithPin(created.envelopeBuffer, '9999'), /INVALID_PIN/);

  setProjectVar(created.vaultData, 'api', 'prod', 'JWT_SECRET', 'super-secret-1', {
    policy: 'pin_confirm',
    critical: true,
  });
  let envBuf = updateVaultData(created.envelopeBuffer, created.masterKey, created.vaultData);
  const vaultFile = path.join(TEST_HOME, 'vault.vlt');
  writeVaultWithBackup(vaultFile, envBuf);
  writeVaultWithBackup(vaultFile, envBuf);
  assert(listBackups().length >= 1, 'Rolling backup should be created on overwrite');

  // Recover with Recovery Key & set new PIN
  const recovered = recoverVaultWithKey(envBuf, created.recoveryKey.toLowerCase(), '5678');
  assert.strictEqual(recovered.vaultData.projects.api.environments.prod.vars.JWT_SECRET.value, 'super-secret-1');
  assert.throws(() => unlockVaultWithPin(recovered.envelopeBuffer, '1234'), /INVALID_PIN/);
  const unlockedNew = unlockVaultWithPin(recovered.envelopeBuffer, '5678');
  assert.strictEqual(unlockedNew.vaultData.projects.api.environments.prod.vars.JWT_SECRET.value, 'super-secret-1');

  // Change PIN
  const changed = changeVaultPin(recovered.envelopeBuffer, '5678', '4321');
  assert.strictEqual(unlockVaultWithPin(changed.envelopeBuffer, '4321').vaultData.projects.api.environments.prod.vars.JWT_SECRET.value, 'super-secret-1');
  console.log('[PASS] 1. VLT2 Envelope crypto, Recovery Key PIN reset, Change PIN & rolling backups');

  // 2. Variable 5-Version History & Rollback
  const vData = changed.vaultData;
  for (let i = 1; i <= 7; i += 1) {
    setProjectVar(vData, 'web', 'dev', 'API_TOKEN', `val-v${i}`);
  }
  const tokenVar = vData.projects.web.environments.dev.vars.API_TOKEN;
  assert.strictEqual(tokenVar.value, 'val-v7');
  assert.strictEqual(tokenVar.history.length, 5, 'History must cap at 5 snapshots');
  assert.strictEqual(tokenVar.history[0].value, 'val-v6');
  const rolled = rollbackProjectVar(vData, 'web', 'dev', 'API_TOKEN', 0);
  assert.strictEqual(rolled.value, 'val-v6');
  assert.strictEqual(rolled.history[0].value, 'val-v7');
  console.log('[PASS] 2. Variable 5-version history & rollback');

  // 3. Zero-Footprint Directory Linking
  const repoDir = path.join(TEST_HOME, 'repos', 'sample-service');
  const subDir = path.join(repoDir, 'src', 'api');
  fs.mkdirSync(subDir, { recursive: true });
  linkDirectory(vData, repoDir, 'web', 'dev');
  const resolved = resolveLinkedDirectory(vData, subDir);
  assert(resolved && resolved.project === 'web' && resolved.env === 'dev', 'Subdirectory should resolve linked project/env');
  assert.strictEqual(fs.readdirSync(repoDir).filter((f) => f.includes('vlt')).length, 0, 'No .vlt files written in repo');
  console.log('[PASS] 3. Zero-footprint directory linking');

  // 4. Granular Policies, AI Agent Escalation & Timed AI Turbo Mode
  const envPolicyTest = {
    policy: 'session',
    critical: false,
    vars: {
      PUBLIC_URL: { value: 'http://localhost', policy: 'inherit', critical: false },
      CONFIRM_KEY: { value: 'c1', policy: 'confirm', critical: false },
      ROOT_SECRET: { value: 'root', policy: 'pin_confirm', critical: true },
      DENIED_KEY: { value: 'nope', policy: 'blocked', critical: false },
    },
  };
  assert.strictEqual(resolveEffectivePolicy(envPolicyTest, ['PUBLIC_URL'], { isAiAgent: false }, false).policy, 'session');
  const pinEsc = resolveEffectivePolicy(envPolicyTest, ['PUBLIC_URL', 'ROOT_SECRET'], { isAiAgent: false }, false);
  assert.strictEqual(pinEsc.policy, 'pin_confirm');
  assert.strictEqual(pinEsc.critical, true);
  assert.deepStrictEqual(pinEsc.criticalKeys, ['ROOT_SECRET']);
  assert.strictEqual(resolveEffectivePolicy(envPolicyTest, ['PUBLIC_URL', 'DENIED_KEY'], { isAiAgent: false }, false).policy, 'blocked');

  // AI Agent without Turbo escalates 'session' -> 'confirm'
  const aiNormal = resolveEffectivePolicy(envPolicyTest, ['PUBLIC_URL'], { isAiAgent: true }, false);
  assert.strictEqual(aiNormal.policy, 'confirm');
  assert.strictEqual(aiNormal.escalatedByAi, true);

  // AI Agent WITH Turbo bypasses 'session' & 'confirm'
  const aiTurbo = resolveEffectivePolicy(envPolicyTest, ['PUBLIC_URL', 'CONFIRM_KEY'], { isAiAgent: true }, true);
  assert.strictEqual(aiTurbo.turboBypass, true);

  // AI Agent WITH Turbo CANNOT bypass 'pin_confirm' or 'blocked'
  const aiTurboPin = resolveEffectivePolicy(envPolicyTest, ['ROOT_SECRET'], { isAiAgent: true }, true);
  assert.strictEqual(aiTurboPin.policy, 'pin_confirm');
  assert.strictEqual(aiTurboPin.turboBypass, false);
  console.log('[PASS] 4. Granular policies, critical flags, AI Agent escalation & AI Turbo boundaries');

  // 5. Share / Export / Import Diff & Self-Decrypting HTML Verification
  const rawEnv = '# comment\nexport FOO=bar_new\nBAR="hello world"\nBAZ=same\n';
  const parsedMap = parseEnvString(rawEnv);
  assert.deepStrictEqual(parsedMap, { FOO: 'bar_new', BAR: 'hello world', BAZ: 'same' });
  const diff = computeImportDiff(
    { FOO: { value: 'bar_old' }, BAZ: { value: 'same' } },
    parsedMap
  );
  assert.strictEqual(diff.added.length, 1);
  assert.strictEqual(diff.modified.length, 1);
  assert.strictEqual(diff.unchanged.length, 1);

  const pack = exportVltPack({ project: 'web', env: 'dev', vars: { SECRET: '123' } }, 'pass99');
  assert.throws(() => importVltPack(pack, 'wrong'), /INVALID_TRANSFER_PASSWORD/);
  assert.strictEqual(importVltPack(pack, 'pass99').vars.SECRET, '123');

  const tpl = formatEnvOutput({ DB_PASS: { value: 'abc' } }, 'tpl', 'web', 'dev');
  assert.strictEqual(tpl.trim(), 'DB_PASS=vlt://web/dev/DB_PASS');

  const htmlShare = generateSelfDecryptingHtml('web', 'dev', { DB_PASS: 'top-secret' }, 'sharepass123');
  const payloadMatch = htmlShare.match(/const PAYLOAD = (\{.*?\});/);
  assert(payloadMatch, 'Self-decrypting HTML must embed PAYLOAD');
  const embedded = JSON.parse(payloadMatch[1]);
  const derivedHtmlKey = crypto.pbkdf2Sync('sharepass123', Buffer.from(embedded.salt, 'base64'), 100000, 32, 'sha256');
  const combinedBuf = Buffer.from(embedded.data, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', derivedHtmlKey, Buffer.from(embedded.iv, 'base64'));
  decipher.setAuthTag(combinedBuf.subarray(combinedBuf.length - 16));
  const decryptedShare = JSON.parse(Buffer.concat([decipher.update(combinedBuf.subarray(0, combinedBuf.length - 16)), decipher.final()]).toString('utf8'));
  assert.strictEqual(decryptedShare.vars.DB_PASS, 'top-secret');
  console.log('[PASS] 5. Share/Export (.vltpack, .env.tpl, .html PBKDF2+AES-GCM) & Import Diff');

  // 6. End-to-End Daemon + CLI (vlt run & vlt aws-cred)
  // Start fresh daemon in isolated TEST_HOME
  fs.rmSync(vaultFile, { force: true });
  const daemonInfo = await startServer(0);
  const port = daemonInfo.port;
  process.env.ENVGUARD_PORT = String(port);

  try {
    const initRes = await reqJson(port, 'POST', '/api/init', { pin: '2468', defaultTtlMinutes: 60, ttlMinutes: 60 });
    assert.strictEqual(initRes.status, 200);
    assert.strictEqual(initRes.data.status.popupTimeoutSeconds, 30, 'Default popup timeout should be 30s');
    const updTimeout = await reqJson(port, 'POST', '/api/settings', { popupTimeoutSeconds: 45 });
    assert.strictEqual(updTimeout.status, 200);
    assert.strictEqual(updTimeout.data.status.popupTimeoutSeconds, 45);
    await reqJson(port, 'POST', '/api/settings', { popupTimeoutSeconds: 0 });
    assert.strictEqual((await reqJson(port, 'GET', '/api/status')).data.popupTimeoutSeconds, 0);
    await reqJson(port, 'POST', '/api/settings', { popupTimeoutSeconds: 30 });

    // Verify window-bounds persistence
    const wbRes = await reqJson(port, 'POST', '/api/window-bounds', { x: 120, y: 90, width: 1100, height: 760, maximized: true });
    assert.strictEqual(wbRes.status, 200);
    assert.strictEqual((await reqJson(port, 'GET', '/api/window-bounds')).data.windowBounds.maximized, true);

    // Verify Show/Reveal PIN policy & verification
    assert.strictEqual(initRes.data.status.revealPinTtlMinutes, 5);
    await reqJson(port, 'POST', '/api/settings', { revealPinTtlMinutes: 0 });
    assert.strictEqual((await reqJson(port, 'GET', '/api/status')).data.revealAuthorized, false);
    const badReveal = await reqJson(port, 'POST', '/api/verify-reveal-pin', { pin: '0000' });
    assert.strictEqual(badReveal.status, 401);
    const okRevealOnce = await reqJson(port, 'POST', '/api/verify-reveal-pin', { pin: '2468' });
    assert.strictEqual(okRevealOnce.status, 200);
    assert.strictEqual(okRevealOnce.data.oneShot, true);
    assert.strictEqual(okRevealOnce.data.status.revealAuthorized, false, '0m reveal policy must require PIN every time');
    await reqJson(port, 'POST', '/api/settings', { revealPinTtlMinutes: 5 });
    const okRevealGrace = await reqJson(port, 'POST', '/api/verify-reveal-pin', { pin: '2468' });
    assert.strictEqual(okRevealGrace.data.status.revealAuthorized, true);
    await reqJson(port, 'POST', '/api/projects/create', { project: 'demo', env: 'dev', policy: 'session' });
    await reqJson(port, 'POST', '/api/projects/var', {
      project: 'demo',
      env: 'dev',
      key: 'INJECTED_KEY',
      value: 'ram-only-secret',
      policy: 'session',
    });
    await reqJson(port, 'POST', '/api/aws/profile', {
      name: 'ci-test',
      accessKeyId: 'AKIAEXAMPLE123',
      secretAccessKey: 'SECRETEXAMPLE456',
      region: 'us-east-1',
      policy: 'confirm',
    });

    // Lock vault and test denied + timedOut popup
    await reqJson(port, 'POST', '/api/lock');
    process.env.ENVGUARD_TEST_POPUP_RESPONSE = JSON.stringify({ approved: false, timedOut: true });
    const deniedRes = await reqJson(port, 'POST', '/api/authorize-and-fetch', {
      resourceType: 'env',
      project: 'demo',
      env: 'dev',
      callerCommand: 'node app.js',
    });
    assert.strictEqual(deniedRes.status, 403);
    assert.strictEqual(deniedRes.data.error, 'POPUP_TIMEOUT');

    // Unlock via daemon & test CLI `vlt run` memory injection (simulated approval if AI process tree detected)
    await reqJson(port, 'POST', '/api/unlock', { pin: '2468', ttlMinutes: 60 });

    const vltBin = path.resolve(__dirname, '..', 'bin', 'vlt.js');
    process.env.ENVGUARD_TEST_POPUP_RESPONSE = JSON.stringify({ approved: true, ttlMinutes: 60 });
    const cleanEnv = { ...process.env };
    delete cleanEnv.ANTIGRAVITY_CLI_ALIAS;
    delete cleanEnv.ANTIGRAVITY_AGENT;
    delete cleanEnv.CLAUDECODE;
    const runRes = await runCliAsync(
      [vltBin, 'run', '-p', 'demo', '-e', 'dev', '--', process.execPath, '-e', 'process.stdout.write(process.env.INJECTED_KEY || "")'],
      cleanEnv
    );
    assert.strictEqual(runRes.status, 0, `vlt run failed: ${runRes.stderr}`);
    assert.strictEqual(runRes.stdout.trim(), 'ram-only-secret');

    // Test AI Turbo Mode + AI Agent marker on 'confirm' AWS profile (NO popup needed!)
    delete process.env.ENVGUARD_TEST_POPUP_RESPONSE;
    delete cleanEnv.ENVGUARD_TEST_POPUP_RESPONSE;
    await reqJson(port, 'POST', '/api/turbo', { minutes: 15 });
    const awsRes = await runCliAsync(
      [vltBin, 'aws-cred', '--profile', 'ci-test'],
      { ...cleanEnv, CLAUDECODE: '1' }
    );
    assert.strictEqual(awsRes.status, 0, `vlt aws-cred failed: ${awsRes.stderr}`);
    const awsJson = JSON.parse(awsRes.stdout);
    assert.strictEqual(awsJson.Version, 1);
    assert.strictEqual(awsJson.AccessKeyId, 'AKIAEXAMPLE123');
    assert.strictEqual(awsJson.SecretAccessKey, 'SECRETEXAMPLE456');

    const auditRes = await reqJson(port, 'GET', '/api/audit');
    assert(auditRes.data.auditLog.some((e) => e.decision === 'ALLOWED (AI Turbo)'), 'Audit log should record AI Turbo decision');

    // Test Direct HTTP / Spring Boot / Check-Linked endpoints
    const linkTestDir = path.join(TEST_HOME, 'java-svc');
    fs.mkdirSync(linkTestDir, { recursive: true });
    await reqJson(port, 'POST', '/api/links', { dirPath: linkTestDir, project: 'demo', env: 'dev' });
    const chkUnlocked = await reqJson(port, 'GET', `/api/check-linked?cwd=${encodeURIComponent(linkTestDir)}`);
    assert.strictEqual(chkUnlocked.data.linked, true);
    assert.strictEqual(chkUnlocked.data.project, 'demo');

    const springRes = await reqJson(port, 'GET', '/spring/demo/dev.properties');
    assert.strictEqual(springRes.status, 200);
    assert(springRes.raw.includes('INJECTED_KEY=ram-only-secret'), 'Spring properties should return KEY=VALUE');

    const envJsonRes = await reqJson(port, 'GET', '/env/demo/dev');
    assert.strictEqual(envJsonRes.status, 200);
    assert.strictEqual(envJsonRes.data.INJECTED_KEY, 'ram-only-secret');

    const envKeyRes = await reqJson(port, 'GET', '/env/demo/dev/INJECTED_KEY');
    assert.strictEqual(envKeyRes.status, 200);
    assert.strictEqual(envKeyRes.raw, 'ram-only-secret');

    // Verify linkedDirHints works even when locked
    await reqJson(port, 'POST', '/api/lock');
    const chkLocked = await reqJson(port, 'GET', `/api/check-linked?cwd=${encodeURIComponent(linkTestDir)}`);
    assert.strictEqual(chkLocked.data.linked, true);
    assert.strictEqual(chkLocked.data.locked, true);

    await reqJson(port, 'POST', '/api/unlock', { pin: '2468', ttlMinutes: 60 });
    const resetRes = await reqJson(port, 'POST', '/api/reset-vault', {});
    assert.strictEqual(resetRes.status, 200);
    assert.strictEqual(resetRes.data.status.initialized, false, 'Vault reset should return to uninitialized First-Run state');
    console.log('[PASS] 6. End-to-End Daemon + vlt run + vlt aws-cred + AI Turbo + WindowBounds + RevealPIN + Reset');
  } finally {
    daemonInfo.server.close();
    fs.rmSync(TEST_HOME, { recursive: true, force: true });
  }

  console.log('\nALL ENVGUARD TESTS PASSED!');
}

runTests().catch((err) => {
  console.error('TEST FAILED:', err);
  process.exit(1);
});
