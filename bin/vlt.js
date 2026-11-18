#!/usr/bin/env node
'use strict';

const { spawn } = require('child_process');
const fs = require('fs');
const http = require('http');
const path = require('path');
const readline = require('readline');
const { loadConfig, saveConfig, parseEnvString, normalizeDirKey } = require('../src/crypto-vault');
const { getDaemonInfoPath } = require('../src/daemon');
const {
  getShellAutoHookStatus,
  installShellAutoHook,
  removeShellAutoHook,
} = require('../src/integrations');
const {
  openDesktopAppWindow,
  ensureTrayAgentRunning,
  installDesktopShortcuts,
} = require('../src/desktop-shell');

function collectEnvHints() {
  const keys = [
    'ANTIGRAVITY_CLI_ALIAS',
    'ANTIGRAVITY_AGENT',
    'CLAUDECODE',
    'CLAUDE_CODE_ENTRYPOINT',
    'CURSOR_TRACE_ID',
    'WINDSURF_AGENT',
    'AIDER_MODEL',
    'GEMINI_CLI',
    'TERM_PROGRAM',
  ];
  const hints = {};
  for (const k of keys) {
    if (process.env[k]) hints[k] = process.env[k];
  }
  return hints;
}

function getTargetPort() {
  const cfg = loadConfig();
  const infoPath = getDaemonInfoPath();
  if (fs.existsSync(infoPath)) {
    try {
      const info = JSON.parse(fs.readFileSync(infoPath, 'utf8'));
      if (info.port) return Number(info.port);
    } catch {
      // ignore stale daemon.json
    }
  }
  return cfg.port;
}

function httpRequest(port, method, reqPath, bodyObj = null, timeoutMs = 45000) {
  return new Promise((resolve, reject) => {
    const payload = bodyObj ? JSON.stringify(bodyObj) : null;
    const reqOpts = {
      hostname: '127.0.0.1',
      port,
      path: reqPath,
      method,
      headers: payload
        ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }
        : undefined,
    };
    if (timeoutMs > 0) {
      reqOpts.timeout = timeoutMs;
    }
    const req = http.request(reqOpts, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let json = {};
          try { json = JSON.parse(text); } catch { /* ignore */ }
          resolve({ status: res.statusCode, data: json, raw: text });
        });
      }
    );
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('DAEMON_TIMEOUT'));
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function pingDaemon(port) {
  try {
    const res = await httpRequest(port, 'GET', '/api/status', null, 500);
    return res.status === 200 ? { port, status: res.data } : null;
  } catch {
    return null;
  }
}

async function ensureDaemonRunning() {
  const initialPort = getTargetPort();
  const existing = await pingDaemon(initialPort);
  if (existing) {
    return { ...existing, baseUrl: `http://127.0.0.1:${existing.port}` };
  }

  const daemonScript = path.resolve(__dirname, '..', 'src', 'daemon.js');
  const child = spawn(process.execPath, [daemonScript], {
    detached: true,
    stdio: 'ignore',
    windowsHide: true,
    env: process.env,
  });
  child.unref();

  const deadline = Date.now() + 3000;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 80));
    const currentPort = getTargetPort();
    const alive = await pingDaemon(currentPort);
    if (alive) {
      return { ...alive, baseUrl: `http://127.0.0.1:${alive.port}` };
    }
  }
  throw new Error('Failed to start EnvGuard background daemon.');
}

function promptLine(question, hidden = false) {
  return new Promise((resolve) => {
    if (!process.stdin.isTTY) {
      const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
      rl.question(question, (ans) => {
        rl.close();
        resolve(ans);
      });
      return;
    }
    if (!hidden) {
      const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
      rl.question(question, (ans) => {
        rl.close();
        resolve(ans);
      });
      return;
    }

    process.stderr.write(question);
    const stdin = process.stdin;
    const wasRaw = stdin.isRaw;
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    let value = '';
    const onData = (ch) => {
      if (ch === '\r' || ch === '\n' || ch === '\u0004') {
        stdin.setRawMode(Boolean(wasRaw));
        stdin.pause();
        stdin.removeListener('data', onData);
        process.stderr.write('\n');
        resolve(value);
      } else if (ch === '\u0003') {
        process.exit(130);
      } else if (ch === '\b' || ch === '\x7f') {
        if (value.length > 0) value = value.slice(0, -1);
      } else {
        value += ch;
      }
    };
    stdin.on('data', onData);
  });
}

function parseFlags(args) {
  const flags = {};
  const positionals = [];
  let passthrough = [];
  const dashIdx = args.indexOf('--');
  const head = dashIdx === -1 ? args : args.slice(0, dashIdx);
  if (dashIdx !== -1) passthrough = args.slice(dashIdx + 1);

  for (let i = 0; i < head.length; i += 1) {
    const a = head[i];
    if (a.startsWith('--')) {
      const eqIdx = a.indexOf('=');
      if (eqIdx !== -1) {
        flags[a.slice(2, eqIdx)] = a.slice(eqIdx + 1);
      } else {
        const key = a.slice(2);
        const next = head[i + 1];
        if (next !== undefined && (!next.startsWith('-') || /^-\d+$/.test(next))) {
          flags[key] = next;
          i += 1;
        } else {
          flags[key] = true;
        }
      }
    } else if (a.startsWith('-') && a.length === 2 && !/^-\d+$/.test(a)) {
      const key = a.slice(1);
      const next = head[i + 1];
      if (next !== undefined && (!next.startsWith('-') || /^-\d+$/.test(next))) {
        flags[key] = next;
        i += 1;
      } else {
        flags[key] = true;
      }
    } else {
      positionals.push(a);
    }
  }
  return { flags, positionals, passthrough };
}

function printUsage() {
  console.log(`EnvGuard (vlt) — Encrypted Secret & Environment Vault

Commands:
  vlt init [--pin <pin>] [--ttl <min>]
  vlt recover [--key <EVG-...>] [--pin <newPin>]
  vlt ui | app
  vlt install-desktop
  vlt unlock [--pin <pin>] [--ttl <min>]
  vlt lock
  vlt status
  vlt turbo [<minutes>|off]
  vlt link -p <project> -e <env> [dir]
  vlt unlink [dir]
  vlt is-linked [dir]
  vlt hook <install|uninstall|status>
  vlt run [-p <project>] [-e <env>] [--env-file <path>] -- <command...>
  vlt set <project> <env> <KEY=VALUE> [--policy session|confirm|pin_confirm|blocked] [--critical]
  vlt get <project> <env> [KEY]
  vlt rollback <project> <env> <KEY> [index]
  vlt export -p <project> -e <env> --format html|vltpack|env|example|tpl -o <file> [--pass <pass>]
  vlt import <file> -p <project> -e <env> [--mode merge|overwrite] [--pass <pass>]
  vlt aws-cred --profile <name>
  vlt git-cred <get|store|erase>
  vlt scan-os
  vlt config [--vault-path <path>] [--autostart on|off] [--popup-timeout <sec>]`);
}

function getAuthHttpTimeout(daemon) {
  const secs = daemon.status?.popupTimeoutSeconds ?? 30;
  return secs > 0 ? (secs + 15) * 1000 : 0;
}

function readStdinText() {
  return new Promise((resolve) => {
    const chunks = [];
    process.stdin.on('data', (c) => chunks.push(c));
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  });
}

async function cmdRun(daemon, flags, passthrough, positionals) {
  const cmdArgs = passthrough.length > 0 ? passthrough : positionals;
  if (cmdArgs.length === 0) {
    console.error('Usage: vlt run [-p <project>] [-e <env>] -- <command...>');
    process.exit(1);
  }

  let project = flags.p || flags.project || '';
  let env = flags.e || flags.env || '';
  const injectedVars = {};

  // Inspect local .env or .env.tpl for vlt:// references if present
  const localEnvCandidates = flags['env-file']
    ? [path.resolve(flags['env-file'])]
    : [path.resolve('.env.tpl'), path.resolve('.env')];

  const refGroups = new Map();
  for (const envFile of localEnvCandidates) {
    if (!fs.existsSync(envFile)) continue;
    const parsed = parseEnvString(fs.readFileSync(envFile, 'utf8'));
    for (const [k, v] of Object.entries(parsed)) {
      const m = String(v).match(/^vlt:\/\/([^/]+)\/([^/]+)\/(.+)$/);
      if (m) {
        const gKey = `${m[1]}\0${m[2]}`;
        if (!refGroups.has(gKey)) refGroups.set(gKey, { project: m[1], env: m[2], map: {} });
        refGroups.get(gKey).map[m[3]] = k;
      } else if (!Object.prototype.hasOwnProperty.call(injectedVars, k)) {
        injectedVars[k] = v;
      }
    }
    break;
  }

  const callerPayloadBase = {
    cwd: process.cwd(),
    callerPid: process.ppid,
    callerCommand: cmdArgs.join(' '),
    envHints: collectEnvHints(),
  };

  const authTimeoutMs = getAuthHttpTimeout(daemon);
  if (project || refGroups.size === 0) {
    const authRes = await httpRequest(daemon.port, 'POST', '/api/authorize-and-fetch', {
      ...callerPayloadBase,
      resourceType: 'env',
      project,
      env,
    }, authTimeoutMs);
    if (authRes.status !== 200) {
      console.error(`[EnvGuard] Access denied or failed (${authRes.data.error || authRes.status})`);
      process.exit(1);
    }
    Object.assign(injectedVars, authRes.data.data?.vars || {});
  }

  for (const grp of refGroups.values()) {
    const res = await httpRequest(daemon.port, 'POST', '/api/authorize-and-fetch', {
      ...callerPayloadBase,
      resourceType: 'env',
      project: grp.project,
      env: grp.env,
      keys: Object.keys(grp.map),
    }, authTimeoutMs);
    if (res.status !== 200) {
      console.error(`[EnvGuard] Access denied for vlt://${grp.project}/${grp.env} (${res.data.error || res.status})`);
      process.exit(1);
    }
    const fetched = res.data.data?.vars || {};
    for (const [vaultKey, targetVar] of Object.entries(grp.map)) {
      if (Object.prototype.hasOwnProperty.call(fetched, vaultKey)) {
        injectedVars[targetVar] = fetched[vaultKey];
      }
    }
  }

  const runEnv = { ...process.env, ...injectedVars, ENVGUARD_ACTIVE: '1' };
  const spawnChild = (useShell) => {
    const command = useShell && process.platform === 'win32'
      ? cmdArgs.map((a) => (/[\s"&|<>^()]/.test(a) ? `"${a.replace(/"/g, '\\"')}"` : a)).join(' ')
      : cmdArgs[0];
    const args = useShell && process.platform === 'win32' ? [] : cmdArgs.slice(1);
    const child = spawn(command, args, {
      stdio: 'inherit',
      shell: useShell,
      env: runEnv,
    });
    child.on('error', (err) => {
      if (!useShell && process.platform === 'win32' && (err.code === 'ENOENT' || err.code === 'EINVAL')) {
        spawnChild(true);
        return;
      }
      console.error(`[EnvGuard] Failed to launch command: ${err.message}`);
      process.exit(1);
    });
    child.on('exit', (code, signal) => {
      if (signal) process.kill(process.pid, signal);
      process.exit(code ?? 0);
    });
  };
  spawnChild(false);
}

async function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  if (!cmd || cmd === '--help' || cmd === '-h' || cmd === 'help') {
    printUsage();
    return;
  }

  const { flags, positionals, passthrough } = parseFlags(argv.slice(1));

  if (cmd === 'is-linked') {
    const dirArg = path.resolve(positionals[0] || process.cwd());
    const targetPort = getTargetPort();
    const alive = await pingDaemon(targetPort);
    if (alive) {
      const res = await httpRequest(targetPort, 'GET', `/api/check-linked?cwd=${encodeURIComponent(dirArg)}`, null, 1500);
      if (res.status === 200 && res.data.linked) {
        if (flags.json) console.log(JSON.stringify(res.data));
        process.exit(0);
      }
      process.exit(1);
    }
    const hints = new Set(loadConfig().linkedDirHints || []);
    let cur = dirArg;
    while (true) {
      if (hints.has(normalizeDirKey(cur))) process.exit(0);
      const parent = path.dirname(cur);
      if (parent === cur) break;
      cur = parent;
    }
    process.exit(1);
  }

  if (cmd === 'hook') {
    const sub = positionals[0] || 'status';
    if (sub === 'install') {
      const res = installShellAutoHook();
      console.log(`Shell auto-hook installed in:\n  - ${res.profiles.join('\n  - ')}`);
      return;
    }
    if (sub === 'uninstall' || sub === 'remove') {
      const res = removeShellAutoHook();
      console.log(`Shell auto-hook removed from:\n  - ${res.profiles.join('\n  - ')}`);
      return;
    }
    const st = getShellAutoHookStatus();
    console.log(JSON.stringify(st, null, 2));
    return;
  }

  const daemon = await ensureDaemonRunning();

  if (cmd === 'ui' || cmd === 'app') {
    const url = `${daemon.baseUrl}/`;
    ensureTrayAgentRunning(daemon.port);
    const win = openDesktopAppWindow(url);
    console.log(`EnvGuard Desktop App launched (${win.mode})`);
    return;
  }

  if (cmd === 'app-window') {
    const url = `${daemon.baseUrl}/`;
    openDesktopAppWindow(url);
    return;
  }

  if (cmd === 'install-desktop') {
    const res = installDesktopShortcuts();
    console.log('EnvGuard desktop shortcuts installed:');
    for (const s of res.shortcuts) {
      console.log(`  - ${s}`);
    }
    return;
  }

  if (cmd === 'status') {
    const res = await httpRequest(daemon.port, 'GET', '/api/status');
    console.log(JSON.stringify(res.data, null, 2));
    return;
  }

  if (cmd === 'init') {
    const pin = flags.pin || (await promptLine('Master PIN (min 4 chars): ', true));
    const ttl = Number(flags.ttl ?? 240);
    const res = await httpRequest(daemon.port, 'POST', '/api/init', { pin, defaultTtlMinutes: ttl, ttlMinutes: ttl });
    if (res.status !== 200) {
      console.error(`Init failed: ${res.data.error}`);
      process.exit(1);
    }
    console.log('Vault initialized and unlocked!');
    console.log(`EMERGENCY RECOVERY KEY (save offline now): ${res.data.recoveryKey}`);
    return;
  }

  if (cmd === 'recover') {
    const recoveryKey = flags.key || (await promptLine('Emergency Recovery Key (EVG-...): ', false));
    const newPin = flags.pin || (await promptLine('New Master PIN (min 4 chars): ', true));
    const res = await httpRequest(daemon.port, 'POST', '/api/recover', { recoveryKey, newPin });
    if (res.status !== 200) {
      console.error(`Recovery failed: ${res.data.error}`);
      process.exit(1);
    }
    console.log('Vault recovered and unlocked with your new PIN.');
    return;
  }

  if (cmd === 'unlock') {
    const pin = flags.pin || (await promptLine('Master PIN: ', true));
    const ttlMinutes = flags.ttl !== undefined ? Number(flags.ttl) : undefined;
    const res = await httpRequest(daemon.port, 'POST', '/api/unlock', { pin, ttlMinutes });
    if (res.status !== 200) {
      console.error(`Unlock failed: ${res.data.error}`);
      process.exit(1);
    }
    console.log('Vault unlocked.');
    return;
  }

  if (cmd === 'lock') {
    await httpRequest(daemon.port, 'POST', '/api/lock', {});
    console.log('Vault locked and session wiped.');
    return;
  }

  if (cmd === 'turbo') {
    const arg = positionals[0];
    const minutes = arg === 'off' ? 0 : (arg !== undefined ? Number(arg) : 30);
    const res = await httpRequest(daemon.port, 'POST', '/api/turbo', { minutes });
    if (res.status !== 200) {
      console.error(`Turbo failed: ${res.data.error}`);
      process.exit(1);
    }
    console.log(minutes > 0 ? `⚡ AI Turbo Mode ENABLED for ${minutes} minutes.` : 'AI Turbo Mode DISABLED.');
    return;
  }

  if (cmd === 'link') {
    const project = flags.p || flags.project;
    const env = flags.e || flags.env || 'dev';
    const dirPath = positionals[0] || process.cwd();
    if (!project) {
      console.error('Usage: vlt link -p <project> [-e <env>] [dir]');
      process.exit(1);
    }
    const res = await httpRequest(daemon.port, 'POST', '/api/links', { dirPath, project, env });
    if (res.status !== 200) {
      console.error(`Link failed: ${res.data.error}`);
      process.exit(1);
    }
    console.log(`Linked ${res.data.link.displayPath} -> ${project} (${env})`);
    return;
  }

  if (cmd === 'unlink') {
    const dirPath = positionals[0] || process.cwd();
    const res = await httpRequest(daemon.port, 'DELETE', '/api/links', { dirPath });
    if (res.status !== 200) {
      console.error(`Unlink failed: ${res.data.error}`);
      process.exit(1);
    }
    console.log(`Unlinked ${path.resolve(dirPath)}`);
    return;
  }

  if (cmd === 'run') {
    await cmdRun(daemon, flags, passthrough, positionals);
    return;
  }

  if (cmd === 'set') {
    const [project, env, kv] = positionals;
    if (!project || !env || !kv || !kv.includes('=')) {
      console.error('Usage: vlt set <project> <env> <KEY=VALUE> [--policy <p>] [--critical]');
      process.exit(1);
    }
    const eq = kv.indexOf('=');
    const key = kv.slice(0, eq);
    const value = kv.slice(eq + 1);
    const res = await httpRequest(daemon.port, 'POST', '/api/projects/var', {
      project,
      env,
      key,
      value,
      policy: flags.policy,
      critical: flags.critical ? true : undefined,
    });
    if (res.status !== 200) {
      console.error(`Set failed: ${res.data.error}`);
      process.exit(1);
    }
    console.log(`Saved ${key} in ${project}/${env}.`);
    return;
  }

  if (cmd === 'get') {
    const [project, env, key] = positionals;
    if (!project || !env) {
      console.error('Usage: vlt get <project> <env> [KEY]');
      process.exit(1);
    }
    const res = await httpRequest(daemon.port, 'POST', '/api/authorize-and-fetch', {
      resourceType: 'env',
      project,
      env,
      keys: key ? [key] : undefined,
      cwd: process.cwd(),
      callerPid: process.ppid,
      callerCommand: `vlt get ${positionals.join(' ')}`,
      envHints: collectEnvHints(),
    }, getAuthHttpTimeout(daemon));
    if (res.status !== 200) {
      console.error(`Access denied or not found: ${res.data.error}`);
      process.exit(1);
    }
    const vars = res.data.data?.vars || {};
    if (key) {
      if (!Object.prototype.hasOwnProperty.call(vars, key)) {
        console.error(`Key not found: ${key}`);
        process.exit(1);
      }
      console.log(vars[key]);
    } else {
      console.log(JSON.stringify(vars, null, 2));
    }
    return;
  }

  if (cmd === 'rollback') {
    const [project, env, key, idxStr] = positionals;
    if (!project || !env || !key) {
      console.error('Usage: vlt rollback <project> <env> <KEY> [historyIndex]');
      process.exit(1);
    }
    const res = await httpRequest(daemon.port, 'POST', '/api/projects/rollback', {
      project,
      env,
      key,
      historyIndex: Number(idxStr || 0),
    });
    if (res.status !== 200) {
      console.error(`Rollback failed: ${res.data.error}`);
      process.exit(1);
    }
    console.log(`Rolled back ${key} in ${project}/${env}.`);
    return;
  }

  if (cmd === 'export') {
    const project = flags.p || flags.project;
    const env = flags.e || flags.env || 'dev';
    const format = flags.format || 'env';
    const outFile = flags.o || flags.out;
    let transferPassword = flags.pass;
    if ((format === 'html' || format === 'vltpack') && !transferPassword) {
      transferPassword = await promptLine('Transfer Password (min 4 chars): ', true);
    }
    const res = await httpRequest(daemon.port, 'POST', '/api/export', {
      project,
      env,
      format,
      transferPassword,
    });
    if (res.status !== 200) {
      console.error(`Export failed: ${res.data.error}`);
      process.exit(1);
    }
    if (outFile) {
      fs.writeFileSync(path.resolve(outFile), res.data.content, 'utf8');
      console.log(`Exported ${format} to ${path.resolve(outFile)}`);
    } else {
      process.stdout.write(res.data.content);
    }
    return;
  }

  if (cmd === 'import') {
    const file = positionals[0];
    const project = flags.p || flags.project;
    const env = flags.e || flags.env || 'dev';
    const mode = flags.mode || 'merge';
    if (!file || !project) {
      console.error('Usage: vlt import <file> -p <project> [-e <env>] [--mode merge|overwrite] [--pass <pass>]');
      process.exit(1);
    }
    const rawContent = fs.readFileSync(path.resolve(file), 'utf8');
    let transferPassword = flags.pass || '';
    if (rawContent.trim().startsWith('VLTPACK1:') && !transferPassword) {
      transferPassword = await promptLine('Transfer Password: ', true);
    }
    const diffRes = await httpRequest(daemon.port, 'POST', '/api/import-diff', {
      project,
      env,
      rawContent,
      transferPassword,
    });
    if (diffRes.status !== 200) {
      console.error(`Import failed: ${diffRes.data.error}`);
      process.exit(1);
    }
    const applyRes = await httpRequest(daemon.port, 'POST', '/api/import-apply', {
      project,
      env,
      incomingMap: diffRes.data.incomingMap,
      mode,
    });
    if (applyRes.status !== 200) {
      console.error(`Import apply failed: ${applyRes.data.error}`);
      process.exit(1);
    }
    const { added, modified, unchanged } = diffRes.data.diff;
    console.log(`Imported into ${project}/${env} (${mode}): +${added.length} added, ~${modified.length} modified, =${unchanged.length} unchanged.`);
    return;
  }

  if (cmd === 'aws-cred') {
    const profile = flags.profile || positionals[0] || 'default';
    const res = await httpRequest(daemon.port, 'POST', '/api/authorize-and-fetch', {
      resourceType: 'aws',
      profile,
      cwd: process.cwd(),
      callerPid: process.ppid,
      callerCommand: `aws-cli credential_process --profile ${profile}`,
      envHints: collectEnvHints(),
    }, getAuthHttpTimeout(daemon));
    if (res.status !== 200) {
      console.error(`[EnvGuard] AWS credential access denied (${res.data.error || res.status})`);
      process.exit(1);
    }
    process.stdout.write(JSON.stringify(res.data.data));
    return;
  }

  if (cmd === 'git-cred') {
    const action = positionals[0] || 'get';
    const inputText = await readStdinText();
    const parsed = {};
    for (const line of inputText.split(/\r?\n/)) {
      const idx = line.indexOf('=');
      if (idx > 0) parsed[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
    }
    if (action === 'get') {
      const res = await httpRequest(daemon.port, 'POST', '/api/authorize-and-fetch', {
        resourceType: 'git',
        host: parsed.host,
        username: parsed.username,
        cwd: process.cwd(),
        callerPid: process.ppid,
        callerCommand: `git credential get (${parsed.host || 'unknown'})`,
        envHints: collectEnvHints(),
      }, getAuthHttpTimeout(daemon));
      if (res.status !== 200) {
        process.exit(1);
      }
      const d = res.data.data;
      process.stdout.write(`protocol=${d.protocol}\nhost=${d.host}\nusername=${d.username}\npassword=${d.password}\n\n`);
      return;
    }
    if (action === 'store' && daemon.status?.unlocked && parsed.host && parsed.password) {
      await httpRequest(daemon.port, 'POST', '/api/git/credential', {
        host: parsed.host,
        username: parsed.username || '',
        token: parsed.password,
        protocol: parsed.protocol || 'https',
      }).catch(() => {});
    }
    return;
  }

  if (cmd === 'scan-os') {
    const [awsRes, gitRes, osRes] = await Promise.all([
      httpRequest(daemon.port, 'GET', '/api/aws/scan'),
      httpRequest(daemon.port, 'GET', '/api/git/status'),
      httpRequest(daemon.port, 'GET', '/api/os-env/scan'),
    ]);
    console.log('=== EnvGuard Read-Only System Scan ===');
    console.log('\n[AWS ~/.aws Profiles]');
    if (!awsRes.data.profiles || awsRes.data.profiles.length === 0) {
      console.log('  (none found)');
    } else {
      for (const p of awsRes.data.profiles) {
        console.log(`  - ${p.name} (region: ${p.region}, key: ${p.accessKeyIdMasked}, credential_process: ${p.usesCredentialProcess ? 'ACTIVE' : 'plaintext'})`);
      }
    }
    console.log('\n[Git Credential Helper]');
    console.log(`  Helpers: ${(gitRes.data.helpers || []).join(', ') || '(none)'}`);
    console.log(`  EnvGuard Active: ${gitRes.data.usesEnvGuard ? 'YES' : 'NO'}`);
    console.log(`  ~/.git-credentials plaintext entries: ${gitRes.data.plaintextCount || 0}`);

    console.log('\n[OS User Environment Variables]');
    const osItems = osRes.data.items || [];
    if (osItems.length === 0) {
      console.log('  (none found)');
    } else {
      for (const item of osItems) {
        console.log(`  - ${item.name} = ${item.maskedValue} [${item.suspicious ? 'SENSITIVE' : 'normal'}] (${item.source})`);
      }
    }
    return;
  }

  if (cmd === 'config') {
    if (flags['vault-path'] || flags.autostart !== undefined || flags['popup-timeout'] !== undefined) {
      const popupTimeoutSeconds = flags['popup-timeout'] !== undefined
        ? Math.max(0, Number(flags['popup-timeout']))
        : undefined;
      if (daemon.status?.unlocked) {
        const res = await httpRequest(daemon.port, 'POST', '/api/settings', {
          vaultPath: flags['vault-path'],
          autoStartOs: flags.autostart !== undefined ? (flags.autostart === 'on' || flags.autostart === 'true') : undefined,
          popupTimeoutSeconds,
        });
        if (res.status !== 200) {
          console.error(`Config failed: ${res.data.error}`);
          process.exit(1);
        }
        console.log('Configuration updated.');
      } else {
        const updates = {};
        if (flags['vault-path']) updates.vaultPath = path.resolve(flags['vault-path']);
        if (popupTimeoutSeconds !== undefined) updates.popupTimeoutSeconds = popupTimeoutSeconds;
        saveConfig(updates);
        console.log('Saved local config (unlock vault to migrate or update OS startup).');
      }
      return;
    }
    console.log(JSON.stringify(loadConfig(), null, 2));
    return;
  }

  console.error(`Unknown command: ${cmd}`);
  printUsage();
  process.exit(1);
}

main().catch((err) => {
  console.error(`[EnvGuard] ${err.message}`);
  process.exit(1);
});
