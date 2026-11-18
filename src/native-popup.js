'use strict';

const { execFile, spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const AI_AGENT_PROCESS_PATTERNS = [
  /antigravity/i,
  /claude/i,
  /cursor/i,
  /windsurf/i,
  /copilot/i,
  /aider/i,
  /cline/i,
  /codex/i,
  /gemini/i,
];

const AI_ENV_MARKERS = [
  'ANTIGRAVITY_CLI_ALIAS',
  'ANTIGRAVITY_AGENT',
  'CLAUDECODE',
  'CLAUDE_CODE_ENTRYPOINT',
  'CURSOR_TRACE_ID',
  'WINDSURF_AGENT',
  'AIDER_MODEL',
  'GEMINI_CLI',
];

const SUSPICIOUS_CMD_REGEX = /\b(printenv|env|set|export|dir\s+env:|get-childitem\s+env:|gci\s+env:)\b/i;

function detectAiFromEnvHints(envHints = {}) {
  for (const key of AI_ENV_MARKERS) {
    if (envHints[key]) {
      return `${key}=${String(envHints[key]).slice(0, 40)}`;
    }
  }
  return null;
}

function getProcessAncestryWindows(startPid) {
  return new Promise((resolve) => {
    if (!startPid || process.platform !== 'win32') {
      return resolve([]);
    }
    const psScript = [
      `$p = ${Number(startPid)};`,
      '$procs = @{};',
      'Get-CimInstance Win32_Process -Property ProcessId,ParentProcessId,Name | ForEach-Object { $procs[[int]$_.ProcessId] = $_ };',
      '$chain = @();',
      '$seen = @{};',
      'for ($i = 0; $i -lt 6 -and $p -gt 0 -and $procs.ContainsKey($p) -and -not $seen.ContainsKey($p); $i++) {',
      '  $seen[$p] = $true;',
      '  $cur = $procs[$p];',
      '  $chain += @{ pid = $cur.ProcessId; name = $cur.Name };',
      '  $p = [int]$cur.ParentProcessId;',
      '}',
      '$chain | ConvertTo-Json -Compress',
    ].join(' ');

    execFile(
      'powershell.exe',
      ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', psScript],
      { timeout: 1500, windowsHide: true },
      (err, stdout) => {
        if (err || !stdout || !stdout.trim()) {
          return resolve([]);
        }
        try {
          const parsed = JSON.parse(stdout.trim());
          const arr = Array.isArray(parsed) ? parsed : [parsed];
          resolve(arr.reverse());
        } catch {
          resolve([]);
        }
      }
    );
  });
}

function getProcessAncestryLinux(startPid) {
  const chain = [];
  let pid = Number(startPid);
  const seen = new Set();
  for (let i = 0; i < 6 && pid > 1 && !seen.has(pid); i += 1) {
    seen.add(pid);
    try {
      const stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf8');
      const openIdx = stat.indexOf('(');
      const closeIdx = stat.lastIndexOf(')');
      const name = stat.slice(openIdx + 1, closeIdx);
      const rest = stat.slice(closeIdx + 2).split(' ');
      const ppid = Number(rest[1]);
      chain.unshift({ pid, name });
      pid = ppid;
    } catch {
      break;
    }
  }
  return chain;
}

async function inspectCallerProcess(callerPid, commandStr = '', envHints = {}) {
  let chain = [];
  if (process.platform === 'win32') {
    chain = await getProcessAncestryWindows(callerPid);
  } else {
    chain = getProcessAncestryLinux(callerPid);
  }

  const chainNames = chain.map((c) => `${c.name}(${c.pid})`);
  const chainText = chainNames.length > 0 ? chainNames.join(' -> ') : `pid(${callerPid || 'unknown'})`;
  const envAiMatch = detectAiFromEnvHints(envHints);
  const procAiMatch = chain.some((c) => AI_AGENT_PROCESS_PATTERNS.some((rx) => rx.test(c.name)));
  const isAiAgent = Boolean(envAiMatch || procAiMatch);
  const isSuspiciousCommand = SUSPICIOUS_CMD_REGEX.test(String(commandStr || ''));

  return {
    chainText,
    isAiAgent,
    aiHint: envAiMatch || (procAiMatch ? 'process-tree' : null),
    isSuspiciousCommand,
  };
}

function getPopupLocale(lang = 'en') {
  if (lang === 'es') {
    return {
      windowTitle: 'EnvGuard — Autorización de Secretos',
      badgeCritical: 'CRÍTICO — PIN + CONFIRMACIÓN REQUERIDA',
      badgePinConfirm: 'PIN + CONFIRMACIÓN REQUERIDA',
      badgeAi: 'SOLICITUD DE AGENTE IA / AUTOMATIZACIÓN',
      badgeConfirm: 'CONFIRMACIÓN REQUERIDA',
      badgeLocked: 'BÓVEDA BLOQUEADA — INGRESÁ TU PIN',
      lblResource: 'Recurso:',
      lblCommand: 'Comando:',
      lblChain: 'Cadena de procesos:',
      lblCwd: 'Carpeta:',
      lblCriticalKeys: 'Claves críticas:',
      lblPin: 'PIN Maestro:',
      lblTtl: 'Duración de sesión / permiso:',
      chkTurbo: '⚡ Activar Modo Turbo IA por 30 minutos (no pausar agente)',
      btnConfirm: 'Confirmar y Permitir',
      btnCancel: 'Cancelar',
      ttlOptions: [
        { label: 'Solo esta vez (0 min)', minutes: 0 },
        { label: '15 minutos', minutes: 15 },
        { label: '30 minutos', minutes: 30 },
        { label: '1 hora', minutes: 60 },
        { label: '2 horas', minutes: 120 },
        { label: '4 horas', minutes: 240 },
        { label: '8 horas (Jornada)', minutes: 480 },
        { label: 'Hasta bloquear manualmente', minutes: -1 },
      ],
    };
  }
  return {
    windowTitle: 'EnvGuard — Secret Access Authorization',
    badgeCritical: 'CRITICAL — PIN + CONFIRMATION REQUIRED',
    badgePinConfirm: 'PIN + CONFIRMATION REQUIRED',
    badgeAi: 'AI AGENT / AUTOMATION REQUEST',
    badgeConfirm: 'CONFIRMATION REQUIRED',
    badgeLocked: 'VAULT LOCKED — ENTER MASTER PIN',
    lblResource: 'Resource:',
    lblCommand: 'Command:',
    lblChain: 'Process chain:',
    lblCwd: 'Directory:',
    lblCriticalKeys: 'Critical keys:',
    lblPin: 'Master PIN:',
    lblTtl: 'Session / approval duration:',
    chkTurbo: '⚡ Enable AI Turbo Mode for 30 minutes (auto-approve AI)',
    btnConfirm: 'Confirm & Allow',
    btnCancel: 'Cancel',
    ttlOptions: [
      { label: 'Just once (0 min)', minutes: 0 },
      { label: '15 minutes', minutes: 15 },
      { label: '30 minutes', minutes: 30 },
      { label: '1 hour', minutes: 60 },
      { label: '2 hours', minutes: 120 },
      { label: '4 hours', minutes: 240 },
      { label: '8 hours (Workday)', minutes: 480 },
      { label: 'Until manually locked', minutes: -1 },
    ],
  };
}

function buildWindowsPopupScript() {
  return `
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$ctx = $env:ENVGUARD_POPUP_CTX | ConvertFrom-Json
$loc = $ctx.loc

$form = New-Object System.Windows.Forms.Form
$form.Text = $loc.windowTitle
$form.ClientSize = New-Object System.Drawing.Size(540, $(if ($ctx.needPin) { 450 } else { 385 }))
$form.StartPosition = 'CenterScreen'
if ($ctx.popupX -ne $null -and $ctx.popupY -ne $null) {
  $vs = [System.Windows.Forms.SystemInformation]::VirtualScreen
  $px = [int]$ctx.popupX
  $py = [int]$ctx.popupY
  if ($px -ge ($vs.Left - 100) -and $px -le ($vs.Right - 100) -and $py -ge $vs.Top -and $py -le ($vs.Bottom - 80)) {
    $form.StartPosition = 'Manual'
    $form.Location = New-Object System.Drawing.Point($px, $py)
  }
}
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.TopMost = $true
$form.BackColor = [System.Drawing.ColorTranslator]::FromHtml('#0f172a')
$form.ForeColor = [System.Drawing.ColorTranslator]::FromHtml('#f8fafc')
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9.5)

$bannerColor = '#2563eb'
if ($ctx.isCritical -or $ctx.effectivePolicy -eq 'pin_confirm') { $bannerColor = '#dc2626' }
elseif ($ctx.isAiAgent -or $ctx.isSuspiciousCommand) { $bannerColor = '#d97706' }

$banner = New-Object System.Windows.Forms.Panel
$banner.SetBounds(0, 0, 540, 44)
$banner.BackColor = [System.Drawing.ColorTranslator]::FromHtml($bannerColor)
$form.Controls.Add($banner)

$badgeLbl = New-Object System.Windows.Forms.Label
$badgeLbl.Text = $ctx.bannerText
$badgeLbl.SetBounds(16, 10, 508, 24)
$badgeLbl.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
$badgeLbl.ForeColor = [System.Drawing.Color]::White
$banner.Controls.Add($badgeLbl)

$y = 58
function Add-InfoRow([string]$label, [string]$val, [string]$colorHex) {
  $lbl = New-Object System.Windows.Forms.Label
  $lbl.Text = $label
  $lbl.SetBounds(18, $script:y, 130, 20)
  $lbl.ForeColor = [System.Drawing.ColorTranslator]::FromHtml('#94a3b8')
  $form.Controls.Add($lbl)

  $valBox = New-Object System.Windows.Forms.Label
  $valBox.Text = $val
  $valBox.SetBounds(152, $script:y, 370, 34)
  $valBox.ForeColor = [System.Drawing.ColorTranslator]::FromHtml($colorHex)
  $form.Controls.Add($valBox)
  $script:y += 36
}

Add-InfoRow $loc.lblResource $ctx.resourceLabel '#f8fafc'
Add-InfoRow $loc.lblCommand $ctx.callerCommand '#93c5fd'
Add-InfoRow $loc.lblChain $ctx.processChain '#cbd5e1'
Add-InfoRow $loc.lblCwd $ctx.cwd '#cbd5e1'

if ($ctx.criticalKeysText -and $ctx.criticalKeysText.Length -gt 0) {
  Add-InfoRow $loc.lblCriticalKeys $ctx.criticalKeysText '#fca5a5'
}

$pinInput = $null
if ($ctx.needPin) {
  $pinLbl = New-Object System.Windows.Forms.Label
  $pinLbl.Text = $loc.lblPin
  $pinLbl.SetBounds(18, $y + 4, 130, 22)
  $pinLbl.ForeColor = [System.Drawing.ColorTranslator]::FromHtml('#f8fafc')
  $pinLbl.Font = New-Object System.Drawing.Font('Segoe UI', 9.5, [System.Drawing.FontStyle]::Bold)
  $form.Controls.Add($pinLbl)

  $pinInput = New-Object System.Windows.Forms.TextBox
  $pinInput.SetBounds(152, $y, 366, 26)
  $pinInput.UseSystemPasswordChar = $true
  $pinInput.BackColor = [System.Drawing.ColorTranslator]::FromHtml('#1e293b')
  $pinInput.ForeColor = [System.Drawing.Color]::White
  $pinInput.BorderStyle = 'FixedSingle'
  $form.Controls.Add($pinInput)
  $y += 38
}

$ttlLbl = New-Object System.Windows.Forms.Label
$ttlLbl.Text = $loc.lblTtl
$ttlLbl.SetBounds(18, $y + 4, 180, 22)
$ttlLbl.ForeColor = [System.Drawing.ColorTranslator]::FromHtml('#94a3b8')
$form.Controls.Add($ttlLbl)

$ttlCombo = New-Object System.Windows.Forms.ComboBox
$ttlCombo.SetBounds(205, $y, 313, 26)
$ttlCombo.DropDownStyle = 'DropDownList'
$ttlCombo.BackColor = [System.Drawing.ColorTranslator]::FromHtml('#1e293b')
$ttlCombo.ForeColor = [System.Drawing.Color]::White
$selectedIdx = 0
for ($i = 0; $i -lt $loc.ttlOptions.Count; $i++) {
  [void]$ttlCombo.Items.Add($loc.ttlOptions[$i].label)
  if ([int]$loc.ttlOptions[$i].minutes -eq [int]$ctx.defaultTtlMinutes) { $selectedIdx = $i }
}
$ttlCombo.SelectedIndex = $selectedIdx
$form.Controls.Add($ttlCombo)
$y += 38

$turboChk = $null
if ($ctx.showTurboOption) {
  $turboChk = New-Object System.Windows.Forms.CheckBox
  $turboChk.Text = $loc.chkTurbo
  $turboChk.SetBounds(18, $y, 500, 24)
  $turboChk.ForeColor = [System.Drawing.ColorTranslator]::FromHtml('#fcd34d')
  $form.Controls.Add($turboChk)
  $y += 34
}

$form.ClientSize = New-Object System.Drawing.Size(540, ($y + 56))

$btnCancel = New-Object System.Windows.Forms.Button
$btnCancel.Text = $loc.btnCancel
$btnCancel.SetBounds(250, $y + 8, 120, 34)
$btnCancel.FlatStyle = 'Flat'
$btnCancel.BackColor = [System.Drawing.ColorTranslator]::FromHtml('#334155')
$btnCancel.ForeColor = [System.Drawing.Color]::White
$btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.Controls.Add($btnCancel)

$btnOk = New-Object System.Windows.Forms.Button
$btnOk.Text = $loc.btnConfirm
$btnOk.SetBounds(382, $y + 8, 140, 34)
$btnOk.FlatStyle = 'Flat'
$btnOk.BackColor = [System.Drawing.ColorTranslator]::FromHtml($(if ($ctx.isCritical -or $ctx.effectivePolicy -eq 'pin_confirm') { '#dc2626' } else { '#2563eb' }))
$btnOk.ForeColor = [System.Drawing.Color]::White
$btnOk.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.Controls.Add($btnOk)

$form.AcceptButton = $btnOk
$form.CancelButton = $btnCancel

$script:remaining = [int]$ctx.timeoutSeconds
$script:timedOut = $false
$countdownTimer = $null
if ($script:remaining -gt 0) {
  $btnCancel.Text = "$($loc.btnCancel) ($($script:remaining)s)"
  $countdownTimer = New-Object System.Windows.Forms.Timer
  $countdownTimer.Interval = 1000
  $countdownTimer.Add_Tick({
    $script:remaining--
    if ($script:remaining -le 0) {
      $script:timedOut = $true
      $countdownTimer.Stop()
      $form.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
      $form.Close()
    } else {
      $btnCancel.Text = "$($loc.btnCancel) ($($script:remaining)s)"
    }
  })
}

$form.Add_Shown({
  $form.TopMost = $true
  $form.BringToFront()
  $form.Activate()
  if ($pinInput -ne $null) { $pinInput.Focus() }
  if ($countdownTimer -ne $null) { $countdownTimer.Start() }
})

$script:lastX = $null
$script:lastY = $null
$form.Add_FormClosed({
  $script:lastX = $form.Location.X
  $script:lastY = $form.Location.Y
  if ($countdownTimer -ne $null) {
    $countdownTimer.Stop()
    $countdownTimer.Dispose()
  }
})

$res = $form.ShowDialog()
$chosenTtl = [int]$loc.ttlOptions[$ttlCombo.SelectedIndex].minutes
$out = @{
  approved = ($res -eq [System.Windows.Forms.DialogResult]::OK)
  timedOut = $script:timedOut
  pin = $(if ($pinInput -ne $null) { $pinInput.Text } else { $null })
  ttlMinutes = $chosenTtl
  enableTurboMinutes = $(if ($turboChk -ne $null -and $turboChk.Checked) { 30 } else { 0 })
  popupX = $script:lastX
  popupY = $script:lastY
}
$out | ConvertTo-Json -Compress
`;
}

function showWindowsPopup(ctx) {
  const popupExe = path.resolve(__dirname, '..', 'dist', 'EnvGuardPopup.exe');
  if (fs.existsSync(popupExe)) {
    return new Promise((resolve) => {
      const stamp = `${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
      const tmpIn = path.join(os.tmpdir(), `envguard-in-${stamp}.json`);
      const tmpOut = path.join(os.tmpdir(), `envguard-out-${stamp}.json`);
      const execTimeoutMs = ctx.timeoutSeconds > 0 ? (ctx.timeoutSeconds + 10) * 1000 : 0;
      const cleanup = () => {
        try { fs.unlinkSync(tmpIn); } catch { /* ignore */ }
        try { fs.unlinkSync(tmpOut); } catch { /* ignore */ }
      };
      try {
        fs.writeFileSync(tmpIn, JSON.stringify(ctx), 'utf8');
        execFile(
          popupExe,
          [tmpIn, tmpOut],
          { timeout: execTimeoutMs, windowsHide: false },
          (err) => {
            let raw = '';
            try {
              if (fs.existsSync(tmpOut)) {
                raw = fs.readFileSync(tmpOut, 'utf8').replace(/^\uFEFF/, '').trim();
              }
            } catch { /* ignore */ }
            cleanup();
            if (!raw) {
              return resolve({
                approved: false,
                timedOut: Boolean(err && err.killed),
                pin: null,
                ttlMinutes: 0,
                enableTurboMinutes: 0,
              });
            }
            try {
              const parsed = JSON.parse(raw);
              resolve({
                approved: Boolean(parsed.approved),
                timedOut: Boolean(parsed.timedOut),
                pin: parsed.pin || null,
                ttlMinutes: Number(parsed.ttlMinutes ?? ctx.defaultTtlMinutes),
                enableTurboMinutes: Number(parsed.enableTurboMinutes || 0),
                popupX: typeof parsed.popupX === 'number' ? parsed.popupX : null,
                popupY: typeof parsed.popupY === 'number' ? parsed.popupY : null,
              });
            } catch {
              resolve({ approved: false, timedOut: false, pin: null, ttlMinutes: 0, enableTurboMinutes: 0 });
            }
          }
        );
      } catch {
        cleanup();
        resolve({ approved: false, timedOut: false, pin: null, ttlMinutes: 0, enableTurboMinutes: 0 });
      }
    });
  }

  return new Promise((resolve) => {
    const tmpFile = path.join(os.tmpdir(), `envguard-popup-${process.pid}-${Date.now()}.ps1`);
    const execTimeoutMs = ctx.timeoutSeconds > 0 ? (ctx.timeoutSeconds + 10) * 1000 : 0;
    try {
      fs.writeFileSync(tmpFile, buildWindowsPopupScript(), 'utf8');
      execFile(
        'powershell.exe',
        ['-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File', tmpFile],
        {
          env: { ...process.env, ENVGUARD_POPUP_CTX: JSON.stringify(ctx) },
          timeout: execTimeoutMs,
          windowsHide: true,
        },
        (err, stdout) => {
          try { fs.unlinkSync(tmpFile); } catch { /* ignore */ }
          if (err || !stdout || !stdout.trim()) {
            return resolve({
              approved: false,
              timedOut: Boolean(err && err.killed),
              pin: null,
              ttlMinutes: 0,
              enableTurboMinutes: 0,
            });
          }
          try {
            const parsed = JSON.parse(stdout.trim());
            resolve({
              approved: Boolean(parsed.approved),
              timedOut: Boolean(parsed.timedOut),
              pin: parsed.pin || null,
              ttlMinutes: Number(parsed.ttlMinutes ?? ctx.defaultTtlMinutes),
              enableTurboMinutes: Number(parsed.enableTurboMinutes || 0),
              popupX: typeof parsed.popupX === 'number' ? parsed.popupX : null,
              popupY: typeof parsed.popupY === 'number' ? parsed.popupY : null,
            });
          } catch {
            resolve({ approved: false, timedOut: false, pin: null, ttlMinutes: 0, enableTurboMinutes: 0 });
          }
        }
      );
    } catch {
      try { fs.unlinkSync(tmpFile); } catch { /* ignore */ }
      resolve({ approved: false, timedOut: false, pin: null, ttlMinutes: 0, enableTurboMinutes: 0 });
    }
  });
}

function hasCommand(cmd) {
  const res = spawnSync('which', [cmd], { encoding: 'utf8' });
  return res.status === 0;
}

async function showLinuxPopup(ctx) {
  const hasDisplay = Boolean(process.env.DISPLAY || process.env.WAYLAND_DISPLAY);
  const msg = `${ctx.bannerText}\n\n${ctx.loc.lblResource} ${ctx.resourceLabel}\n${ctx.loc.lblCommand} ${ctx.callerCommand}\n${ctx.loc.lblChain} ${ctx.processChain}\n${ctx.loc.lblCwd} ${ctx.cwd}`;

  const spawnOpts = {
    encoding: 'utf8',
    timeout: ctx.timeoutSeconds > 0 ? ctx.timeoutSeconds * 1000 : undefined,
  };

  if (hasDisplay && hasCommand('zenity')) {
    const timeoutArgs = ctx.timeoutSeconds > 0 ? [`--timeout=${ctx.timeoutSeconds}`] : [];
    if (ctx.needPin) {
      const z = spawnSync('zenity', ['--password', `--title=${ctx.loc.windowTitle}`, `--text=${msg}`, ...timeoutArgs], spawnOpts);
      return {
        approved: z.status === 0,
        timedOut: z.status === 5 || Boolean(z.error),
        pin: z.status === 0 ? z.stdout.trim() : null,
        ttlMinutes: ctx.defaultTtlMinutes,
        enableTurboMinutes: 0,
      };
    }
    const z = spawnSync('zenity', ['--question', `--title=${ctx.loc.windowTitle}`, `--text=${msg}`, `--ok-label=${ctx.loc.btnConfirm}`, `--cancel-label=${ctx.loc.btnCancel}`, ...timeoutArgs], spawnOpts);
    return { approved: z.status === 0, timedOut: z.status === 5 || Boolean(z.error), pin: null, ttlMinutes: ctx.defaultTtlMinutes, enableTurboMinutes: 0 };
  }

  if (hasDisplay && hasCommand('kdialog')) {
    if (ctx.needPin) {
      const k = spawnSync('kdialog', ['--password', msg, '--title', ctx.loc.windowTitle], spawnOpts);
      return {
        approved: k.status === 0,
        timedOut: Boolean(k.error),
        pin: k.status === 0 ? k.stdout.trim() : null,
        ttlMinutes: ctx.defaultTtlMinutes,
        enableTurboMinutes: 0,
      };
    }
    const k = spawnSync('kdialog', ['--yesno', msg, '--title', ctx.loc.windowTitle], spawnOpts);
    return { approved: k.status === 0, timedOut: Boolean(k.error), pin: null, ttlMinutes: ctx.defaultTtlMinutes, enableTurboMinutes: 0 };
  }

  // Headless / SSH TTY fallback
  try {
    const fd = fs.openSync('/dev/tty', 'r+');
    fs.writeSync(fd, `\n[EnvGuard] ${msg}\n`);
    let pin = null;
    if (ctx.needPin) {
      fs.writeSync(fd, `${ctx.loc.lblPin} `);
      const buf = Buffer.alloc(256);
      const bytes = fs.readSync(fd, buf, 0, 256, null);
      pin = buf.toString('utf8', 0, bytes).trim();
    }
    fs.writeSync(fd, `${ctx.loc.btnConfirm}? (y/N): `);
    const ansBuf = Buffer.alloc(16);
    const ansBytes = fs.readSync(fd, ansBuf, 0, 16, null);
    fs.closeSync(fd);
    const ans = ansBuf.toString('utf8', 0, ansBytes).trim().toLowerCase();
    return {
      approved: ans === 'y' || ans === 'yes' || ans === 's' || ans === 'si',
      pin,
      ttlMinutes: ctx.defaultTtlMinutes,
      enableTurboMinutes: 0,
    };
  } catch {
    return { approved: false, pin: null, ttlMinutes: 0, enableTurboMinutes: 0 };
  }
}

async function requestUserAuthorization(options) {
  if (process.env.ENVGUARD_TEST_POPUP_RESPONSE) {
    try {
      return JSON.parse(process.env.ENVGUARD_TEST_POPUP_RESPONSE);
    } catch {
      return { approved: false, pin: null, ttlMinutes: 0, enableTurboMinutes: 0 };
    }
  }

  const lang = options.lang === 'es' ? 'es' : 'en';
  const loc = getPopupLocale(lang);
  const needPin = Boolean(options.isVaultLocked || options.effectivePolicy === 'pin_confirm');

  let bannerText = loc.badgeConfirm;
  if (options.critical && options.effectivePolicy === 'pin_confirm') {
    bannerText = loc.badgeCritical;
  } else if (options.effectivePolicy === 'pin_confirm') {
    bannerText = loc.badgePinConfirm;
  } else if (options.isVaultLocked) {
    bannerText = loc.badgeLocked;
  } else if (options.isAiAgent || options.isSuspiciousCommand) {
    bannerText = loc.badgeAi;
  }

  const ctx = {
    loc,
    bannerText,
    needPin,
    isCritical: Boolean(options.critical),
    effectivePolicy: options.effectivePolicy || 'confirm',
    isAiAgent: Boolean(options.isAiAgent),
    isSuspiciousCommand: Boolean(options.isSuspiciousCommand),
    showTurboOption: Boolean(options.isAiAgent || options.effectivePolicy !== 'pin_confirm'),
    resourceLabel: String(options.resourceLabel || ''),
    callerCommand: String(options.callerCommand || 'unknown').slice(0, 140),
    processChain: String(options.processChain || '').slice(0, 140),
    cwd: String(options.cwd || process.cwd()).slice(0, 140),
    criticalKeysText: Array.isArray(options.criticalKeys) && options.criticalKeys.length > 0
      ? options.criticalKeys.join(', ')
      : '',
    defaultTtlMinutes: options.defaultTtlMinutes !== undefined ? Number(options.defaultTtlMinutes) : 240,
    timeoutSeconds: options.timeoutSeconds !== undefined ? Math.max(0, Number(options.timeoutSeconds)) : 30,
    popupX: typeof options.popupBounds?.x === 'number' ? options.popupBounds.x : null,
    popupY: typeof options.popupBounds?.y === 'number' ? options.popupBounds.y : null,
  };

  if (process.platform === 'win32') {
    return showWindowsPopup(ctx);
  }
  return showLinuxPopup(ctx);
}

module.exports = {
  inspectCallerProcess,
  requestUserAuthorization,
  getPopupLocale,
};
