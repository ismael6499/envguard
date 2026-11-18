/* EnvGuard Dashboard UI Controller */
'use strict';

(function () {
  const state = {
    lang: localStorage.getItem('envguard_lang') || 'en',
    locales: { en: {}, es: {} },
    status: null,
    projects: {},
    linkedDirs: {},
    awsProfiles: {},
    awsDiskScan: null,
    gitCredentials: {},
    gitHelperStatus: null,
    osScanItems: [],
    osBackups: {},
    selectedProject: '',
    selectedEnv: '',
    revealedKeys: new Set(),
    pendingDiff: null,
    pendingRevealAction: null,
  };

  async function ensureRevealAuthorized(onSuccess) {
    try {
      const st = await api('/api/status');
      state.status = st;
      if (st.revealAuthorized && Number(st.revealPinTtlMinutes) !== 0) {
        await onSuccess();
        return;
      }
    } catch {
      // Fall through to prompt
    }
    state.pendingRevealAction = onSuccess;
    document.getElementById('revealPinInput').value = '';
    openModal('revealPinModal');
    setTimeout(() => document.getElementById('revealPinInput').focus(), 30);
  }

  function t(key, vars = {}) {
    const dict = state.locales[state.lang] || state.locales.en || {};
    let str = dict[key] ?? state.locales.en[key] ?? key;
    for (const [k, v] of Object.entries(vars)) {
      str = str.replace(new RegExp(`\\{${k}\\}`, 'g'), String(v));
    }
    return str;
  }

  function applyI18n() {
    document.querySelectorAll('[data-i18n]').forEach((el) => {
      const key = el.getAttribute('data-i18n');
      if (key) el.textContent = t(key);
    });
    document.querySelectorAll('[data-i18n-placeholder]').forEach((el) => {
      const key = el.getAttribute('data-i18n-placeholder');
      if (key) el.setAttribute('placeholder', t(key));
    });
    document.getElementById('langEnBtn').classList.toggle('active', state.lang === 'en');
    document.getElementById('langEsBtn').classList.toggle('active', state.lang === 'es');
    document.title = t('appTitle');
  }

  function showToast(msg) {
    const toast = document.getElementById('toast');
    toast.textContent = msg;
    toast.classList.remove('hidden');
    clearTimeout(showToast._timer);
    showToast._timer = setTimeout(() => toast.classList.add('hidden'), 3200);
  }

  async function api(url, opts = {}) {
    const res = await fetch(url, {
      method: opts.method || 'GET',
      headers: opts.body ? { 'Content-Type': 'application/json' } : undefined,
      body: opts.body ? JSON.stringify(opts.body) : undefined,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(data.error || `HTTP ${res.status}`);
    }
    return data;
  }

  function formatDuration(sec) {
    if (sec < 0) return t('sessionUntilLocked');
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec % 3600) / 60);
    const s = sec % 60;
    if (h > 0) return `${h}h ${m}m`;
    return `${m}:${String(s).padStart(2, '0')}`;
  }

  function renderHeaderStatus() {
    const st = state.status;
    if (!st) return;
    const badge = document.getElementById('statusBadge');
    const timer = document.getElementById('sessionTimerBadge');
    const unlockedCtrls = document.getElementById('unlockedControls');
    const authGate = document.getElementById('authGate');
    const initCard = document.getElementById('initCard');
    const unlockCard = document.getElementById('unlockCard');
    const dashboard = document.getElementById('dashboard');

    if (!st.initialized) {
      badge.className = 'status-badge locked';
      badge.textContent = t('statusUninitialized');
      timer.classList.add('hidden');
      unlockedCtrls.classList.add('hidden');
      authGate.classList.remove('hidden');
      initCard.classList.remove('hidden');
      unlockCard.classList.add('hidden');
      dashboard.classList.add('hidden');
      return;
    }

    if (!st.unlocked) {
      badge.className = 'status-badge locked';
      badge.textContent = t('statusLocked');
      timer.classList.add('hidden');
      unlockedCtrls.classList.add('hidden');
      authGate.classList.remove('hidden');
      initCard.classList.add('hidden');
      unlockCard.classList.remove('hidden');
      dashboard.classList.add('hidden');
      return;
    }

    badge.className = 'status-badge unlocked';
    badge.textContent = t('statusUnlocked');
    timer.classList.remove('hidden');
    timer.textContent = t('sessionRemaining', { time: st.untilLocked ? t('sessionUntilLocked') : formatDuration(st.remainingSeconds) });
    unlockedCtrls.classList.remove('hidden');
    authGate.classList.add('hidden');
    dashboard.classList.remove('hidden');

    const turboBtn = document.getElementById('turboToggleBtn');
    if (st.aiTurboActive) {
      turboBtn.className = 'btn btn-turbo on';
      turboBtn.textContent = t('turboBtnOn', { time: formatDuration(st.aiTurboRemainingSeconds) });
    } else {
      turboBtn.className = 'btn btn-turbo off';
      turboBtn.textContent = t('turboBtnOff');
    }
  }

  function openModal(modalId) {
    document.getElementById('modalBackdrop').classList.remove('hidden');
    document.querySelectorAll('#modalBackdrop .modal').forEach((m) => m.classList.add('hidden'));
    document.getElementById(modalId).classList.remove('hidden');
  }

  function closeAllModals() {
    document.getElementById('modalBackdrop').classList.add('hidden');
    document.querySelectorAll('#modalBackdrop .modal').forEach((m) => m.classList.add('hidden'));
  }

  function renderProjectsTab() {
    const pNames = Object.keys(state.projects || {});
    const pSel = document.getElementById('projectSelect');
    const eSel = document.getElementById('envSelect');
    pSel.innerHTML = '';

    if (pNames.length === 0) {
      document.getElementById('activeEnvHeader').textContent = t('noProjectsYet');
      document.getElementById('varsTableBody').innerHTML = '';
      document.getElementById('varsEmptyMsg').classList.add('hidden');
      document.getElementById('linkedDirsList').innerHTML = `<div class="muted">${t('noLinkedDirs')}</div>`;
      eSel.innerHTML = '';
      return;
    }

    if (!state.selectedProject || !state.projects[state.selectedProject]) {
      state.selectedProject = pNames[0];
    }
    for (const p of pNames) {
      const opt = document.createElement('option');
      opt.value = p;
      opt.textContent = p;
      pSel.appendChild(opt);
    }
    pSel.value = state.selectedProject;

    const envs = state.projects[state.selectedProject]?.environments || {};
    const eNames = Object.keys(envs);
    eSel.innerHTML = '';
    if (!state.selectedEnv || !envs[state.selectedEnv]) {
      state.selectedEnv = eNames[0] || '';
    }
    for (const e of eNames) {
      const opt = document.createElement('option');
      opt.value = e;
      opt.textContent = e;
      eSel.appendChild(opt);
    }
    eSel.value = state.selectedEnv;

    const envObj = envs[state.selectedEnv];
    if (!envObj) return;

    document.getElementById('envPolicySelect').value = envObj.policy || 'confirm';
    document.getElementById('envCriticalChk').checked = Boolean(envObj.critical);
    document.getElementById('activeEnvHeader').textContent = `${state.selectedProject} / ${state.selectedEnv}`;

    const tbody = document.getElementById('varsTableBody');
    tbody.innerHTML = '';
    const entries = Object.entries(envObj.vars || {});
    document.getElementById('varsEmptyMsg').classList.toggle('hidden', entries.length > 0);

    for (const [k, info] of entries) {
      const tr = document.createElement('tr');
      const revealId = `${state.selectedProject}:${state.selectedEnv}:${k}`;
      const isShown = state.revealedKeys.has(revealId);

      const tdKey = document.createElement('td');
      const codeK = document.createElement('code');
      codeK.textContent = k;
      tdKey.appendChild(codeK);
      if (info.critical) {
        const badge = document.createElement('span');
        badge.className = 'pill pill-critical';
        badge.style.marginLeft = '6px';
        badge.textContent = t('criticalTag');
        tdKey.appendChild(badge);
      }

      const tdVal = document.createElement('td');
      const codeV = document.createElement('code');
      codeV.textContent = isShown ? info.value : '••••••••••••';
      tdVal.appendChild(codeV);

      const tdPol = document.createElement('td');
      const polSel = document.createElement('select');
      polSel.className = 'compact-select';
      for (const [pv, pk] of [
        ['inherit', 'policyInherit'],
        ['session', 'policySession'],
        ['confirm', 'policyConfirm'],
        ['pin_confirm', 'policyPinConfirm'],
        ['blocked', 'policyBlocked'],
      ]) {
        const o = document.createElement('option');
        o.value = pv;
        o.textContent = t(pk);
        polSel.appendChild(o);
      }
      polSel.value = info.policy || 'inherit';
      polSel.onchange = async () => {
        await api('/api/projects/var', {
          method: 'POST',
          body: { project: state.selectedProject, env: state.selectedEnv, key: k, value: info.value, policy: polSel.value },
        });
        showToast(t('toastSaved'));
        await refreshProjects();
      };
      tdPol.appendChild(polSel);

      const tdCrit = document.createElement('td');
      const critChk = document.createElement('input');
      critChk.type = 'checkbox';
      critChk.checked = Boolean(info.critical);
      critChk.onchange = async () => {
        await api('/api/projects/var', {
          method: 'POST',
          body: { project: state.selectedProject, env: state.selectedEnv, key: k, value: info.value, critical: critChk.checked },
        });
        showToast(t('toastSaved'));
        await refreshProjects();
      };
      tdCrit.appendChild(critChk);

      const tdHist = document.createElement('td');
      const histCount = Array.isArray(info.history) ? info.history.length : 0;
      const histBtn = document.createElement('button');
      histBtn.type = 'button';
      histBtn.className = 'btn btn-secondary compact-btn';
      histBtn.textContent = t('btnHistory', { count: histCount });
      histBtn.onclick = () => ensureRevealAuthorized(() => showHistoryModal(k, info));
      tdHist.appendChild(histBtn);

      const tdAct = document.createElement('td');
      const actWrap = document.createElement('div');
      actWrap.className = 'row-actions';

      const toggleBtn = document.createElement('button');
      toggleBtn.type = 'button';
      toggleBtn.className = 'btn btn-secondary compact-btn';
      toggleBtn.textContent = isShown ? t('btnHide') : t('btnShow');
      toggleBtn.onclick = () => {
        if (isShown) {
          state.revealedKeys.delete(revealId);
          renderProjectsTab();
          return;
        }
        ensureRevealAuthorized(() => {
          state.revealedKeys.add(revealId);
          renderProjectsTab();
        });
      };

      const copyBtn = document.createElement('button');
      copyBtn.type = 'button';
      copyBtn.className = 'btn btn-secondary compact-btn';
      copyBtn.textContent = t('btnCopy');
      copyBtn.onclick = () => {
        ensureRevealAuthorized(async () => {
          await navigator.clipboard.writeText(info.value);
          showToast(t('toastCopied'));
        });
      };

      const editBtn = document.createElement('button');
      editBtn.type = 'button';
      editBtn.className = 'btn btn-secondary compact-btn';
      editBtn.textContent = t('btnEdit');
      editBtn.onclick = () => ensureRevealAuthorized(() => openVarModal(k, info));

      const delBtn = document.createElement('button');
      delBtn.type = 'button';
      delBtn.className = 'btn btn-danger compact-btn';
      delBtn.textContent = t('btnDelete');
      delBtn.onclick = async () => {
        if (!confirm(t('confirmDeleteVar', { key: k }))) return;
        await api('/api/projects/var', {
          method: 'DELETE',
          body: { project: state.selectedProject, env: state.selectedEnv, key: k },
        });
        showToast(t('toastSaved'));
        await refreshProjects();
      };

      actWrap.append(toggleBtn, copyBtn, editBtn, delBtn);
      tdAct.appendChild(actWrap);

      tr.append(tdKey, tdVal, tdPol, tdCrit, tdHist, tdAct);
      tbody.appendChild(tr);
    }

    // Linked Directories
    const linkList = document.getElementById('linkedDirsList');
    linkList.innerHTML = '';
    const matchingLinks = Object.values(state.linkedDirs || {}).filter(
      (l) => l.project === state.selectedProject && l.env === state.selectedEnv
    );
    if (matchingLinks.length === 0) {
      linkList.innerHTML = `<div class="muted">${t('noLinkedDirs')}</div>`;
    } else {
      for (const lnk of matchingLinks) {
        const row = document.createElement('div');
        row.className = 'item-row';
        const code = document.createElement('code');
        code.textContent = lnk.displayPath;
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'btn btn-danger compact-btn';
        btn.textContent = t('btnUnlink');
        btn.onclick = async () => {
          await api('/api/links', { method: 'DELETE', body: { dirPath: lnk.displayPath } });
          await refreshProjects();
        };
        row.append(code, btn);
        linkList.appendChild(row);
      }
    }

    const base = window.location.origin;
    const pEnc = encodeURIComponent(state.selectedProject);
    const eEnc = encodeURIComponent(state.selectedEnv);
    document.getElementById('springUrlCode').textContent = `spring.config.import=optional:${base}/spring/${pEnc}/${eEnc}.properties`;
    document.getElementById('directJsonUrlCode').textContent = `${base}/env/${pEnc}/${eEnc}`;
  }

  function showHistoryModal(key, info) {
    document.getElementById('historyModalTitle').textContent = t('historyModalTitle', { key });
    const list = document.getElementById('historyList');
    list.innerHTML = '';

    const curRow = document.createElement('div');
    curRow.className = 'item-row';
    curRow.innerHTML = `<div><strong>${t('historyCurrent')}</strong><br/><code>${escapeHtml(info.value)}</code></div>`;
    list.appendChild(curRow);

    const hist = info.history || [];
    if (hist.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'muted';
      empty.textContent = t('historyEmpty');
      list.appendChild(empty);
    } else {
      hist.forEach((h, idx) => {
        const row = document.createElement('div');
        row.className = 'item-row';
        const left = document.createElement('div');
        const ts = document.createElement('div');
        ts.className = 'muted';
        ts.textContent = `${t('historySnapshot')} (${new Date(h.updatedAt).toLocaleString()})`;
        const code = document.createElement('code');
        code.textContent = h.value;
        left.append(ts, code);

        const rbBtn = document.createElement('button');
        rbBtn.type = 'button';
        rbBtn.className = 'btn btn-primary compact-btn';
        rbBtn.textContent = t('btnRollback');
        rbBtn.onclick = async () => {
          await api('/api/projects/rollback', {
            method: 'POST',
            body: { project: state.selectedProject, env: state.selectedEnv, key, historyIndex: idx },
          });
          closeAllModals();
          showToast(t('toastSaved'));
          await refreshProjects();
        };

        row.append(left, rbBtn);
        list.appendChild(row);
      });
    }
    openModal('historyModal');
  }

  function escapeHtml(str) {
    return String(str ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  function openVarModal(existingKey = '', existingInfo = null) {
    document.getElementById('varKeyInput').value = existingKey;
    document.getElementById('varValInput').value = existingInfo ? existingInfo.value : '';
    document.getElementById('varPolicySelect').value = existingInfo ? (existingInfo.policy || 'inherit') : 'inherit';
    document.getElementById('varCriticalChk').checked = existingInfo ? Boolean(existingInfo.critical) : false;
    document.getElementById('varDescInput').value = existingInfo ? (existingInfo.description || '') : '';
    openModal('varModal');
  }

  async function refreshProjects() {
    const data = await api('/api/projects');
    state.projects = data.projects || {};
    state.linkedDirs = data.linkedDirs || {};
    renderProjectsTab();
  }

  async function refreshAwsTab() {
    const data = await api('/api/aws');
    state.awsProfiles = data.profiles || {};
    state.awsDiskScan = data.diskScan || null;
    renderAwsTab();
  }

  function renderAwsTab() {
    const diskCard = document.getElementById('awsDiskCard');
    const diskList = document.getElementById('awsDiskList');
    const scanProfiles = state.awsDiskScan?.profiles || [];
    if (scanProfiles.length > 0) {
      diskCard.classList.remove('hidden');
      diskList.innerHTML = '';
      for (const p of scanProfiles) {
        const row = document.createElement('div');
        row.className = 'item-row';
        const left = document.createElement('label');
        left.className = 'checkbox-label';
        const chk = document.createElement('input');
        chk.type = 'checkbox';
        chk.className = 'aws-scan-chk';
        chk.value = p.name;
        chk.checked = true;
        const txt = document.createElement('span');
        txt.innerHTML = `<strong>${escapeHtml(p.name)}</strong> (${escapeHtml(p.region)}) — <code>${escapeHtml(p.accessKeyIdMasked)}</code>`;
        left.append(chk, txt);

        const badge = document.createElement('span');
        badge.className = p.usesCredentialProcess ? 'pill pill-ok' : 'pill pill-muted';
        badge.textContent = p.usesCredentialProcess ? t('awsStatusActive') : t('awsStatusPlaintext');
        row.append(left, badge);
        diskList.appendChild(row);
      }
    } else {
      diskCard.classList.add('hidden');
    }

    const list = document.getElementById('awsVaultList');
    list.innerHTML = '';
    const entries = Object.entries(state.awsProfiles || {});
    if (entries.length === 0) {
      list.innerHTML = `<div class="muted">${t('noAwsProfiles')}</div>`;
      return;
    }
    for (const [name, p] of entries) {
      const row = document.createElement('div');
      row.className = 'item-row';

      const info = document.createElement('div');
      info.innerHTML = `<strong>${escapeHtml(name)}</strong> (${escapeHtml(p.region)})<br/><code>${escapeHtml((p.accessKeyId || '').slice(0, 6))}••••••</code>`;
      if (p.critical) {
        info.innerHTML += ` <span class="pill pill-critical">${t('criticalTag')}</span>`;
      }

      const actions = document.createElement('div');
      actions.className = 'row-actions';

      const polSel = document.createElement('select');
      polSel.className = 'compact-select';
      for (const [pv, pk] of [
        ['session', 'policySession'],
        ['confirm', 'policyConfirm'],
        ['pin_confirm', 'policyPinConfirm'],
        ['blocked', 'policyBlocked'],
      ]) {
        const o = document.createElement('option');
        o.value = pv;
        o.textContent = t(pk);
        polSel.appendChild(o);
      }
      polSel.value = p.policy || 'confirm';
      polSel.onchange = async () => {
        await api('/api/aws/profile', { method: 'POST', body: { name, policy: polSel.value } });
        showToast(t('toastSaved'));
        await refreshAwsTab();
      };

      const actBtn = document.createElement('button');
      actBtn.type = 'button';
      actBtn.className = 'btn btn-primary compact-btn';
      actBtn.textContent = t('btnActivateAwsProcess');
      actBtn.onclick = async () => {
        const res = await api('/api/aws/activate-process', { method: 'POST', body: { profile: name } });
        showToast(t('awsProcessActivated', { path: res.configPath }));
        await refreshAwsTab();
      };

      const rmPlainBtn = document.createElement('button');
      rmPlainBtn.type = 'button';
      rmPlainBtn.className = 'btn btn-secondary compact-btn';
      rmPlainBtn.textContent = t('btnRemoveAwsPlaintext');
      rmPlainBtn.onclick = async () => {
        if (!confirm(t('confirmRemovePlaintext', { profile: name }))) return;
        await api('/api/aws/remove-plaintext', { method: 'POST', body: { profile: name } });
        showToast(t('toastSaved'));
        await refreshAwsTab();
      };

      const delBtn = document.createElement('button');
      delBtn.type = 'button';
      delBtn.className = 'btn btn-danger compact-btn';
      delBtn.textContent = t('btnDelete');
      delBtn.onclick = async () => {
        await api('/api/aws/profile', { method: 'DELETE', body: { name } });
        await refreshAwsTab();
      };

      actions.append(polSel, actBtn, rmPlainBtn, delBtn);
      row.append(info, actions);
      list.appendChild(row);
    }
  }

  async function refreshGitTab() {
    const data = await api('/api/git');
    state.gitCredentials = data.credentials || {};
    state.gitHelperStatus = data.helperStatus || {};
    const banner = document.getElementById('gitHelperBanner');
    const toggleBtn = document.getElementById('toggleGitHelperBtn');
    const active = Boolean(state.gitHelperStatus.usesEnvGuard);
    banner.textContent = active ? t('gitHelperActive') : t('gitHelperInactive');
    toggleBtn.textContent = active ? t('btnDisableGitHelper') : t('btnEnableGitHelper');

    const list = document.getElementById('gitVaultList');
    list.innerHTML = '';
    const entries = Object.values(state.gitCredentials);
    if (entries.length === 0) {
      list.innerHTML = `<div class="muted">${t('noGitCreds')}</div>`;
      return;
    }
    for (const c of entries) {
      const row = document.createElement('div');
      row.className = 'item-row';
      const left = document.createElement('div');
      left.innerHTML = `<strong>${escapeHtml(c.protocol)}://${escapeHtml(c.host)}</strong> — <code>${escapeHtml(c.username)}</code>`;
      if (c.critical) left.innerHTML += ` <span class="pill pill-critical">${t('criticalTag')}</span>`;

      const right = document.createElement('div');
      right.className = 'row-actions';
      const delBtn = document.createElement('button');
      delBtn.type = 'button';
      delBtn.className = 'btn btn-danger compact-btn';
      delBtn.textContent = t('btnDelete');
      delBtn.onclick = async () => {
        await api('/api/git/credential', { method: 'DELETE', body: { id: c.id } });
        await refreshGitTab();
      };
      right.appendChild(delBtn);
      row.append(left, right);
      list.appendChild(row);
    }
  }

  async function refreshOsEnvBackups() {
    const data = await api('/api/os-env/backups');
    state.osBackups = data.backups || {};
    const list = document.getElementById('osBackupsList');
    list.innerHTML = '';
    const entries = Object.entries(state.osBackups);
    if (entries.length === 0) {
      list.innerHTML = `<div class="muted">${t('noOsBackups')}</div>`;
      return;
    }
    for (const [k, b] of entries) {
      const row = document.createElement('div');
      row.className = 'item-row';
      const left = document.createElement('div');
      left.innerHTML = `<strong>${escapeHtml(k)}</strong> → <code>${escapeHtml(b.projectTarget)}/${escapeHtml(b.envTarget)}</code> (${escapeHtml(b.originalValue)})`;
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'btn btn-secondary compact-btn';
      btn.textContent = t('btnRestoreOsVar');
      btn.onclick = async () => {
        await api('/api/os-env/restore', { method: 'POST', body: { varName: k } });
        showToast(t('osRestoredSuccess', { key: k }));
        await refreshOsEnvBackups();
      };
      row.append(left, btn);
      list.appendChild(row);
    }
  }

  function renderOsScanTable() {
    const tbody = document.getElementById('osScanBody');
    const empty = document.getElementById('osScanEmpty');
    tbody.innerHTML = '';
    empty.classList.toggle('hidden', state.osScanItems.length > 0);
    for (const item of state.osScanItems) {
      const tr = document.createElement('tr');
      const tdChk = document.createElement('td');
      const chk = document.createElement('input');
      chk.type = 'checkbox';
      chk.className = 'os-var-chk';
      chk.value = item.name;
      chk.checked = item.suspicious;
      tdChk.appendChild(chk);

      const tdName = document.createElement('td');
      tdName.innerHTML = `<code>${escapeHtml(item.name)}</code>`;
      const tdVal = document.createElement('td');
      tdVal.innerHTML = `<code>${escapeHtml(item.maskedValue)}</code>`;
      const tdSrc = document.createElement('td');
      tdSrc.textContent = item.source;
      const tdRisk = document.createElement('td');
      tdRisk.innerHTML = item.suspicious
        ? `<span class="pill pill-critical">${t('riskSensitive')}</span>`
        : `<span class="pill pill-muted">${t('riskNormal')}</span>`;

      tr.append(tdChk, tdName, tdVal, tdSrc, tdRisk);
      tbody.appendChild(tr);
    }
  }

  async function refreshAuditAndSettings() {
    const [auditRes, setRes] = await Promise.all([api('/api/audit'), api('/api/settings')]);
    document.getElementById('vaultPathInput').value = setRes.vaultPath || '';
    document.getElementById('autoStartChk').checked = Boolean(setRes.autoStartOs);
    document.getElementById('shellHookChk').checked = Boolean(setRes.shellHookInstalled);
    const ptSel = document.getElementById('popupTimeoutSelect');
    const ptVal = String(setRes.popupTimeoutSeconds ?? 30);
    if (!Array.from(ptSel.options).some((o) => o.value === ptVal)) {
      const customOpt = document.createElement('option');
      customOpt.value = ptVal;
      customOpt.textContent = `${ptVal}s`;
      ptSel.appendChild(customOpt);
    }
    ptSel.value = ptVal;
    const revSel = document.getElementById('revealPinTtlSelect');
    const revVal = String(setRes.revealPinTtlMinutes ?? 5);
    if (!Array.from(revSel.options).some((o) => o.value === revVal)) {
      const customRevOpt = document.createElement('option');
      customRevOpt.value = revVal;
      customRevOpt.textContent = `${revVal}m`;
      revSel.appendChild(customRevOpt);
    }
    revSel.value = revVal;

    const bList = document.getElementById('backupsList');
    bList.innerHTML = '';
    const backups = setRes.backups || [];
    if (backups.length === 0) {
      bList.innerHTML = `<div class="muted">${t('noBackups')}</div>`;
    } else {
      for (const b of backups) {
        const row = document.createElement('div');
        row.className = 'item-row';
        row.innerHTML = `<code>${escapeHtml(b.filename)}</code><span class="muted">${new Date(b.createdAt).toLocaleString()} (${b.sizeBytes} B)</span>`;
        bList.appendChild(row);
      }
    }

    const tbody = document.getElementById('auditTableBody');
    tbody.innerHTML = '';
    const logs = auditRes.auditLog || [];
    if (logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" class="empty-msg">${t('noAuditLogs')}</td></tr>`;
      return;
    }
    for (const log of logs) {
      const tr = document.createElement('tr');
      const tdT = document.createElement('td');
      tdT.textContent = new Date(log.timestamp).toLocaleString();
      const tdC = document.createElement('td');
      tdC.innerHTML = `<code>${escapeHtml(log.callerCommand)}</code>`;
      if (log.isAiAgent) tdC.innerHTML += ` <span class="pill pill-ai">🤖 ${t('aiAgentTag')}</span>`;
      const tdR = document.createElement('td');
      tdR.textContent = log.resourceName || log.resourceType;
      const tdP = document.createElement('td');
      tdP.textContent = log.effectivePolicy || '';
      const tdD = document.createElement('td');
      const allowed = String(log.decision || '').includes('ALLOWED') || String(log.decision || '').includes('ENABLED');
      tdD.innerHTML = `<span class="pill ${allowed ? 'pill-ok' : 'pill-critical'}">${escapeHtml(log.decision)}</span>`;
      tr.append(tdT, tdC, tdR, tdP, tdD);
      tbody.appendChild(tr);
    }
  }

  async function loadAllData() {
    await Promise.all([
      refreshProjects(),
      refreshAwsTab(),
      refreshGitTab(),
      refreshOsEnvBackups(),
      refreshAuditAndSettings(),
    ]);
  }

  async function pollStatus() {
    try {
      const prevUnlocked = state.status?.unlocked;
      const prevRevealAuth = state.status?.revealAuthorized;
      state.status = await api('/api/status');
      renderHeaderStatus();
      if (state.status.unlocked && !prevUnlocked) {
        await loadAllData();
      } else if (prevRevealAuth && !state.status.revealAuthorized && state.revealedKeys.size > 0) {
        state.revealedKeys.clear();
        renderProjectsTab();
      }
    } catch {
      // Ignore transient poll errors
    }
  }

  function wireEvents() {
    document.getElementById('langEnBtn').onclick = async () => {
      state.lang = 'en';
      localStorage.setItem('envguard_lang', 'en');
      applyI18n();
      renderHeaderStatus();
      if (state.status?.unlocked) {
        await api('/api/settings', { method: 'POST', body: { language: 'en' } }).catch(() => {});
        await loadAllData();
      }
    };
    document.getElementById('langEsBtn').onclick = async () => {
      state.lang = 'es';
      localStorage.setItem('envguard_lang', 'es');
      applyI18n();
      renderHeaderStatus();
      if (state.status?.unlocked) {
        await api('/api/settings', { method: 'POST', body: { language: 'es' } }).catch(() => {});
        await loadAllData();
      }
    };

    document.querySelectorAll('.modal-close').forEach((btn) => {
      btn.onclick = closeAllModals;
    });

    // Turbo Dropdown
    document.getElementById('turboToggleBtn').onclick = () => {
      document.getElementById('turboMenu').classList.toggle('hidden');
    };
    document.querySelectorAll('#turboMenu .dropdown-item').forEach((btn) => {
      btn.onclick = async () => {
        const mins = Number(btn.getAttribute('data-turbo-min'));
        document.getElementById('turboMenu').classList.add('hidden');
        const res = await api('/api/turbo', { method: 'POST', body: { minutes: mins } });
        state.status = res.status;
        renderHeaderStatus();
        showToast(mins > 0 ? t('toastTurboOn', { min: mins }) : t('toastTurboOff'));
      };
    });

    // Init / Unlock / Recover / Lock
    document.getElementById('initForm').onsubmit = async (e) => {
      e.preventDefault();
      try {
        const pin = document.getElementById('initPinInput').value;
        const confirmPin = document.getElementById('initPinConfirmInput').value;
        if (pin !== confirmPin) {
          showToast(t('pinMismatchError'));
          return;
        }
        const ttlMinutes = Number(document.getElementById('initTtlSelect').value);
        const revealPinTtlMinutes = Number(document.getElementById('initRevealTtlSelect').value);
        const popupTimeoutSeconds = Number(document.getElementById('initPopupTimeoutSelect').value);
        const res = await api('/api/init', {
          method: 'POST',
          body: { pin, defaultTtlMinutes: ttlMinutes, ttlMinutes, revealPinTtlMinutes, popupTimeoutSeconds, language: state.lang },
        });
        document.getElementById('initPinInput').value = '';
        document.getElementById('initPinConfirmInput').value = '';
        document.getElementById('recoveryKeyDisplay').textContent = res.recoveryKey;
        openModal('recoveryNoticeModal');
        state.status = res.status;
        renderHeaderStatus();
        await loadAllData();
      } catch (err) {
        showToast(t('toastError', { msg: err.message }));
      }
    };

    document.getElementById('revealPinForm').onsubmit = async (e) => {
      e.preventDefault();
      try {
        const pin = document.getElementById('revealPinInput').value;
        const res = await api('/api/verify-reveal-pin', { method: 'POST', body: { pin } });
        state.status = res.status;
        const action = state.pendingRevealAction;
        state.pendingRevealAction = null;
        closeAllModals();
        if (action) await action();
      } catch (err) {
        showToast(t('toastError', { msg: err.message }));
      }
    };

    document.getElementById('topChangePinBtn').onclick = () => {
      document.querySelectorAll('.tab-btn').forEach((b) => b.classList.toggle('active', b.getAttribute('data-tab') === 'audit'));
      document.querySelectorAll('.tab-pane').forEach((p) => {
        p.classList.toggle('hidden', p.id !== 'tab-audit');
        p.classList.toggle('active', p.id === 'tab-audit');
      });
      setTimeout(() => document.getElementById('curPinInput').focus(), 40);
    };

    document.getElementById('copyRecoveryBtn').onclick = async () => {
      await navigator.clipboard.writeText(document.getElementById('recoveryKeyDisplay').textContent);
      showToast(t('toastCopied'));
    };
    document.getElementById('ackRecoveryBtn').onclick = closeAllModals;

    document.getElementById('unlockForm').onsubmit = async (e) => {
      e.preventDefault();
      try {
        const pin = document.getElementById('unlockPinInput').value;
        const ttlMinutes = Number(document.getElementById('unlockTtlSelect').value);
        const res = await api('/api/unlock', { method: 'POST', body: { pin, ttlMinutes } });
        document.getElementById('unlockPinInput').value = '';
        state.status = res.status;
        renderHeaderStatus();
        showToast(t('toastUnlocked'));
        await loadAllData();
      } catch (err) {
        showToast(t('toastError', { msg: err.message }));
      }
    };

    document.getElementById('showRecoverBtn').onclick = () => {
      document.getElementById('unlockForm').classList.add('hidden');
      document.getElementById('recoverForm').classList.remove('hidden');
    };
    document.getElementById('cancelRecoverBtn').onclick = () => {
      document.getElementById('recoverForm').classList.add('hidden');
      document.getElementById('unlockForm').classList.remove('hidden');
    };
    document.getElementById('recoverForm').onsubmit = async (e) => {
      e.preventDefault();
      try {
        const recoveryKey = document.getElementById('recoverKeyInput').value;
        const newPin = document.getElementById('recoverNewPinInput').value;
        const res = await api('/api/recover', { method: 'POST', body: { recoveryKey, newPin } });
        state.status = res.status;
        renderHeaderStatus();
        showToast(t('toastUnlocked'));
        await loadAllData();
      } catch (err) {
        showToast(t('toastError', { msg: err.message }));
      }
    };

    document.getElementById('lockBtn').onclick = async () => {
      const res = await api('/api/lock', { method: 'POST' });
      state.status = res.status;
      state.revealedKeys.clear();
      renderHeaderStatus();
      showToast(t('toastLocked'));
    };

    document.getElementById('sessionTtlSelect').onchange = async (e) => {
      const res = await api('/api/session/ttl', { method: 'POST', body: { ttlMinutes: Number(e.target.value) } });
      state.status = res.status;
      renderHeaderStatus();
      showToast(t('toastSaved'));
    };

    // Tabs
    document.querySelectorAll('.tab-btn').forEach((btn) => {
      btn.onclick = () => {
        const target = btn.getAttribute('data-tab');
        document.querySelectorAll('.tab-btn').forEach((b) => b.classList.toggle('active', b === btn));
        document.querySelectorAll('.tab-pane').forEach((p) => {
          p.classList.toggle('hidden', p.id !== `tab-${target}`);
          p.classList.toggle('active', p.id === `tab-${target}`);
        });
      };
    });

    // Projects
    document.getElementById('projectSelect').onchange = (e) => {
      state.selectedProject = e.target.value;
      state.selectedEnv = '';
      renderProjectsTab();
    };
    document.getElementById('envSelect').onchange = (e) => {
      state.selectedEnv = e.target.value;
      renderProjectsTab();
    };
    document.getElementById('saveEnvPolicyBtn').onclick = async () => {
      await api('/api/projects/env-policy', {
        method: 'POST',
        body: {
          project: state.selectedProject,
          env: state.selectedEnv,
          policy: document.getElementById('envPolicySelect').value,
          critical: document.getElementById('envCriticalChk').checked,
        },
      });
      showToast(t('toastSaved'));
      await refreshProjects();
    };

    document.getElementById('newProjectBtn').onclick = () => {
      document.getElementById('npProjectInput').value = '';
      document.getElementById('npEnvInput').value = 'dev';
      openModal('newProjectModal');
    };
    document.getElementById('newEnvBtn').onclick = () => {
      document.getElementById('npProjectInput').value = state.selectedProject || '';
      document.getElementById('npEnvInput').value = 'prod';
      openModal('newProjectModal');
    };
    document.getElementById('newProjectForm').onsubmit = async (e) => {
      e.preventDefault();
      const project = document.getElementById('npProjectInput').value.trim();
      const env = document.getElementById('npEnvInput').value.trim();
      await api('/api/projects/create', { method: 'POST', body: { project, env } });
      state.selectedProject = project;
      state.selectedEnv = env;
      closeAllModals();
      showToast(t('toastSaved'));
      await refreshProjects();
    };

    document.getElementById('addVarBtn').onclick = () => openVarModal('', null);
    document.getElementById('varForm').onsubmit = async (e) => {
      e.preventDefault();
      await api('/api/projects/var', {
        method: 'POST',
        body: {
          project: state.selectedProject,
          env: state.selectedEnv,
          key: document.getElementById('varKeyInput').value.trim(),
          value: document.getElementById('varValInput').value,
          policy: document.getElementById('varPolicySelect').value,
          critical: document.getElementById('varCriticalChk').checked,
          description: document.getElementById('varDescInput').value,
        },
      });
      closeAllModals();
      showToast(t('toastSaved'));
      await refreshProjects();
    };

    document.getElementById('linkDirBtn').onclick = async () => {
      const dirPath = document.getElementById('linkDirInput').value.trim();
      if (!dirPath || !state.selectedProject || !state.selectedEnv) return;
      await api('/api/links', { method: 'POST', body: { dirPath, project: state.selectedProject, env: state.selectedEnv } });
      document.getElementById('linkDirInput').value = '';
      showToast(t('toastSaved'));
      await refreshProjects();
    };

    // Import Diff
    document.getElementById('openImportBtn').onclick = () => {
      state.pendingDiff = null;
      document.getElementById('importRawText').value = '';
      document.getElementById('importPassInput').value = '';
      document.getElementById('importDiffResult').classList.add('hidden');
      document.getElementById('applyImportBtn').classList.add('hidden');
      openModal('importModal');
    };
    document.getElementById('importFileInput').onchange = async (e) => {
      const file = e.target.files?.[0];
      if (!file) return;
      document.getElementById('importRawText').value = await file.text();
    };
    document.getElementById('previewDiffBtn').onclick = async () => {
      try {
        const res = await api('/api/import-diff', {
          method: 'POST',
          body: {
            project: state.selectedProject,
            env: state.selectedEnv,
            rawContent: document.getElementById('importRawText').value,
            transferPassword: document.getElementById('importPassInput').value,
          },
        });
        state.pendingDiff = res;
        const box = document.getElementById('importDiffResult');
        const { added, modified, unchanged } = res.diff;
        box.innerHTML = [
          `<div class="diff-added"><strong>${t('diffAdded', { count: added.length })}</strong>: ${added.map((a) => escapeHtml(a.key)).join(', ')}</div>`,
          `<div class="diff-modified"><strong>${t('diffModified', { count: modified.length })}</strong>: ${modified.map((m) => escapeHtml(m.key)).join(', ')}</div>`,
          `<div class="diff-unchanged"><strong>${t('diffUnchanged', { count: unchanged.length })}</strong></div>`,
        ].join('');
        box.classList.remove('hidden');
        document.getElementById('applyImportBtn').classList.remove('hidden');
      } catch (err) {
        showToast(t('toastError', { msg: err.message }));
      }
    };
    document.getElementById('applyImportBtn').onclick = async () => {
      if (!state.pendingDiff) return;
      await api('/api/import-apply', {
        method: 'POST',
        body: {
          project: state.selectedProject,
          env: state.selectedEnv,
          incomingMap: state.pendingDiff.incomingMap,
          mode: document.getElementById('importModeSelect').value,
        },
      });
      closeAllModals();
      showToast(t('toastSaved'));
      await refreshProjects();
    };

    // Export / Share
    document.getElementById('openExportBtn').onclick = () => {
      const vars = state.projects[state.selectedProject]?.environments?.[state.selectedEnv]?.vars || {};
      const grid = document.getElementById('exportKeyCheckboxes');
      grid.innerHTML = '';
      for (const k of Object.keys(vars)) {
        const lbl = document.createElement('label');
        lbl.className = 'checkbox-label';
        const chk = document.createElement('input');
        chk.type = 'checkbox';
        chk.className = 'export-key-chk';
        chk.value = k;
        chk.checked = true;
        lbl.append(chk, document.createTextNode(k));
        grid.appendChild(lbl);
      }
      const fmt = document.getElementById('exportFormatSelect').value;
      document.getElementById('exportPassField').classList.toggle('hidden', fmt !== 'html' && fmt !== 'vltpack');
      openModal('exportModal');
    };
    document.getElementById('exportFormatSelect').onchange = (e) => {
      const fmt = e.target.value;
      document.getElementById('exportPassField').classList.toggle('hidden', fmt !== 'html' && fmt !== 'vltpack');
    };
    document.getElementById('exportAllKeysBtn').onclick = () => {
      document.querySelectorAll('.export-key-chk').forEach((c) => { c.checked = true; });
    };
    document.getElementById('exportNoKeysBtn').onclick = () => {
      document.querySelectorAll('.export-key-chk').forEach((c) => { c.checked = false; });
    };
    document.getElementById('downloadExportBtn').onclick = async () => {
      try {
        const format = document.getElementById('exportFormatSelect').value;
        const transferPassword = document.getElementById('exportPassInput').value;
        if ((format === 'html' || format === 'vltpack') && transferPassword.length < 4) {
          showToast(t('confirmPasswordError'));
          return;
        }
        const keys = Array.from(document.querySelectorAll('.export-key-chk:checked')).map((c) => c.value);
        const res = await api('/api/export', {
          method: 'POST',
          body: { project: state.selectedProject, env: state.selectedEnv, format, keys, transferPassword },
        });
        const blob = new Blob([res.content], { type: res.mime || 'text/plain' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = res.filename;
        a.click();
        closeAllModals();
        showToast(t('toastSaved'));
      } catch (err) {
        showToast(t('toastError', { msg: err.message }));
      }
    };

    // AWS
    document.getElementById('scanAwsBtn').onclick = async () => {
      state.awsDiskScan = await api('/api/aws/scan');
      renderAwsTab();
    };
    document.getElementById('importSelectedAwsBtn').onclick = async () => {
      const profiles = Array.from(document.querySelectorAll('.aws-scan-chk:checked')).map((c) => c.value);
      const res = await api('/api/aws/import-disk', { method: 'POST', body: { profiles } });
      showToast(t('awsImportSuccess', { count: res.imported.length }));
      await refreshAwsTab();
    };
    document.getElementById('addAwsBtn').onclick = () => openModal('awsModal');
    document.getElementById('awsForm').onsubmit = async (e) => {
      e.preventDefault();
      await api('/api/aws/profile', {
        method: 'POST',
        body: {
          name: document.getElementById('awsNameInput').value.trim(),
          accessKeyId: document.getElementById('awsKeyInput').value.trim(),
          secretAccessKey: document.getElementById('awsSecretInput').value.trim(),
          sessionToken: document.getElementById('awsTokenInput').value.trim(),
          region: document.getElementById('awsRegionInput').value.trim(),
          policy: document.getElementById('awsPolicySelect').value,
          critical: document.getElementById('awsCriticalChk').checked,
        },
      });
      closeAllModals();
      showToast(t('toastSaved'));
      await refreshAwsTab();
    };

    // Git
    document.getElementById('addGitBtn').onclick = () => openModal('gitModal');
    document.getElementById('gitForm').onsubmit = async (e) => {
      e.preventDefault();
      await api('/api/git/credential', {
        method: 'POST',
        body: {
          host: document.getElementById('gitHostInput').value.trim(),
          username: document.getElementById('gitUserInput').value.trim(),
          token: document.getElementById('gitTokenInput').value.trim(),
          protocol: document.getElementById('gitProtoSelect').value,
          policy: document.getElementById('gitPolicySelect').value,
          critical: document.getElementById('gitCriticalChk').checked,
        },
      });
      closeAllModals();
      showToast(t('toastSaved'));
      await refreshGitTab();
    };
    document.getElementById('toggleGitHelperBtn').onclick = async () => {
      const enable = !state.gitHelperStatus?.usesEnvGuard;
      await api('/api/git/helper', { method: 'POST', body: { enable } });
      showToast(t('toastSaved'));
      await refreshGitTab();
    };

    // OS Env Cleaner
    document.getElementById('scanOsBtn').onclick = async () => {
      const res = await api('/api/os-env/scan');
      state.osScanItems = res.items || [];
      renderOsScanTable();
    };
    document.getElementById('migrateOsBtn').onclick = async () => {
      const varNames = Array.from(document.querySelectorAll('.os-var-chk:checked')).map((c) => c.value);
      if (varNames.length === 0) return;
      const res = await api('/api/os-env/migrate', {
        method: 'POST',
        body: {
          varNames,
          project: document.getElementById('osTargetProject').value.trim(),
          env: document.getElementById('osTargetEnv').value.trim(),
          removeFromOs: document.getElementById('osRemoveChk').checked,
        },
      });
      showToast(t('osMigratedSuccess', { count: res.migrated.length }));
      await Promise.all([refreshProjects(), refreshOsEnvBackups()]);
      const scanRes = await api('/api/os-env/scan');
      state.osScanItems = scanRes.items || [];
      renderOsScanTable();
    };

    // Audit & Settings
    document.getElementById('refreshAuditBtn').onclick = refreshAuditAndSettings;
    document.getElementById('saveVaultPathBtn').onclick = async () => {
      await api('/api/settings', { method: 'POST', body: { vaultPath: document.getElementById('vaultPathInput').value.trim() } });
      showToast(t('vaultPathUpdated'));
      await refreshAuditAndSettings();
    };
    document.getElementById('saveAutoStartBtn').onclick = async () => {
      await api('/api/settings', { method: 'POST', body: { autoStartOs: document.getElementById('autoStartChk').checked } });
      showToast(t('autoStartUpdated'));
    };
    document.getElementById('saveShellHookBtn').onclick = async () => {
      await api('/api/settings', { method: 'POST', body: { shellAutoHook: document.getElementById('shellHookChk').checked } });
      showToast(t('shellHookUpdated'));
    };
    document.getElementById('copySpringUrlBtn').onclick = async () => {
      const txt = document.getElementById('springUrlCode').textContent;
      if (!txt) return;
      await navigator.clipboard.writeText(txt);
      showToast(t('toastCopied'));
    };
    document.getElementById('copyDirectUrlBtn').onclick = async () => {
      const txt = document.getElementById('directJsonUrlCode').textContent;
      if (!txt) return;
      await navigator.clipboard.writeText(txt);
      showToast(t('toastCopied'));
    };
    document.getElementById('savePopupTimeoutBtn').onclick = async () => {
      await api('/api/settings', { method: 'POST', body: { popupTimeoutSeconds: Number(document.getElementById('popupTimeoutSelect').value) } });
      showToast(t('popupTimeoutUpdated'));
      await pollStatus();
    };
    document.getElementById('saveRevealTtlBtn').onclick = async () => {
      await api('/api/settings', { method: 'POST', body: { revealPinTtlMinutes: Number(document.getElementById('revealPinTtlSelect').value) } });
      showToast(t('revealPolicyUpdated'));
      await pollStatus();
    };
    document.getElementById('resetVaultBtn').onclick = async () => {
      if (!confirm(t('confirmResetVault'))) return;
      const res = await api('/api/reset-vault', { method: 'POST', body: {} });
      state.status = res.status;
      state.revealedKeys.clear();
      renderHeaderStatus();
      showToast(t('vaultResetSuccess'));
    };
    document.getElementById('changePinForm').onsubmit = async (e) => {
      e.preventDefault();
      try {
        await api('/api/change-pin', {
          method: 'POST',
          body: {
            currentPin: document.getElementById('curPinInput').value,
            newPin: document.getElementById('newPinInput').value,
          },
        });
        document.getElementById('curPinInput').value = '';
        document.getElementById('newPinInput').value = '';
        showToast(t('pinChangedSuccess'));
      } catch (err) {
        showToast(t('toastError', { msg: err.message }));
      }
    };
    document.getElementById('downloadVaultBtn').onclick = () => {
      window.location.href = '/api/vault/download-backup';
    };
  }

  async function initWindowBoundsSync() {
    let lastNormalBounds = null;
    let lastSentJson = '';
    try {
      const res = await api('/api/window-bounds');
      const saved = res.windowBounds;
      if (saved && typeof saved === 'object') {
        lastNormalBounds = { x: saved.x, y: saved.y, width: saved.width, height: saved.height };
        if (!saved.maximized && Number.isFinite(saved.width) && Number.isFinite(saved.height)) {
          try {
            window.resizeTo(saved.width, saved.height);
            window.moveTo(saved.x, saved.y);
          } catch { /* ignore if blocked by browser */ }
        }
      }
    } catch { /* ignore */ }

    const captureBounds = () => {
      const isMax = window.outerWidth >= window.screen.availWidth - 8 && window.outerHeight >= window.screen.availHeight - 8;
      if (!isMax && window.outerWidth >= 320 && window.outerHeight >= 240) {
        lastNormalBounds = {
          x: Math.round(window.screenX),
          y: Math.round(window.screenY),
          width: Math.round(window.outerWidth),
          height: Math.round(window.outerHeight),
        };
      }
      const base = lastNormalBounds || {
        x: Math.round(window.screenX),
        y: Math.round(window.screenY),
        width: Math.max(400, Math.round(window.outerWidth || 1240)),
        height: Math.max(300, Math.round(window.outerHeight || 840)),
      };
      return { ...base, maximized: isMax };
    };

    const syncBounds = (useBeacon = false) => {
      const payload = captureBounds();
      const json = JSON.stringify(payload);
      if (json === lastSentJson) return;
      lastSentJson = json;
      if (useBeacon && navigator.sendBeacon) {
        navigator.sendBeacon('/api/window-bounds', new Blob([json], { type: 'application/json' }));
        return;
      }
      api('/api/window-bounds', { method: 'POST', body: payload }).catch(() => {});
    };

    setTimeout(() => {
      window.addEventListener('resize', () => syncBounds(false));
      window.addEventListener('beforeunload', () => syncBounds(true));
      setInterval(() => syncBounds(false), 1500);
    }, 500);
  }

  async function boot() {
    const [en, es] = await Promise.all([
      api('/locales/en.json'),
      api('/locales/es.json'),
    ]);
    state.locales.en = en;
    state.locales.es = es;
    applyI18n();
    wireEvents();
    initWindowBoundsSync();
    await pollStatus();
    if (state.status?.language && !localStorage.getItem('envguard_lang')) {
      state.lang = state.status.language;
      applyI18n();
    }
    setInterval(pollStatus, 5000);
  }

  boot();
})();
