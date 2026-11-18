'use strict';

const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { ensureIconFile } = require('../src/desktop-shell');
const { ensureDirSync } = require('../src/crypto-vault');

const ROOT = path.resolve(__dirname, '..');
const DIST_DIR = path.join(ROOT, 'dist');
const DOWNLOADS_DIR = path.join(os.homedir(), 'Downloads');
const CSC_PATH = 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe';

function buildPopupExeSource() {
  return `using System;
using System.Collections;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace EnvGuardNative {
  public class PopupForm : Form {
    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    private TextBox pinInput;
    private ComboBox ttlCombo;
    private CheckBox turboChk;
    private Button btnCancel;
    private Timer countdownTimer;
    private int remainingSeconds;
    private bool timedOut = false;
    private List<int> ttlMinutesList = new List<int>();
    private string cancelBaseText = "Cancel";
    private int? lastX = null;
    private int? lastY = null;
    private bool approvedResult = false;
    private string pinResult = null;
    private int chosenTtl = 240;
    private int turboMinutesResult = 0;

    public PopupForm(Dictionary<string, object> ctx) {
      Dictionary<string, object> loc = ctx["loc"] as Dictionary<string, object>;
      string windowTitle = GetStr(loc, "windowTitle", "EnvGuard — Authorization");
      string bannerText = GetStr(ctx, "bannerText", "CONFIRMATION REQUIRED");
      bool needPin = GetBool(ctx, "needPin");
      bool isCritical = GetBool(ctx, "isCritical");
      string effectivePolicy = GetStr(ctx, "effectivePolicy", "confirm");
      bool isAiAgent = GetBool(ctx, "isAiAgent");
      bool isSuspicious = GetBool(ctx, "isSuspiciousCommand");
      bool showTurbo = GetBool(ctx, "showTurboOption");
      string resourceLabel = GetStr(ctx, "resourceLabel", "");
      string callerCommand = GetStr(ctx, "callerCommand", "");
      string processChain = GetStr(ctx, "processChain", "");
      string cwd = GetStr(ctx, "cwd", "");
      string criticalKeysText = GetStr(ctx, "criticalKeysText", "");
      int defaultTtl = GetInt(ctx, "defaultTtlMinutes", 240);
      remainingSeconds = GetInt(ctx, "timeoutSeconds", 30);
      cancelBaseText = GetStr(loc, "btnCancel", "Cancel");

      this.Text = windowTitle;
      this.StartPosition = FormStartPosition.CenterScreen;
      this.FormBorderStyle = FormBorderStyle.FixedDialog;
      this.MaximizeBox = false;
      this.MinimizeBox = false;
      this.TopMost = true;
      this.ShowInTaskbar = true;
      this.BackColor = ColorTranslator.FromHtml("#0f172a");
      this.ForeColor = ColorTranslator.FromHtml("#f8fafc");
      this.Font = new Font("Segoe UI", 9.5f);

      if (ctx.ContainsKey("popupX") && ctx["popupX"] != null && ctx.ContainsKey("popupY") && ctx["popupY"] != null) {
        int px = Convert.ToInt32(ctx["popupX"]);
        int py = Convert.ToInt32(ctx["popupY"]);
        Rectangle vs = SystemInformation.VirtualScreen;
        if (px >= vs.Left - 100 && px <= vs.Right - 100 && py >= vs.Top && py <= vs.Bottom - 80) {
          this.StartPosition = FormStartPosition.Manual;
          this.Location = new Point(px, py);
        }
      }

      string bannerColor = "#2563eb";
      if (isCritical || effectivePolicy == "pin_confirm") bannerColor = "#dc2626";
      else if (isAiAgent || isSuspicious) bannerColor = "#d97706";

      Panel banner = new Panel();
      banner.SetBounds(0, 0, 560, 46);
      banner.BackColor = ColorTranslator.FromHtml(bannerColor);
      this.Controls.Add(banner);

      Label badgeLbl = new Label();
      badgeLbl.Text = bannerText;
      badgeLbl.SetBounds(16, 11, 528, 24);
      badgeLbl.Font = new Font("Segoe UI", 10f, FontStyle.Bold);
      badgeLbl.ForeColor = Color.White;
      banner.Controls.Add(badgeLbl);

      int y = 60;
      AddInfoRow(GetStr(loc, "lblResource", "Resource:"), resourceLabel, "#f8fafc", ref y);
      AddInfoRow(GetStr(loc, "lblCommand", "Command:"), callerCommand, "#93c5fd", ref y);
      AddInfoRow(GetStr(loc, "lblChain", "Process chain:"), processChain, "#cbd5e1", ref y);
      AddInfoRow(GetStr(loc, "lblCwd", "Directory:"), cwd, "#cbd5e1", ref y);
      if (!string.IsNullOrEmpty(criticalKeysText)) {
        AddInfoRow(GetStr(loc, "lblCriticalKeys", "Critical keys:"), criticalKeysText, "#fca5a5", ref y);
      }

      if (needPin) {
        Label pinLbl = new Label();
        pinLbl.Text = GetStr(loc, "lblPin", "Master PIN:");
        pinLbl.SetBounds(18, y + 4, 145, 22);
        pinLbl.ForeColor = ColorTranslator.FromHtml("#f8fafc");
        pinLbl.Font = new Font("Segoe UI", 9.5f, FontStyle.Bold);
        this.Controls.Add(pinLbl);

        pinInput = new TextBox();
        pinInput.SetBounds(168, y, 370, 26);
        pinInput.UseSystemPasswordChar = true;
        pinInput.BackColor = ColorTranslator.FromHtml("#1e293b");
        pinInput.ForeColor = Color.White;
        pinInput.BorderStyle = BorderStyle.FixedSingle;
        this.Controls.Add(pinInput);
        y += 38;
      }

      Label ttlLbl = new Label();
      ttlLbl.Text = GetStr(loc, "lblTtl", "Session duration:");
      ttlLbl.SetBounds(18, y + 4, 190, 22);
      ttlLbl.ForeColor = ColorTranslator.FromHtml("#94a3b8");
      this.Controls.Add(ttlLbl);

      ttlCombo = new ComboBox();
      ttlCombo.SetBounds(212, y, 326, 26);
      ttlCombo.DropDownStyle = ComboBoxStyle.DropDownList;
      ttlCombo.BackColor = ColorTranslator.FromHtml("#1e293b");
      ttlCombo.ForeColor = Color.White;
      int selectedIdx = 0;
      ArrayList opts = loc != null && loc.ContainsKey("ttlOptions") ? (loc["ttlOptions"] as ArrayList) : null;
      if (opts != null) {
        for (int i = 0; i < opts.Count; i++) {
          Dictionary<string, object> o = opts[i] as Dictionary<string, object>;
          string lbl = GetStr(o, "label", "4h");
          int mins = GetInt(o, "minutes", 240);
          ttlCombo.Items.Add(lbl);
          ttlMinutesList.Add(mins);
          if (mins == defaultTtl) selectedIdx = i;
        }
      }
      if (ttlCombo.Items.Count > 0) ttlCombo.SelectedIndex = selectedIdx;
      this.Controls.Add(ttlCombo);
      y += 38;

      if (showTurbo) {
        turboChk = new CheckBox();
        turboChk.Text = GetStr(loc, "chkTurbo", "Enable AI Turbo Mode (30m)");
        turboChk.SetBounds(18, y, 520, 24);
        turboChk.ForeColor = ColorTranslator.FromHtml("#fcd34d");
        this.Controls.Add(turboChk);
        y += 34;
      }

      this.ClientSize = new Size(560, y + 58);

      btnCancel = new Button();
      btnCancel.Text = remainingSeconds > 0 ? string.Format("{0} ({1}s)", cancelBaseText, remainingSeconds) : cancelBaseText;
      btnCancel.SetBounds(255, y + 10, 138, 34);
      btnCancel.FlatStyle = FlatStyle.Flat;
      btnCancel.BackColor = ColorTranslator.FromHtml("#334155");
      btnCancel.ForeColor = Color.White;
      btnCancel.DialogResult = DialogResult.Cancel;
      this.Controls.Add(btnCancel);

      Button btnOk = new Button();
      btnOk.Text = GetStr(loc, "btnConfirm", "Confirm & Allow");
      btnOk.SetBounds(403, y + 10, 140, 34);
      btnOk.FlatStyle = FlatStyle.Flat;
      btnOk.BackColor = ColorTranslator.FromHtml((isCritical || effectivePolicy == "pin_confirm") ? "#dc2626" : "#2563eb");
      btnOk.ForeColor = Color.White;
      btnOk.DialogResult = DialogResult.OK;
      this.Controls.Add(btnOk);

      this.AcceptButton = btnOk;
      this.CancelButton = btnCancel;

      if (remainingSeconds > 0) {
        countdownTimer = new Timer();
        countdownTimer.Interval = 1000;
        countdownTimer.Tick += delegate {
          remainingSeconds--;
          if (remainingSeconds <= 0) {
            timedOut = true;
            countdownTimer.Stop();
            this.DialogResult = DialogResult.Cancel;
            this.Close();
          } else {
            btnCancel.Text = string.Format("{0} ({1}s)", cancelBaseText, remainingSeconds);
          }
        };
      }

      this.Shown += delegate {
        ShowWindow(this.Handle, 5);
        this.TopMost = true;
        this.BringToFront();
        this.Activate();
        SetForegroundWindow(this.Handle);
        if (pinInput != null) pinInput.Focus();
        if (countdownTimer != null) countdownTimer.Start();
      };

      this.FormClosing += delegate {
        lastX = this.Location.X;
        lastY = this.Location.Y;
        approvedResult = (this.DialogResult == DialogResult.OK);
        pinResult = pinInput != null ? pinInput.Text : null;
        if (ttlCombo != null && ttlCombo.SelectedIndex >= 0 && ttlCombo.SelectedIndex < ttlMinutesList.Count) {
          chosenTtl = ttlMinutesList[ttlCombo.SelectedIndex];
        }
        turboMinutesResult = (turboChk != null && turboChk.Checked) ? 30 : 0;
        if (countdownTimer != null) {
          countdownTimer.Stop();
          countdownTimer.Dispose();
        }
      };
    }

    private void AddInfoRow(string label, string val, string colorHex, ref int y) {
      Label lbl = new Label();
      lbl.Text = label;
      lbl.SetBounds(18, y, 145, 20);
      lbl.ForeColor = ColorTranslator.FromHtml("#94a3b8");
      this.Controls.Add(lbl);

      Label valBox = new Label();
      valBox.Text = val;
      valBox.SetBounds(168, y, 372, 34);
      valBox.ForeColor = ColorTranslator.FromHtml(colorHex);
      this.Controls.Add(valBox);
      y += 36;
    }

    public Dictionary<string, object> BuildOutput() {
      Dictionary<string, object> res = new Dictionary<string, object>();
      res["approved"] = approvedResult;
      res["timedOut"] = timedOut;
      res["pin"] = pinResult;
      res["ttlMinutes"] = chosenTtl;
      res["enableTurboMinutes"] = turboMinutesResult;
      res["popupX"] = lastX;
      res["popupY"] = lastY;
      return res;
    }

    private static string GetStr(Dictionary<string, object> dict, string key, string fallback) {
      if (dict != null && dict.ContainsKey(key) && dict[key] != null) return dict[key].ToString();
      return fallback;
    }

    private static bool GetBool(Dictionary<string, object> dict, string key) {
      if (dict != null && dict.ContainsKey(key) && dict[key] != null) return Convert.ToBoolean(dict[key]);
      return false;
    }

    private static int GetInt(Dictionary<string, object> dict, string key, int fallback) {
      if (dict != null && dict.ContainsKey(key) && dict[key] != null) return Convert.ToInt32(dict[key]);
      return fallback;
    }

    [STAThread]
    public static void Main(string[] args) {
      Application.EnableVisualStyles();
      Application.SetCompatibleTextRenderingDefault(false);
      string jsonInput = null;
      string outFile = args.Length > 1 ? args[1] : null;
      if (args.Length > 0 && File.Exists(args[0])) {
        jsonInput = File.ReadAllText(args[0], Encoding.UTF8);
      } else {
        jsonInput = Environment.GetEnvironmentVariable("ENVGUARD_POPUP_CTX");
      }
      if (string.IsNullOrEmpty(jsonInput)) {
        Environment.Exit(1);
        return;
      }
      JavaScriptSerializer ser = new JavaScriptSerializer();
      Dictionary<string, object> ctx = ser.Deserialize<Dictionary<string, object>>(jsonInput);
      PopupForm form = new PopupForm(ctx);
      form.ShowDialog();
      string outJson = ser.Serialize(form.BuildOutput());
      if (!string.IsNullOrEmpty(outFile)) {
        File.WriteAllText(outFile, outJson, new UTF8Encoding(false));
      } else {
        Console.WriteLine(outJson);
      }
    }
  }
}
`;
}

function buildLauncherExeSource() {
  return `using System;
using System.Diagnostics;
using System.IO;
using System.Windows.Forms;

namespace EnvGuardApp {
  public class Program {
    private static string FindNodeExe() {
      string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
      string pfx86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
      string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
      string[] candidates = new string[] {
        Path.Combine(pf, "nodejs", "node.exe"),
        Path.Combine(pfx86, "nodejs", "node.exe"),
        Path.Combine(local, "Programs", "nodejs", "node.exe")
      };
      foreach (string c in candidates) {
        if (!string.IsNullOrEmpty(c) && File.Exists(c)) return c;
      }
      return "node.exe";
    }

    private static string FindVltJs() {
      string baseDir = AppDomain.CurrentDomain.BaseDirectory;
      string[] candidates = new string[] {
        Path.GetFullPath(Path.Combine(baseDir, "..\\\\bin\\\\vlt.js")),
        Path.GetFullPath(Path.Combine(baseDir, "bin\\\\vlt.js")),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "EnvGuard", "bin", "vlt.js")
      };
      foreach (string c in candidates) {
        if (File.Exists(c)) return c;
      }
      return candidates[0];
    }

    [STAThread]
    public static void Main(string[] args) {
      string nodeExe = FindNodeExe();
      string vltJs = FindVltJs();
      if (!File.Exists(vltJs)) {
        MessageBox.Show("EnvGuard runtime not found at: " + vltJs, "EnvGuard", MessageBoxButtons.OK, MessageBoxIcon.Error);
        return;
      }
      string subCmd = args.Length > 0 ? string.Join(" ", args) : "ui";
      ProcessStartInfo psi = new ProcessStartInfo();
      psi.FileName = nodeExe;
      psi.Arguments = "\\"" + vltJs + "\\" " + subCmd;
      psi.WorkingDirectory = Path.GetDirectoryName(Path.GetDirectoryName(vltJs));
      psi.UseShellExecute = false;
      psi.CreateNoWindow = true;
      psi.WindowStyle = ProcessWindowStyle.Hidden;
      Process.Start(psi);
    }
  }
}
`;
}

function buildSetupExeSource() {
  return `using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Windows.Forms;

namespace EnvGuardSetup {
  public class SetupForm : Form {
    private TextBox dirBox;
    private CheckBox chkShortcuts;
    private CheckBox chkShellHook;
    private CheckBox chkAutoStart;
    private CheckBox chkFreshReset;
    private CheckBox chkSpanish;
    private Label lblTitle;
    private Label lblDesc;
    private Label lblDir;
    private Button btnInstall;
    private Button btnCancel;

    public SetupForm() {
      this.Text = "EnvGuard Installer";
      this.ClientSize = new Size(540, 385);
      this.StartPosition = FormStartPosition.CenterScreen;
      this.FormBorderStyle = FormBorderStyle.FixedDialog;
      this.MaximizeBox = false;
      this.BackColor = ColorTranslator.FromHtml("#0f172a");
      this.ForeColor = ColorTranslator.FromHtml("#f8fafc");
      this.Font = new Font("Segoe UI", 9.5f);

      lblTitle = new Label();
      lblTitle.SetBounds(20, 18, 500, 28);
      lblTitle.Font = new Font("Segoe UI", 13f, FontStyle.Bold);
      this.Controls.Add(lblTitle);

      lblDesc = new Label();
      lblDesc.SetBounds(20, 50, 500, 38);
      lblDesc.ForeColor = ColorTranslator.FromHtml("#94a3b8");
      this.Controls.Add(lblDesc);

      lblDir = new Label();
      lblDir.SetBounds(20, 96, 500, 20);
      lblDir.ForeColor = ColorTranslator.FromHtml("#cbd5e1");
      this.Controls.Add(lblDir);

      dirBox = new TextBox();
      dirBox.SetBounds(20, 118, 500, 26);
      dirBox.Text = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "EnvGuard");
      dirBox.BackColor = ColorTranslator.FromHtml("#1e293b");
      dirBox.ForeColor = Color.White;
      dirBox.BorderStyle = BorderStyle.FixedSingle;
      this.Controls.Add(dirBox);

      chkShortcuts = new CheckBox();
      chkShortcuts.SetBounds(20, 158, 500, 24);
      chkShortcuts.Checked = true;
      this.Controls.Add(chkShortcuts);

      chkShellHook = new CheckBox();
      chkShellHook.SetBounds(20, 186, 500, 24);
      chkShellHook.Checked = true;
      this.Controls.Add(chkShellHook);

      chkAutoStart = new CheckBox();
      chkAutoStart.SetBounds(20, 214, 500, 24);
      chkAutoStart.Checked = false;
      this.Controls.Add(chkAutoStart);

      chkFreshReset = new CheckBox();
      chkFreshReset.SetBounds(20, 242, 500, 24);
      chkFreshReset.Checked = false;
      this.Controls.Add(chkFreshReset);

      chkSpanish = new CheckBox();
      chkSpanish.SetBounds(20, 276, 200, 24);
      chkSpanish.Text = "Español (ES)";
      chkSpanish.Checked = System.Globalization.CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "es";
      chkSpanish.CheckedChanged += delegate { ApplyLanguage(); };
      this.Controls.Add(chkSpanish);

      btnCancel = new Button();
      btnCancel.SetBounds(260, 326, 110, 36);
      btnCancel.FlatStyle = FlatStyle.Flat;
      btnCancel.BackColor = ColorTranslator.FromHtml("#334155");
      btnCancel.ForeColor = Color.White;
      btnCancel.Click += delegate { this.Close(); };
      this.Controls.Add(btnCancel);

      btnInstall = new Button();
      btnInstall.SetBounds(380, 326, 140, 36);
      btnInstall.FlatStyle = FlatStyle.Flat;
      btnInstall.BackColor = ColorTranslator.FromHtml("#2563eb");
      btnInstall.ForeColor = Color.White;
      btnInstall.Click += delegate { RunInstall(); };
      this.Controls.Add(btnInstall);

      ApplyLanguage();
    }

    private void ApplyLanguage() {
      bool es = chkSpanish.Checked;
      this.Text = es ? "Instalador de EnvGuard" : "EnvGuard Installer";
      lblTitle.Text = es ? "Instalar EnvGuard" : "Install EnvGuard";
      lblDesc.Text = es
        ? "Extrae la app, configura el CLI 'vlt', accesos directos y abre la pantalla inicial para definir tu PIN y políticas."
        : "Extracts EnvGuard, configures the 'vlt' CLI and shortcuts, and opens First-Run Setup to configure your PIN.";
      lblDir.Text = es ? "Carpeta de instalación:" : "Install Directory:";
      chkShortcuts.Text = es ? "Crear accesos directos en Escritorio y Menú Inicio" : "Create Desktop & Start Menu shortcuts";
      chkShellHook.Text = es ? "Activar hook automático en consola (Java / Maven / Node / Python)" : "Enable automatic terminal hook (Java / Maven / Node / Python)";
      chkAutoStart.Text = es ? "Iniciar EnvGuard automáticamente al prender Windows" : "Start EnvGuard automatically with Windows";
      chkFreshReset.Text = es ? "Iniciar configuración desde cero (pedir nuevo PIN inicial)" : "Start fresh First-Run PIN Setup (backup & reset existing vault)";
      btnCancel.Text = es ? "Cancelar" : "Cancel";
      btnInstall.Text = es ? "Instalar y Abrir" : "Install & Launch";
    }

    private static string FindNodeExe() {
      string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
      string pfx86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
      string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
      string[] candidates = new string[] {
        Path.Combine(pf, "nodejs", "node.exe"),
        Path.Combine(pfx86, "nodejs", "node.exe"),
        Path.Combine(local, "Programs", "nodejs", "node.exe")
      };
      foreach (string c in candidates) {
        if (!string.IsNullOrEmpty(c) && File.Exists(c)) return c;
      }
      return "node.exe";
    }

    private static void ExtractEmbeddedPayload(string installDir) {
      Directory.CreateDirectory(installDir);
      Assembly asm = Assembly.GetExecutingAssembly();
      using (Stream resStream = asm.GetManifestResourceStream("EnvGuard.payload.zip")) {
        if (resStream == null) throw new Exception("Embedded payload missing.");
        using (ZipArchive archive = new ZipArchive(resStream, ZipArchiveMode.Read)) {
          foreach (ZipArchiveEntry entry in archive.Entries) {
            if (string.IsNullOrEmpty(entry.Name)) continue;
            string fullTarget = Path.GetFullPath(Path.Combine(installDir, entry.FullName));
            if (!fullTarget.StartsWith(Path.GetFullPath(installDir), StringComparison.OrdinalIgnoreCase)) continue;
            Directory.CreateDirectory(Path.GetDirectoryName(fullTarget));
            entry.ExtractToFile(fullTarget, true);
          }
        }
      }
    }

    private static void EnsureUserPathAndShim(string installDir, string nodeExe) {
      string binDir = Path.Combine(installDir, "bin");
      string vltCmd = Path.Combine(binDir, "vlt.cmd");
      string vltJs = Path.Combine(binDir, "vlt.js");
      File.WriteAllText(vltCmd, "@echo off\\r\\n\\"" + nodeExe + "\\" \\"" + vltJs + "\\" %*\\r\\n");
      string curPath = Environment.GetEnvironmentVariable("PATH", EnvironmentVariableTarget.User) ?? "";
      if (curPath.IndexOf(binDir, StringComparison.OrdinalIgnoreCase) < 0) {
        string nextPath = string.IsNullOrEmpty(curPath) ? binDir : (curPath.TrimEnd(';') + ";" + binDir);
        Environment.SetEnvironmentVariable("PATH", nextPath, EnvironmentVariableTarget.User);
      }
    }

    private void RunCommand(string fileName, string arguments, string workDir) {
      ProcessStartInfo psi = new ProcessStartInfo();
      psi.FileName = fileName;
      psi.Arguments = arguments;
      psi.WorkingDirectory = workDir;
      psi.UseShellExecute = false;
      psi.CreateNoWindow = true;
      Process p = Process.Start(psi);
      p.WaitForExit();
    }

    private void RunInstall() {
      string installDir = dirBox.Text.Trim();
      string nodeExe = FindNodeExe();
      btnInstall.Enabled = false;
      try {
        ExtractEmbeddedPayload(installDir);
        EnsureUserPathAndShim(installDir, nodeExe);
        string vltJs = Path.Combine(installDir, "bin", "vlt.js");
        string appExe = Path.Combine(installDir, "dist", "EnvGuard.exe");

        if (chkFreshReset.Checked) {
          string home = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".envguard");
          string vaultPath = Path.Combine(home, "vault.vlt");
          string backupsDir = Path.Combine(home, "backups");
          if (File.Exists(vaultPath)) {
            Directory.CreateDirectory(backupsDir);
            string stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
            File.Copy(vaultPath, Path.Combine(backupsDir, "vault-pre-setup-" + stamp + ".vlt.bak"), true);
            File.Delete(vaultPath);
          }
          RunCommand(nodeExe, "\\"" + vltJs + "\\" lock", installDir);
        }

        if (chkShortcuts.Checked) {
          RunCommand(nodeExe, "\\"" + vltJs + "\\" install-desktop", installDir);
        }

        if (chkShellHook.Checked) {
          RunCommand(nodeExe, "\\"" + vltJs + "\\" hook install", installDir);
        }

        RunCommand(nodeExe, "\\"" + vltJs + "\\" config --autostart " + (chkAutoStart.Checked ? "on" : "off"), installDir);

        if (File.Exists(appExe)) {
          Process.Start(appExe);
        } else {
          RunCommand(nodeExe, "\\"" + vltJs + "\\" ui", installDir);
        }
        this.Close();
      } catch (Exception ex) {
        MessageBox.Show(ex.Message, "EnvGuard Setup", MessageBoxButtons.OK, MessageBoxIcon.Error);
        btnInstall.Enabled = true;
      }
    }

    [STAThread]
    public static void Main() {
      Application.EnableVisualStyles();
      Application.SetCompatibleTextRenderingDefault(false);
      Application.Run(new SetupForm());
    }
  }
}
`;
}

function compileCsc(csCode, outExePath, icoPath, extraArgs = []) {
  const tmpCs = path.join(os.tmpdir(), `envguard-build-${path.basename(outExePath, '.exe')}-${Date.now()}.cs`);
  fs.writeFileSync(tmpCs, csCode, 'utf8');
  try {
    const args = [
      '/nologo',
      '/target:winexe',
      '/optimize+',
      `/out:${outExePath}`,
      `/win32icon:${icoPath}`,
      '/r:System.dll',
      '/r:System.Drawing.dll',
      '/r:System.Windows.Forms.dll',
      '/r:System.Web.Extensions.dll',
      ...extraArgs,
      tmpCs,
    ];
    execFileSync(CSC_PATH, args, { encoding: 'utf8', windowsHide: true });
  } finally {
    try { fs.unlinkSync(tmpCs); } catch { /* ignore */ }
  }
}

function createPayloadZip(outZipPath) {
  const stageDir = fs.mkdtempSync(path.join(os.tmpdir(), 'envguard-stage-'));
  try {
    fs.copyFileSync(path.join(ROOT, 'package.json'), path.join(stageDir, 'package.json'));
    ensureDirSync(path.join(stageDir, 'bin'));
    fs.copyFileSync(path.join(ROOT, 'bin', 'vlt.js'), path.join(stageDir, 'bin', 'vlt.js'));
    fs.cpSync(path.join(ROOT, 'src'), path.join(stageDir, 'src'), { recursive: true });
    fs.cpSync(path.join(ROOT, 'assets'), path.join(stageDir, 'assets'), { recursive: true });
    ensureDirSync(path.join(stageDir, 'dist'));
    fs.copyFileSync(path.join(DIST_DIR, 'EnvGuard.exe'), path.join(stageDir, 'dist', 'EnvGuard.exe'));
    fs.copyFileSync(path.join(DIST_DIR, 'EnvGuardPopup.exe'), path.join(stageDir, 'dist', 'EnvGuardPopup.exe'));

    if (fs.existsSync(outZipPath)) fs.unlinkSync(outZipPath);
    execFileSync(
      'powershell.exe',
      [
        '-NoProfile',
        '-ExecutionPolicy',
        'Bypass',
        '-Command',
        `Compress-Archive -Path "${stageDir}\\*" -DestinationPath "${outZipPath}" -CompressionLevel Optimal`,
      ],
      { windowsHide: true }
    );
  } finally {
    fs.rmSync(stageDir, { recursive: true, force: true });
  }
}

function main() {
  if (process.platform !== 'win32') {
    console.log('Windows .exe compilation skipped on non-Windows platform.');
    return;
  }
  if (!fs.existsSync(CSC_PATH)) {
    throw new Error(`csc.exe not found at ${CSC_PATH}`);
  }
  const icoPath = ensureIconFile();
  ensureDirSync(DIST_DIR);
  ensureDirSync(DOWNLOADS_DIR);

  const popupExe = path.join(DIST_DIR, 'EnvGuardPopup.exe');
  const appExe = path.join(DIST_DIR, 'EnvGuard.exe');
  const payloadZip = path.join(DIST_DIR, 'payload.zip');
  const setupDistExe = path.join(DIST_DIR, 'EnvGuard-Setup.exe');
  const setupDownloadsExe = path.join(DOWNLOADS_DIR, 'EnvGuard-Setup.exe');

  compileCsc(buildPopupExeSource(), popupExe, icoPath);
  compileCsc(buildLauncherExeSource(), appExe, icoPath);
  createPayloadZip(payloadZip);

  try {
    compileCsc(buildSetupExeSource(), setupDistExe, icoPath, [
      '/r:System.IO.Compression.dll',
      '/r:System.IO.Compression.FileSystem.dll',
      `/resource:${payloadZip},EnvGuard.payload.zip`,
    ]);
  } finally {
    try { fs.unlinkSync(payloadZip); } catch { /* ignore */ }
  }

  fs.copyFileSync(setupDistExe, setupDownloadsExe);

  console.log('Compiled standalone Windows executables (zero personal paths):');
  console.log(`  - ${popupExe} (${fs.statSync(popupExe).size} bytes)`);
  console.log(`  - ${appExe} (${fs.statSync(appExe).size} bytes)`);
  console.log(`  - ${setupDistExe} (${fs.statSync(setupDistExe).size} bytes)`);
  console.log(`  - ${setupDownloadsExe} (${fs.statSync(setupDownloadsExe).size} bytes)`);
}

main();
