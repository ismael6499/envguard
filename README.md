# EnvGuard (`vlt`)

Cross-platform encrypted secret and `.env` vault with native Windows/Linux authorization popups, configurable Master PIN sessions, AI Agent process-tree protection, timed AI Turbo Mode, zero-CLI integrations (Spring Boot, Java, Node.js, Python, .NET, AWS, Git), and a built-in Desktop UI.

## Key Features

- **Encrypted `VLT2` Envelope Vault (`AES-256-GCM` + `scrypt`)**: Secrets are never stored in plaintext on disk. Includes an **Emergency Recovery Key (`EVG-XXXX-XXXX-XXXX-XXXX`)** for PIN resets and automatic rolling backups (`~/.envguard/backups/`).
- **Native Consent & PIN Popup**:
  - Windows: Instant native compiled GUI (`EnvGuardPopup.exe`) with always-on-top focus, configurable countdown timeout (default `30s`), and remembered screen position.
  - Linux: Native `zenity` / `kdialog` dialog with `/dev/tty` fallback.
- **Granular Access Policies (per Environment, Profile, or Individual Key)**:
  - `Session Pass-through` (`session`) — automatic while your PIN session is active (`0m`, `15m`, `30m`, `1h`, `2h`, `4h`, `8h`, or `Until locked`).
  - `1-Click Confirm / Cancel` (`confirm`) — approve or deny without re-typing the PIN.
  - `PIN + Confirm Always` (`pin_confirm`) — requires PIN + confirmation every time (with `Critical` warning banner support).
  - `Blocked` (`blocked`) — denies all access.
- **AI Agent Detection & Timed AI Turbo Mode**:
  - Inspects caller parent process ancestry (`Antigravity`, `Claude`, `Cursor`, `Windsurf`, etc.) and env-dump commands (`printenv`, `Get-ChildItem Env:`).
  - Automatically escalates automated requests to a Confirm/Cancel prompt unless **⚡ AI Turbo Mode** is explicitly enabled for a timed window (`15m`, `30m`, `1h`, `2h`, `4h`). `pin_confirm` and `blocked` rules are never bypassed.
- **Zero-CLI Language & IDE Integrations**:
  - **Spring Boot / Java**: Import secrets directly via `spring.config.import=optional:http://127.0.0.1:47831/spring/<project>/<env>.properties`.
  - **Direct HTTP Endpoints**: `/env/<project>/<env>` (JSON or `?format=dotenv`) and `/env/<project>/<env>/<KEY>`.
  - **Transparent Shell Auto-Hook (`vlt hook install`)**: Automatically injects linked environment variables when running `mvn`, `gradle`, `java`, `npm`, `pnpm`, `yarn`, `node`, `python`, or `dotnet` inside linked directories (`vlt link`).
  - **Native AWS `credential_process`** (`vlt aws-cred`) & **Git `credential.helper`** (`vlt git-cred`).
- **Share, Export & Import Diff**:
  - Export **Self-Decrypting `.html` Cards** (browser Web Crypto `PBKDF2` + `AES-GCM`, zero dependencies for recipients), encrypted `.vltpack` bundles, safe `.env.tpl` (`vlt://` references), `.env.example`, or `.env`.
  - Smart Diff preview (`Added` / `Modified` / `Unchanged`) + up to **5-version variable history** with 1-click rollback.
- **Desktop App & OS Env Cleaner**:
  - Standalone Desktop window (`vlt ui` / `EnvGuard.exe`) remembering window position/size/maximized state, System Tray quick controls, EN/ES localization, and an OS Environment Cleaner to migrate persistent User environment variables with backup & restore.

## Installation

### Windows Installer (Recommended)
1. Ensure [Node.js](https://nodejs.org/) (v18+) is installed.
2. Download and run `EnvGuard-Setup.exe` from the [Releases](../../releases) page.
3. Choose installation options (Desktop/Start Menu shortcuts, optional terminal auto-hook, optional Windows startup), then configure your Master PIN on the First-Run Setup screen.

### From Source (Windows & Linux)
```bash
git clone <repository-url>
cd envguard
npm link
```
On Windows, you can also build the native `.exe` binaries and installer locally:
```bash
node scripts/build-windows-exe.js
```

## Quick Start

### Launch Desktop App
```bash
vlt ui
```

### Link a Project Directory & Run Commands
```bash
# Link the current repo directory without creating untracked files inside the repo
vlt link -p my-app -e dev

# Run any command with secrets injected into memory only
vlt run -- npm run dev
```

### Spring Boot (`application.properties`)
```properties
spring.config.import=optional:http://127.0.0.1:47831/spring/my-app/dev.properties
```

### CLI Reference
```text
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
vlt config [--vault-path <path>] [--autostart on|off] [--popup-timeout <sec>]
```

## Testing & Auditing

```bash
npm run audit-ui
npm test
```

## License

MIT
