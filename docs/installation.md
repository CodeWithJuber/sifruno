# Install and run from source

Sifruno currently provides a local engineering panel, not a production hosting installer. These steps build source and run a private loopback panel. They do not install services, provision hosting identities, configure DNS/TLS/mail, or certify vendor compatibility.

See [the documentation index](README.md) and [current project state](PROJECT-STATE.md)
for delivered source and acceptance limits. This guide is in main; its commands
were source-reviewed, not replayed as a fresh clean-machine installation. The
merged WIP runtime-input guest archive is not runnable and is not an installation
step. Historical guest/browser results do not certify a current deployment.

## Windows (PowerShell)

1. Install Git, Node.js **24.19.0** (including npm), and Go **1.27.1**. Obtain them from their official distributors. The repository also provides the pinned Windows tool bootstrap described below; it downloads tools only when you explicitly run it. Open PowerShell as your ordinary user.
2. Clone the repository and enter its root. Every command below runs from that directory:

   ```powershell
   git clone https://github.com/CodeWithJuber/sifruno.git
   Set-Location sifruno
   ```

3. Install the locked root and UI dependencies, without dependency lifecycle scripts:

   ```powershell
   npm ci --ignore-scripts --no-audit --no-fund
   npm --prefix web ci --ignore-scripts --no-audit --no-fund
   npm run panel:build
   ```

4. Build the panel and local CLI with your installed Go toolchain:

   ```powershell
   New-Item -ItemType Directory -Force bin | Out-Null
   go build -buildvcs=false -o bin/sifruno.exe ./cmd/sifruno
   go build -buildvcs=false -o bin/panelctl.exe ./cmd/panelctl
   ```

   Builds may download the module versions recorded by `go.mod`/`go.sum`. Do not substitute a different dependency set. For the repository's pinned Windows Go bootstrap/wrapper, see the toolchain note below.

5. Choose a dedicated private state directory, outside source assets and any web-served directory. Keep the same value for the panel and CLI:

   ```powershell
   $panelState = Join-Path $env:LOCALAPPDATA 'Sifruno/local-panel'
   ./bin/sifruno.exe --listen 127.0.0.1:8080 --sites-listen 127.0.0.1:8082 --state "$panelState" --ui web/dist
   ```

   Keep this terminal open. Visit **http://127.0.0.1:8080**. The second listener is for app-owned static-site previews; it is not Apache/PHP hosting. Do not expose either listener publicly.

6. Open the generated operator key privately on this machine using a local editor, then enter it into the panel's private sign-in form. The file is `operator/access.key` inside the chosen state directory. Do not print it to the terminal, paste it into chat, commit it, include it in screenshots, or serve the state directory. Session cookies and CSRF protect the private workflows; this is not remote multi-tenant authentication.

7. To try static hosting, create a website in **Websites**, open its **File Manager**, and choose **Upload file**. Select a static asset, review its relative path and confirm. Open the website preview to check the file, then use **Backups** to create a native ZIP. Follow the [upload and recovery walkthrough](site-file-upload.md) for the exact scope and limits.

8. Verify the panel and CLI using the commands below, from a second terminal in the repository root. Stop the panel with **Ctrl+C** in its original terminal. Preserve its state directory to retain sites, recovery history and operator state; deleting it is not an upgrade procedure.

### Pinned Windows Go toolchain (alternative to installed Go)

From the repository root, explicitly run the bootstrap, without `-Analysis`:

```powershell
.\scripts\bootstrap-tools.ps1
.\scripts\go.ps1 build -buildvcs=false -o bin/sifruno.exe ./cmd/sifruno
.\scripts\go.ps1 build -buildvcs=false -o bin/panelctl.exe ./cmd/panelctl
```

The bootstrap downloads Go 1.27.1 Windows amd64 and checks its pinned SHA-256. The wrapper uses repository-local tooling/cache. This is a development tool bootstrap, not a panel/service installer.

### Verify local responses

While the panel is running, in a second PowerShell terminal set the same state path:

```powershell
$panelState = Join-Path $env:LOCALAPPDATA 'Sifruno/local-panel'
Invoke-RestMethod http://127.0.0.1:8080/api/v1/server
Invoke-RestMethod http://127.0.0.1:8080/api/v1/status
Invoke-RestMethod http://127.0.0.1:8080/openapi.json
./bin/panelctl.exe --state "$panelState" --panel-url http://127.0.0.1:8080 sites list
```

The server response is telemetry; status is compatibility data, not a production-readiness or health certificate. `sites list` exercises authenticated HTTP using the local key without displaying it. `panelctl status` checks local compatibility; `status --require-ready` is expected to fail while compatibility obligations remain unqualified. There is no documented `/health` route.

On Linux/macOS, use `curl --fail http://127.0.0.1:8080/api/v1/server` and `./bin/panelctl --state "$panel_state" --panel-url http://127.0.0.1:8080 sites list` from a second terminal, with the same state value. Keep authentication material private.

## Linux and macOS

Use an installed Git/Node.js/npm/Go toolchain matching the versions above. Run as a normal nonroot user; privileged hosting prerequisites are a separate installation.

```sh
git clone https://github.com/CodeWithJuber/sifruno.git
cd sifruno
npm ci --ignore-scripts --no-audit --no-fund
npm --prefix web ci --ignore-scripts --no-audit --no-fund
npm run panel:build
mkdir -p bin
go build -buildvcs=false -o bin/sifruno ./cmd/sifruno
go build -buildvcs=false -o bin/panelctl ./cmd/panelctl
panel_state="$HOME/.local/share/sifruno/local-panel"
./bin/sifruno --listen 127.0.0.1:8080 --sites-listen 127.0.0.1:8082 --state "$panel_state" --ui web/dist
```

Open the same loopback URL, privately read the generated operator key locally, and sign in. Stop with Ctrl+C and retain state. Windows execution has been observed. Linux qualification covers specific isolated slices described in the evidence guides, not every distribution or a full hosting installation. macOS native execution remains unverified; successful compilation does not establish runtime qualification.

## Optional native hosting prerequisites

Accounts and web metadata preview require a separately admitted Linux broker and trusted controller layout. They are unavailable by default without that setup. Read [hosting accounts](hosting-accounts.md), [controller layout CLI](controller-layout-cli.md), [native web preview](native-web-preview.md), and [runtime input diagnostic](web-runtime-input-check.md) before attempting that separate scope. The input diagnostic checks installation inputs only; it does not apply configuration or establish serving health. There is no zero-configuration installer or automatic service installation in this guide.

## Troubleshooting

- **UI or modules missing:** run both `npm ci` commands, then `npm run panel:build`. `--ui web/dist` is relative to the process working directory; start from the repository root.
- **Port already in use:** stop your own earlier panel, or choose unused loopback ports with `--listen` and `--sites-listen`. Use the same panel URL for CLI requests. Do not change firewall rules to make this guide work.
- **State appears empty or sign-in differs:** confirm the panel and CLI use the same absolute state directory. Do not replace an existing operator key or delete state as a quick fix.
- **Accounts unavailable:** the optional native broker is not installed/admitted by the local-panel steps. An unavailable feature is not a serving-health result.
- **Build fails:** verify tool versions and run from the repository root. Source builds and runtime qualification are separate; no prebuilt release asset is promised here.
