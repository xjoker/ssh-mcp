# install.ps1 — user-level installer for mcp-ssh-bridge (Windows).
#
# Default install location is %LOCALAPPDATA%\Programs\mcp-ssh-bridge — no
# admin elevation required. The MCP binary is just a stdio process
# spawned by your AI client; it does not need C:\Program Files or admin.
#
# Usage:
#   iwr -useb https://raw.githubusercontent.com/xjoker/ssh-mcp/main/scripts/install.ps1 | iex
#   .\scripts\install.ps1                  # from a local checkout
#
# Env vars:
#   $env:PREFIX        install directory (default: $env:LOCALAPPDATA\Programs\mcp-ssh-bridge)
#   $env:BRANCH        git branch (default: main)
#   $env:REPO_URL      git URL  (default: https://github.com/xjoker/ssh-mcp.git)
#   $env:SKIP_BUILD=1  if the source tree is already built, just install the .exe

$ErrorActionPreference = 'Stop'

$RepoUrl = if ($env:REPO_URL) { $env:REPO_URL } else { 'https://github.com/xjoker/ssh-mcp.git' }
$Branch  = if ($env:BRANCH)   { $env:BRANCH }   else { 'main' }
$Prefix  = if ($env:PREFIX)   { $env:PREFIX }   else { Join-Path $env:LOCALAPPDATA 'Programs\mcp-ssh-bridge' }

function Log    ($m) { Write-Host "[install] $m" -ForegroundColor Cyan }
function Warn   ($m) { Write-Host "[install] $m" -ForegroundColor Yellow }
function Fail   ($m) { Write-Host "[install] $m" -ForegroundColor Red; exit 1 }

# 1. Ensure prefix exists.
New-Item -ItemType Directory -Force -Path $Prefix | Out-Null

# 2. Locate or fetch source tree.
$cleanupSrc = $false
if ((Test-Path 'go.mod') -and (Test-Path 'cmd\mcp-ssh-bridge')) {
  Log "using local source tree: $((Get-Location).Path)"
  $Src = (Get-Location).Path
} else {
  if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Fail 'git not found; install Git for Windows first' }
  $Src = Join-Path $env:TEMP "mcp-ssh-bridge-$([guid]::NewGuid().ToString('N'))"
  Log "cloning $RepoUrl@$Branch → $Src"
  & git clone --depth 1 --branch $Branch $RepoUrl $Src | Out-Null
  $cleanupSrc = $true
}

# 3. Build unless skipped.
if ($env:SKIP_BUILD -ne '1') {
  if (-not (Get-Command go -ErrorAction SilentlyContinue)) { Fail 'go not found; install Go 1.22+ from https://go.dev/dl/' }
  Log 'building...'
  Push-Location $Src
  try {
    & go build -trimpath -o (Join-Path 'bin' 'mcp-ssh-bridge.exe') ./cmd/mcp-ssh-bridge
    if ($LASTEXITCODE -ne 0) { Fail 'go build failed' }
  } finally { Pop-Location }
}

$Bin = Join-Path $Src 'bin\mcp-ssh-bridge.exe'
if (-not (Test-Path $Bin)) { Fail "binary missing: $Bin" }

# 4. Install (user-level).
$Dest = Join-Path $Prefix 'mcp-ssh-bridge.exe'
Log "installing → $Dest"
Copy-Item -Force $Bin $Dest

# 5. Cleanup temp clone.
if ($cleanupSrc) { Remove-Item -Recurse -Force $Src }

# 6. PATH hint.
$pathParts = $env:Path -split ';'
if ($pathParts -notcontains $Prefix) {
  Warn "$Prefix is not in PATH. Add it via:"
  Warn "  [Environment]::SetEnvironmentVariable('Path', `"`$env:Path;$Prefix`", 'User')"
  Warn "(then restart your shell)"
}

Log 'done.'
Log ''
Log 'next steps:'
Log "  $Dest config init"
Log "  $Dest config add-server prod --host example.com --user alice --auth agent"
Log ''
Log 'register with your AI client (use the official CLI, not file-editing):'
Log "  claude mcp add --transport stdio --scope user ssh-bridge -- $Dest"
Log "  codex mcp add ssh-bridge -- $Dest"
