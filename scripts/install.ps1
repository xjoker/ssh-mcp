# install.ps1 — download pre-built ssh-mcp binary (Windows amd64).
#
# No Go, no git, no build tools required.
#
# Usage:
#   iwr -useb https://raw.githubusercontent.com/xjoker/ssh-mcp/main/scripts/install.ps1 | iex
#   .\scripts\install.ps1                  # from a local checkout
#
# Env vars:
#   $env:PREFIX    install directory (default: %LOCALAPPDATA%\Programs\ssh-mcp)
#   $env:VERSION   specific release tag (default: latest)

$ErrorActionPreference = 'Stop'

$Repo   = 'xjoker/ssh-mcp'
$Prefix = if ($env:PREFIX) { $env:PREFIX } else { Join-Path $env:LOCALAPPDATA 'Programs\ssh-mcp' }

function Log  ($m) { Write-Host "[install] $m" -ForegroundColor Cyan }
function Warn ($m) { Write-Host "[install] $m" -ForegroundColor Yellow }
function Fail ($m) { Write-Host "[install] $m" -ForegroundColor Red; exit 1 }

# 1. Resolve release tag.
$Tag = $env:VERSION
if (-not $Tag) {
  Log 'fetching latest release...'
  try {
    $releases = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases"
    $Tag = $releases[0].tag_name
  } catch {
    Fail "could not fetch release info: $_. Set `$env:VERSION=vX.Y.Z or visit https://github.com/$Repo/releases"
  }
  if (-not $Tag) { Fail "no releases found at https://github.com/$Repo/releases" }
}

# 2. Build asset URL (Windows: amd64 only for now).
$Asset = 'ssh-mcp_windows_amd64.exe'
$Url   = "https://github.com/$Repo/releases/download/$Tag/$Asset"

# 3. Ensure prefix directory exists.
New-Item -ItemType Directory -Force -Path $Prefix | Out-Null

# 4. Download binary.
$Dest = Join-Path $Prefix 'ssh-mcp.exe'
Log "downloading $Tag (windows/amd64)..."
try {
  Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing
} catch {
  Fail "download failed from $Url : $_"
}

# 5. PATH hint.
$pathParts = [Environment]::GetEnvironmentVariable('Path', 'User') -split ';'
if ($pathParts -notcontains $Prefix) {
  Warn "$Prefix is not in PATH. Add it permanently with:"
  Warn "  [Environment]::SetEnvironmentVariable('Path', `"`$env:Path;$Prefix`", 'User')"
  Warn "(then restart your terminal)"
}

Log "installed $Tag -> $Dest"
Log ''
Log 'next steps:'
Log "  $Dest config init"
Log "  $Dest config add-server prod --host example.com --user alice --auth agent"
Log ''
Log 'register with your AI client (use the official CLI, not file-editing):'
Log "  claude mcp add --transport stdio --scope user ssh-bridge -- $Dest"
Log "  codex  mcp add ssh-bridge -- $Dest"
