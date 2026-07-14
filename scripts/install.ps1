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
    $release = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest"
    $Tag = $release.tag_name
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

# 4. Download to a same-directory temporary file, verify it, then atomically
# replace the existing user-local installation. No administrator rights are
# required for the default prefix.
$Dest = Join-Path $Prefix 'ssh-mcp.exe'
$Temp = Join-Path $Prefix ('.ssh-mcp-install-{0}.tmp' -f [Guid]::NewGuid().ToString('N'))
$Backup = $null
$ChecksumFile = [System.IO.Path]::GetTempFileName()
Log "downloading $Tag (windows/amd64)..."
try {
  Invoke-WebRequest -Uri $Url -OutFile $Temp -UseBasicParsing

  Log 'verifying checksum...'
  $ChecksumUrl = "https://github.com/$Repo/releases/download/$Tag/checksums.sha256"
  Invoke-WebRequest -Uri $ChecksumUrl -OutFile $ChecksumFile -UseBasicParsing

  $ExpectedSHA = $null
  foreach ($Line in Get-Content -LiteralPath $ChecksumFile) {
    $Parts = $Line.Trim() -split '\s+', 2
    if ($Parts.Count -eq 2 -and $Parts[1].TrimStart([char]'*') -eq $Asset) {
      $ExpectedSHA = $Parts[0].ToLowerInvariant()
      break
    }
  }
  if (-not $ExpectedSHA -or $ExpectedSHA -notmatch '^[0-9a-f]{64}$') {
    throw "checksum not found for $Asset in checksums.sha256"
  }

  $ActualSHA = (Get-FileHash -Algorithm SHA256 -LiteralPath $Temp).Hash.ToLowerInvariant()
  if ($ExpectedSHA -ne $ActualSHA) {
    throw "checksum mismatch for $Asset (expected $ExpectedSHA, got $ActualSHA)"
  }

  if (Test-Path -LiteralPath $Dest) {
    $Backup = "$Temp.backup"
    [System.IO.File]::Replace($Temp, $Dest, $Backup)
  } else {
    [System.IO.File]::Move($Temp, $Dest)
  }
  $Temp = $null
} catch {
  Fail "install failed: $_"
} finally {
  if ($Temp -and (Test-Path -LiteralPath $Temp)) {
    Remove-Item -LiteralPath $Temp -Force
  }
  if ($Backup -and (Test-Path -LiteralPath $Backup)) {
    Remove-Item -LiteralPath $Backup -Force
  }
  if (Test-Path -LiteralPath $ChecksumFile) {
    Remove-Item -LiteralPath $ChecksumFile -Force
  }
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
