[CmdletBinding()]
param(
    [string]$IdaDir = 'C:\Program Files\IDA Pro 8.0',
    [string]$ConfigPath = '',
    [string]$ServerName = 'ida80',
    [string]$PluginsDir = '',
    [string]$TestBinary = '',
    [string]$ExpectedVersion = '8.0',
    [switch]$SkipGui,
    [switch]$NoPause
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = Split-Path -Parent $PSScriptRoot
$exitCode = 1
$originalPath = $env:PATH

function Invoke-Checked {
    param([string]$Executable, [string[]]$Arguments)
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $Executable $($Arguments -join ' ')"
    }
}

function Find-OrInstallUv {
    $found = Get-Command uv.exe -ErrorAction SilentlyContinue
    if ($found) { return $found.Source }
    $userBin = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.local\bin'
    $candidate = Join-Path $userBin 'uv.exe'
    if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    Write-Host 'uv was not found. Installing uv from the official Astral installer...'
    $download = Join-Path ([IO.Path]::GetTempPath()) ("ida-mcp-uv-" + [guid]::NewGuid().ToString('N') + '.ps1')
    $oldInstallDir = $env:UV_INSTALL_DIR
    $oldModifyPath = $env:UV_NO_MODIFY_PATH
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -UseBasicParsing -Uri 'https://astral.sh/uv/install.ps1' -OutFile $download
        $env:UV_INSTALL_DIR = $userBin
        $env:UV_NO_MODIFY_PATH = '1'
        # Pipe output to the host so it is not returned as part of the uv path.
        Invoke-Checked 'powershell.exe' @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $download) | Out-Host
    }
    finally {
        $env:UV_INSTALL_DIR = $oldInstallDir
        $env:UV_NO_MODIFY_PATH = $oldModifyPath
        if (Test-Path -LiteralPath $download) { Remove-Item -LiteralPath $download }
    }
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "uv installation did not produce $candidate"
    }
    return $candidate
}

try {
    Write-Host '=== IDA MCP one-click installation ==='
    if (-not (Test-Path -LiteralPath (Join-Path $repoRoot 'vendor\ida-nexus\pyproject.toml'))) {
        throw 'Keep install_one_click.bat and scripts beside the complete repository, including vendor.'
    }
    $IdaDir = (Resolve-Path -LiteralPath $IdaDir).Path
    $console64 = Join-Path $IdaDir 'idat64.exe'
    $console = Join-Path $IdaDir 'idat.exe'
    if (-not (Test-Path -LiteralPath $console64 -PathType Leaf) -and
        -not (Test-Path -LiteralPath $console -PathType Leaf)) {
        throw "No idat64.exe or idat.exe in $IdaDir. A console IDA Pro installation with IDAPython is required."
    }
    if (-not $SkipGui) {
        $running = @(Get-Process -Name ida,ida64,idat,idat64 -ErrorAction SilentlyContinue |
            Where-Object { $_.Path -and $_.Path.StartsWith($IdaDir + '\', [StringComparison]::OrdinalIgnoreCase) })
        if ($running.Count -gt 0) {
            throw 'Save and close IDA and stop its MCP workers before updating the GUI plugin, then run this installer again.'
        }
    }
    if (-not $ConfigPath) { $ConfigPath = Join-Path $repoRoot '.mcp.json' }
    $ConfigPath = [IO.Path]::GetFullPath($ConfigPath)
    $uvExe = Find-OrInstallUv
    $env:PATH = (Split-Path -Parent $uvExe) + ';' + $env:PATH
    Write-Host "[1/4] Syncing locked dependencies in $repoRoot"
    Invoke-Checked $uvExe @('--directory', $repoRoot, 'sync', '--locked')

    Write-Host '[2/4] Updating the GUI plugin (console workers use the repository directly)'
    if (-not $SkipGui) {
        $pluginArgs = @('--directory', $repoRoot, 'run', '--locked', 'python', 'scripts/install_ida80.py')
        if ($PluginsDir) { $pluginArgs += @('--plugins-dir', [IO.Path]::GetFullPath($PluginsDir)) }
        Invoke-Checked $uvExe $pluginArgs
    }
    else { Write-Host 'GUI plugin update skipped.' }

    Write-Host '[3/4] Checking package sources, testing MCP startup, and merging configuration'
    Invoke-Checked $uvExe @('--directory', $repoRoot, 'run', '--locked', 'python',
        'scripts/configure_mcp.py', '--config', $ConfigPath, '--uv', $uvExe,
        '--ida-dir', $IdaDir, '--server-name', $ServerName)

    Write-Host '[4/4] Runtime verification'
    if ($TestBinary) {
        $TestBinary = (Resolve-Path -LiteralPath $TestBinary).Path
        $report = Join-Path $repoRoot 'dist\ida80-headless-report.json'
        New-Item -ItemType Directory -Path (Split-Path -Parent $report) -Force | Out-Null
        Invoke-Checked $uvExe @('--directory', $repoRoot, 'run', '--locked', 'python',
            'scripts/verify_ida.py', '--database', $TestBinary, '--idat', $IdaDir,
            '--expect-version', $ExpectedVersion, '--headless-only', '--output', $report)
        Write-Host "Runtime report: $report"
    }
    else {
        Write-Host 'MCP startup checked. IDA analysis was not tested; use -TestBinary with a disposable executable to test it.'
    }
    Write-Host ''
    Write-Host "SUCCESS: MCP configuration saved to $ConfigPath"
    Write-Host "Server name: $ServerName"
    Write-Host "IDA directory: $IdaDir"
    Write-Host 'Restart your Agent. For Claude Code, start it in the directory containing .mcp.json.'
    Write-Host 'For another JSON-based Agent, import this file or use -ConfigPath to update its MCP config.'
    Write-Host 'Keep this repository at its current location; the configuration contains absolute paths.'
    $exitCode = 0
}
catch {
    Write-Host ''
    Write-Host ('FAILED: ' + $_.Exception.Message) -ForegroundColor Red
}
finally {
    $env:PATH = $originalPath
    if (-not $NoPause) { Read-Host 'Press Enter to close' | Out-Null }
}
exit $exitCode
