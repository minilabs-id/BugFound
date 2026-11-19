<#
.SYNOPSIS
    Local end-to-end smoke test: HTML brief server -> `agentbug.exe engage
    --brief-only` -> report existence check.

.DESCRIPTION
    Starts a loopback-only HTTP server serving a small program brief, runs the
    read-only brief ingestion path (`engage --brief-only`), then runs the normal
    offline engagement so a report file is written. Asserts that the report
    exists, contains the seven required sections, and passes `score.py --strict`.
    No external network, no live program, no submission path.

    This is a wiring/format smoke test, not a benchmark: it asserts no
    recall/precision/FPR claim. Keep generated files under eval/work/
    (gitignored); operator-recorded artifacts belong in eval/results/.
#>
[CmdletBinding()]
param(
    [string]$Agentbug = 'agentbug.exe',
    [switch]$KeepWork
)

$ErrorActionPreference = 'Stop'
$scriptDir = $PSScriptRoot
$workDir = Join-Path (Join-Path $scriptDir 'work') 'e2e'
New-Item -ItemType Directory -Force -Path $workDir | Out-Null

$briefHtml = @'
<!doctype html>
<html><body>
<h1>AgentBug E2E Program</h1>
<p>Program: AgentBug E2E Local</p>
<p>In scope</p>
<ul><li>- 127.0.0.1</li></ul>
<p>Out of scope</p>
<ul><li>- example.com</li></ul>
<p>Please report findings privately. Safe harbor applies to this local testbed.</p>
</body></html>
'@
$briefPath = Join-Path $workDir 'brief.html'
Set-Content -LiteralPath $briefPath -Encoding UTF8 -Value $briefHtml

# Pick a free loopback port.
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
$listener.Stop()

$serverArgs = "-m http.server $port --bind 127.0.0.1 --directory `"$workDir`""
$server = Start-Process -FilePath 'python' -ArgumentList $serverArgs -PassThru -NoNewWindow `
    -RedirectStandardOutput (Join-Path $workDir 'server.out.log') `
    -RedirectStandardError (Join-Path $workDir 'server.err.log')

$savedApiKey = $env:AGENTBUG_API_KEY
$savedOpenAiKey = $env:OPENAI_API_KEY
try {
    # Wait for the brief server to accept connections.
    $ready = $false
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        $client = $null
        try {
            $client = [System.Net.Sockets.TcpClient]::new()
            $client.Connect('127.0.0.1', $port)
            $ready = $true
        } catch {
            Start-Sleep -Milliseconds 250
        } finally {
            if ($null -ne $client) { $client.Dispose() }
        }
        if ($ready) { break }
    }
    if (-not $ready) {
        throw "local brief server did not start on port $port (see $workDir\server.err.log)"
    }

    $url = "http://127.0.0.1:$port/brief.html"

    # Force offline mode so this smoke test never calls an LLM provider.
    $env:AGENTBUG_API_KEY = ''
    $env:OPENAI_API_KEY = ''

    # 1. Required read-only path: ingest the brief, plan tasks, execute no tools.
    $briefArgs = @('engage', '--brief-only', '--url', $url, '--cwd', $workDir, `
        '--db', (Join-Path $workDir 'brief-only.db'))
    & $Agentbug @briefArgs 2>&1 | Tee-Object -FilePath (Join-Path $workDir 'brief-only.log')
    $briefLog = Get-Content -LiteralPath (Join-Path $workDir 'brief-only.log') -Raw
    if ($briefLog -notmatch 'engagement started' -or $briefLog -notmatch 'engagement finished') {
        throw "engage --brief-only did not complete; see $workDir\brief-only.log"
    }
    Write-Host "[e2e] brief-only ingestion OK"

    # 2. Offline full engagement writes a report-<id>.md under --cwd.
    $engageArgs = @('engage', '--url', $url, '--cwd', $workDir, `
        '--db', (Join-Path $workDir 'engage.db'))
    & $Agentbug @engageArgs 2>&1 | Tee-Object -FilePath (Join-Path $workDir 'engage.log')

    $report = Get-ChildItem -LiteralPath $workDir -Recurse -File -Filter 'report*.md' `
        -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $report) {
        throw "no report file found under $workDir after engage"
    }
    Write-Host "[e2e] report exists: $($report.FullName)"

    # The canonical report must contain every section that score.py checks.
    $reportText = Get-Content -LiteralPath $report.FullName -Raw
    $requiredSections = @(
        'Executive Summary', 'Scope & ROE', 'Methodology', 'Findings',
        'Coverage', 'Timeline', 'Appendices'
    )
    $headings = [regex]::Matches($reportText, '(?m)^##\s+(.+?)\s*$') |
        ForEach-Object { $_.Groups[1].Value.Trim() }
    $missing = @($requiredSections | Where-Object {
        $section = $_
        -not ($headings | Where-Object {
            $_ -eq $section -or ($section -eq 'Scope & ROE' -and $_ -eq 'Scope')
        })
    })
    if ($missing.Count -gt 0) {
        throw "report is missing required sections: $($missing -join ', ')"
    }
    Write-Host "[e2e] required sections present: $($requiredSections -join ', ')"

    # Format gate: strict scoring checks sections and finding fields. This is a
    # structural assertion only; no benchmark metric or threshold is claimed.
    $scorer = Join-Path $scriptDir 'score.py'
    & python $scorer $report.FullName --strict
    $scoreExit = $LASTEXITCODE
    if ($scoreExit -ne 0) {
        throw "score.py --strict rejected the report (exit $scoreExit)"
    }
    Write-Host "[e2e] score.py --strict PASS (format only; no benchmark result)."
} finally {
    $env:AGENTBUG_API_KEY = $savedApiKey
    $env:OPENAI_API_KEY = $savedOpenAiKey
    if ($null -ne $server -and -not $server.HasExited) {
        Stop-Process -Id $server.Id -Force
    }
    if (-not $KeepWork) {
        # Artifacts are left in eval/work/ (gitignored) for inspection.
        Write-Host "[e2e] artifacts kept for inspection at $workDir"
    }
}
