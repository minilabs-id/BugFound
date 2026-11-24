<#
.SYNOPSIS
    BugFound benchmark driver for Windows (no WSL). DRY RUN BY DEFAULT.

.DESCRIPTION
    Loops over the targets in targets.yml (or targets.example.yml), runs
    `bugfound.exe engage ...` for each local target, and saves the report, log,
    ground-truth manifest, trace export, joined replay JSONL and the scorer's
    recorded score under eval/results/<id>/. The engagement replay
    (workspace/replay-<id>.jsonl) is fed to `score.py --replay` after being
    joined with trace_events exported from the SQLite DB.

    Without -Execute nothing is run and nothing is written. This is scaffolding:
    no benchmark result is asserted. An operator must run real engagements and
    record the generated results.

.EXAMPLE
    pwsh eval/run_benchmark.ps1
    pwsh eval/run_benchmark.ps1 -Execute
    pwsh eval/run_benchmark.ps1 -Execute -AllowRemote -Bugfound C:\path\bugfound.exe
#>
[CmdletBinding()]
param(
    [switch]$Execute,
    [switch]$AllowRemote,
    [string]$Targets,
    [string]$Results,
    [string]$Bugfound = 'bugfound.exe',
    [switch]$Help
)

function Show-Usage {
    @'
Usage: run_benchmark.ps1 [options]

Options:
  -Execute            Actually run engagements (default: dry run only).
  -Targets FILE       Target inventory (default: eval/targets.yml, then example).
  -Results DIR        Output directory (default: eval/results).
  -Bugfound BIN       BugFound executable (default: bugfound.exe on PATH).
  -AllowRemote        Permit non-loopback/non-private URLs (isolated lab only).
  -Help               Show this help.

Dry run prints the commands it would run and writes nothing. Nothing is submitted
to an external platform; only local reports are produced.
'@
}

if ($Help) {
    Show-Usage
    return
}

$scriptDir = $PSScriptRoot
$exporter = Join-Path $scriptDir 'export_trace.py'
$scorer = Join-Path $scriptDir 'score.py'
if (-not $Targets) {
    $target = Join-Path $scriptDir 'targets.yml'
    if (-not (Test-Path -LiteralPath $target)) {
        $target = Join-Path $scriptDir 'targets.example.yml'
    }
    $Targets = $target
}
if (-not $Results) {
    $Results = Join-Path $scriptDir 'results'
}
if (-not (Test-Path -LiteralPath $Targets)) {
    throw "targets file not found: $Targets"
}

function Test-IsLocalUrl {
    param([string]$Value)
    try {
        $uri = [Uri]::new($Value)
    } catch {
        return $false
    }
    $hostName = $uri.Host.ToLowerInvariant()
    if ($hostName -in @('localhost', '127.0.0.1', '::1')) {
        return $true
    }
    if ($hostName.EndsWith('.local')) {
        return $true
    }
    if ($hostName -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$') {
        $first = [int]$Matches[1]
        $second = [int]$Matches[2]
        if ($first -eq 10 -or $first -eq 127) {
            return $true
        }
        if ($first -eq 192 -and $second -eq 168) {
            return $true
        }
        if ($first -eq 172 -and $second -ge 16 -and $second -le 31) {
            return $true
        }
    }
    return $false
}

# Parse the small YAML subset used by targets.example.yml without external deps.
$inventory = @()
$current = $null
foreach ($line in (Get-Content -LiteralPath $Targets)) {
    if ($line -match '^\s*-\s*id:\s*(\S+)\s*$') {
        if ($null -ne $current) {
            $inventory += $current
        }
        $current = [ordered]@{ id = $Matches[1]; url = ''; cwd = ''; expected_vulns = ''; name = '' }
        continue
    }
    if ($null -eq $current) {
        continue
    }
    if ($line -match '^\s+(url|cwd|expected_vulns|name):\s*(.*?)\s*$') {
        $key = $Matches[1]
        $value = $Matches[2]
        if ($value -match '^(["''])(.*)\1$') {
            $value = $Matches[2]
        }
        $current[$key] = $value
    }
}
if ($null -ne $current) {
    $inventory += $current
}
if ($inventory.Count -eq 0) {
    throw "no targets found in $Targets"
}

$summary = @()
foreach ($target in $inventory) {
    $id = [string]$target['id']
    $url = [string]$target['url']
    $workDir = [string]$target['cwd']
    if (-not $workDir) {
        $workDir = Join-Path (Join-Path $scriptDir 'work') $id
    }
    $safeId = [regex]::Replace($id, '[^A-Za-z0-9._-]', '_')
    $targetDir = Join-Path $Results $safeId
    $report = Join-Path $targetDir 'report.md'
    $log = Join-Path $targetDir 'run.log'
    $replay = Join-Path $targetDir 'replay.jsonl'
    $manifestPath = Join-Path $targetDir 'manifest.json'
    $dbPath = Join-Path $targetDir 'engagement.db'

    if (-not $AllowRemote -and -not (Test-IsLocalUrl -Value $url)) {
        Write-Host "[$id] REFUSED (non-local URL; use -AllowRemote only in an isolated lab): $url"
        $summary += [pscustomobject]@{ Id = $id; Status = 'refused'; Report = $report }
        continue
    }

    $arguments = @('engage', '--url', $url, '--cwd', $workDir, '--db', $dbPath)
    Write-Host "[$id] $Bugfound $($arguments -join ' ')"
    Write-Host "        report -> $report | replay -> $replay | log -> $log"
    if (-not $Execute) {
        Write-Host "        export -> python $exporter <engagement.db> <trace.jsonl>"
        Write-Host "        replay -> python $exporter <engagement.db> $replay --merge <workspace/replay-<id>.jsonl>"
        Write-Host "        score  -> python $scorer --dir $targetDir --manifest $manifestPath --replay $replay --json"
        $summary += [pscustomobject]@{ Id = $id; Status = 'dry-run'; Report = $report }
        continue
    }

    New-Item -ItemType Directory -Force -Path $targetDir, $workDir | Out-Null
    $vulns = @($target['expected_vulns'] -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $manifest = [ordered]@{ project = $id; expected_vulns = $vulns }
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

    & $Bugfound @arguments 2>&1 | Tee-Object -FilePath $log
    $nativeExit = $LASTEXITCODE
    $status = 'ok'
    if ($nativeExit -ne 0) {
        $status = "failed(exit=$nativeExit)"
    }

    $newest = Get-ChildItem -LiteralPath $workDir -Recurse -File -Filter 'report*.md' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($newest) {
        Copy-Item -LiteralPath $newest.FullName -Destination $report -Force
    } else {
        Write-Warning "[$id] no report found under $workDir"
        if ($status -eq 'ok') { $status = 'no-report' }
    }

    # The engagement writes workspace/replay-<engagement-id>.jsonl. Join it with
    # the authoritative trace_events export: the trace DB wins for kinds both
    # sources carry (no double-counted findings or tokens), the engagement log
    # contributes brief/plan/lifecycle context the DB does not store here.
    $engagementReplay = Get-ChildItem -LiteralPath $workDir -Recurse -File -Filter 'replay-*.jsonl' `
        -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    $trace = Join-Path $targetDir 'trace.jsonl'
    $replayCopy = Join-Path $targetDir 'engagement-replay.jsonl'
    if ($engagementReplay) {
        Copy-Item -LiteralPath $engagementReplay.FullName -Destination $replayCopy -Force
    }
    if (Test-Path -LiteralPath $dbPath) {
        try {
            & python $exporter $dbPath $trace
            if ($engagementReplay) {
                & python $exporter $dbPath $replay --merge $engagementReplay.FullName
            } else {
                & python $exporter $dbPath $replay
                Write-Warning "[$id] no workspace/replay-*.jsonl found; trace-only replay"
            }
        } catch {
            Write-Warning "[$id] could not export replay JSONL: $_"
        }
    } else {
        Write-Warning "[$id] engagement DB not found; replay not exported"
    }

    if (Test-Path -LiteralPath $replay) {
        $score = Join-Path $targetDir 'score.json'
        & python $scorer --dir $targetDir --manifest $manifestPath --replay $replay --json |
            Set-Content -LiteralPath $score -Encoding UTF8
        Write-Host "[$id] score -> $score (recorded for the operator; not a benchmark claim)"
    }

    $summary += [pscustomobject]@{ Id = $id; Status = $status; Report = $report }
}

Write-Host ''
Write-Host '===== Summary ====='
$summary | Format-Table -AutoSize | Out-String | Write-Host
if (-not $Execute) {
    Write-Host 'Dry run only - nothing executed. Re-run with -Execute to actually benchmark.'
}
Write-Host 'Scaffolding only: no results are asserted. Scores are recorded per target in eval/results/<id>/score.json for operator review.'
