<#
.SYNOPSIS
    Phase 1 evidence sweep: run the matrix over every archived build and emit the raw CSVs the
    classifier (analysis/manifest.py) consumes. Replaces the ad-hoc scratchpad driver.

.DESCRIPTION
    For each target build runs:
        Harness --build <B> --matrix --sample 1500 --seed 1 --version-path-first
                --csv    baseline/matrix/matrix-<B>.csv
                --out    baseline/matrix/matrix-<B>.md
                --fields baseline/matrix/fields-<B>.csv

    Build 12 (V12) is swept LAST — it is by far the largest corpus. The sweep is idempotent: a build
    whose matrix-<B>.csv already exists is skipped, so an interrupted run resumes cheaply.

    Determinism: --sample/--seed fix a reservoir sample that is byte-identical for a given seed, so
    re-running reproduces the committed evidence exactly. Re-stamp verdicts with analysis/manifest.py.

.PARAMETER OutDir
    Where the matrix/fields/report files land. Default: baseline/matrix next to this script.

.PARAMETER Sample
    Packets per (opcode, direction) reservoir sample. Default 1500.

.PARAMETER Seed
    Reservoir RNG seed, recorded in every CSV. Default 1.

.PARAMETER Force
    Re-run builds even when their matrix-<B>.csv already exists (overwrites).
#>
[CmdletBinding()]
param(
    [string]$OutDir,
    [int]$Sample = 1500,
    [int]$Seed = 1,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$project = Join-Path $here 'Harness.csproj'
if (-not $OutDir) { $OutDir = Join-Path $here 'baseline/matrix' }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# All 42 archived builds. 12 (V12) is last — largest corpus, so the cheap builds land first and an
# interrupted run has done the most edges by the time it reaches the expensive one.
$builds = @(
    2464, 2465, 2486, 2489, 2490, 2491, 2492, 2493, 2495, 2496, 2497, 2500, 2502, 2503, 2504,
    2506, 2507, 2509, 2511, 2512, 2513, 2514, 2516, 2517, 2518, 2520, 2521, 2522, 2524, 2525,
    2527, 2528, 2529, 2530, 2531, 2532, 2533, 2538, 2546, 2549, 2550,
    12
)

Write-Host "Building Harness (Release)..." -ForegroundColor Cyan
dotnet build $project -c Release | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Harness build failed" }

$log = Join-Path $OutDir 'sweep.log'
Remove-Item -Path $log -ErrorAction SilentlyContinue
$swAll = [System.Diagnostics.Stopwatch]::StartNew()

foreach ($b in $builds) {
    $csv = Join-Path $OutDir "matrix-$b.csv"
    $md = Join-Path $OutDir "matrix-$b.md"
    $fields = Join-Path $OutDir "fields-$b.csv"

    if ((Test-Path $csv) -and -not $Force) {
        Write-Host "skip  build $b (matrix-$b.csv exists)" -ForegroundColor DarkGray
        continue
    }

    Write-Host "sweep build $b ..." -ForegroundColor Yellow -NoNewline
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Add-Content -Path $log -Value "===== build $b ====="

    dotnet run --project $project -c Release --no-build -- `
        --build $b --matrix --sample $Sample --seed $Seed --version-path-first `
        --csv $csv --out $md --fields $fields 2>> $log | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sweep failed for build $b (see $log)" }

    $sw.Stop()
    Write-Host (" done in {0:N1}s" -f $sw.Elapsed.TotalSeconds) -ForegroundColor Green
}

$swAll.Stop()
Write-Host ("sweep complete in {0:N1}s -> {1}" -f $swAll.Elapsed.TotalSeconds, $OutDir) -ForegroundColor Cyan
Write-Host "Next: py analysis/manifest.py --out $OutDir/manifest.csv" -ForegroundColor Cyan
