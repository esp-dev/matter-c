param(
    [string]$Compiler = '',
    [ValidateRange(1, 300)][int]$Seconds = 20,
    [ValidateRange(1, 100000000)][int]$Runs = 1000000,
    [ValidateRange(1, 2147483647)][int]$Seed = 20261007,
    [switch]$ReplayOnly,
    [switch]$Sanitize,
    [string]$ReplayFile = ''
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
if ($ReplayFile -and !$ReplayOnly) { throw 'ReplayFile requires ReplayOnly' }
$repoDir = (Resolve-Path "$PSScriptRoot/../..").Path
if (!$Compiler) { $Compiler = 'clang' }
$compilerPath = (Get-Command $Compiler -CommandType Application | Select-Object -First 1).Source
$outDir = Join-Path $repoDir ('build/matter-fuzz/' + [guid]::NewGuid())
$corpusDir = Join-Path $outDir 'corpus'
New-Item -ItemType Directory -Path $corpusDir -Force | Out-Null
Write-Output "Fuzz artifacts: $outDir"
$savedPath = $env:PATH
$savedAsan = $env:ASAN_OPTIONS
$savedUbsan = $env:UBSAN_OPTIONS
try {
    $env:PATH = (Split-Path $compilerPath) + [IO.Path]::PathSeparator + $savedPath
    $flags = @('-std=c99', '-O1', '-g', '-Wall', '-Wextra', '-Werror')
    if (!$ReplayOnly -or $Sanitize) {
        $flags += @('-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer')
        $env:ASAN_OPTIONS = 'halt_on_error=1:detect_leaks=0'
        $env:UBSAN_OPTIONS = 'halt_on_error=1:print_stacktrace=1'
    }
    $linkFlags = @()
    if ($ReplayOnly) { $flags += '-DMATTER_FUZZ_STANDALONE' }
    else {
        $target = & $compilerPath -dumpmachine
        if ($LASTEXITCODE -ne 0) { throw 'Cannot determine compiler target' }
        if ($target -eq 'x86_64-w64-windows-gnu') {
            # LLVM-MinGW ships libFuzzer, but its driver rejects -fsanitize=fuzzer.
            # Use the same coverage instrumentation and link the real runtime.
            $resourceDir = & $compilerPath -print-resource-dir
            if ($LASTEXITCODE -ne 0) { throw 'Cannot locate compiler runtime' }
            $runtime = Join-Path $resourceDir 'lib/windows/libclang_rt.fuzzer-x86_64.a'
            if (!(Test-Path -LiteralPath $runtime)) { throw "Missing libFuzzer runtime: $runtime" }
            $flags += '-fsanitize-coverage=inline-8bit-counters,pc-table,trace-cmp'
            $linkFlags = @($runtime, '-lc++')
        } else { $flags += '-fsanitize=fuzzer' }
    }
    $version = & $compilerPath --version
    if ($LASTEXITCODE -ne 0) { throw 'Compiler unavailable' }
    $version | Write-Output
    $sources = @('matter_tlv.c','matter_tlv_writer.c','matter_tlv_validate.c') |
        ForEach-Object { "$repoDir/main/apps/matter/codec/$_" }
    $exe = Join-Path $outDir 'fuzz_tlv.exe'
    & $compilerPath @flags -I "$repoDir/main/apps/matter" @sources "$PSScriptRoot/fuzz/fuzz_tlv.c" @linkFlags -o $exe
    if ($LASTEXITCODE -ne 0) { throw 'Fuzz/replay compilation failed; no uninstrumented fallback' }
    foreach ($line in Get-Content -LiteralPath "$PSScriptRoot/fuzz/seeds.txt") {
        if (!$line.Trim() -or $line.StartsWith('#')) { continue }
        if ($line -notmatch '^([a-z0-9-]+)\|([0-9a-f]+)$' -or ($Matches[2].Length % 2)) { throw "Bad seed: $line" }
        $path = Join-Path $corpusDir $Matches[1]
        $hex = $Matches[2]
        $bytes = [byte[]]::new($hex.Length / 2)
        for ($i = 0; $i -lt $bytes.Length; ++$i) { $bytes[$i] = [Convert]::ToByte($hex.Substring(2*$i,2),16) }
        if ($bytes.Length -gt 4096 -or (Test-Path -LiteralPath $path)) { throw 'Invalid seed size/name' }
        [IO.File]::WriteAllBytes($path, $bytes)
    }
    $seedFiles = @(Get-ChildItem -LiteralPath $corpusDir -File | Sort-Object Name)
    if ($ReplayOnly) {
        $arguments = @($seedFiles.FullName)
        if ($ReplayFile) { $arguments = @((Resolve-Path -LiteralPath $ReplayFile).Path) }
    } else {
        $arguments = @($corpusDir, "-seed=$Seed", "-runs=$Runs", "-max_total_time=$Seconds",
            '-max_len=4096', '-len_control=0', '-timeout=5', '-rss_limit_mb=512',
            '-malloc_limit_mb=32', '-detect_leaks=0', '-print_final_stats=1',
            "-artifact_prefix=$($outDir.Replace('\','/'))/")
    }
    $log = Join-Path $outDir 'run.log'
    $clock = [Diagnostics.Stopwatch]::StartNew()
    & $exe @arguments > $log 2>&1
    $result = $LASTEXITCODE
    $clock.Stop()
    $sourceHashes = @(@($sources) + @("$PSScriptRoot/fuzz/fuzz_tlv.c") | ForEach-Object {
        @{ path=$_; sha256=(Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash }
    })
    [ordered]@{ compiler=$compilerPath; compilerVersion=$version; sources=$sourceHashes;
        flags=$flags; linkFlags=$linkFlags; arguments=$arguments; exitCode=$result;
        elapsedSeconds=$clock.Elapsed.TotalSeconds; seedCount=$seedFiles.Count;
        seedManifestSha256=(Get-FileHash "$PSScriptRoot/fuzz/seeds.txt" -Algorithm SHA256).Hash } |
        ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $outDir 'run.json')
    Get-Content -LiteralPath $log -Tail 18
    if ($result -ne 0) { throw "Fuzz/replay failed ($result); preserve corpus/artifacts: $outDir" }
    if (!$ReplayOnly -and !(Select-String -LiteralPath $log -Pattern 'DONE.*cov:' -Quiet)) {
        throw "No coverage-guided completion evidence; inspect $log"
    }
    Write-Output "PASS fuzz/replay; elapsed $($clock.Elapsed.TotalSeconds.ToString('F2')) s; $log"
} finally {
    $env:PATH = $savedPath
    $env:ASAN_OPTIONS = $savedAsan
    $env:UBSAN_OPTIONS = $savedUbsan
}
