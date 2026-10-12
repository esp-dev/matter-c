param([switch]$Sanitize, [string]$Compiler = 'gcc')
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$repoDir = (Resolve-Path "$PSScriptRoot/../..").Path
if ($Sanitize -and !$PSBoundParameters.ContainsKey('Compiler')) {
    $Compiler = 'clang'
}
$compilerPath = (Get-Command $Compiler -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$out = "$repoDir/build/discovery-tests/" + [guid]::NewGuid()
New-Item -ItemType Directory -Force $out | Out-Null
$savedPath=$env:PATH; $savedAsan=$env:ASAN_OPTIONS; $savedUbsan=$env:UBSAN_OPTIONS
try {
    $env:PATH=(Split-Path $compilerPath)+[IO.Path]::PathSeparator+$savedPath
    $flags=@('-std=c99','-Wall','-Wextra','-Werror','-g','-O1','-I',"$repoDir/main/apps/matter")
    if ($Sanitize) {
        $flags+=@('-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer')
        $env:ASAN_OPTIONS='halt_on_error=1:detect_leaks=0'; $env:UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1'
    }
    foreach ($variant in @('libc','alloc')) {
        $moduleFlags=@(); $testFlags=@()
        if ($variant -eq 'alloc') { $moduleFlags=@('-DMATTER_TEST_ALLOC_REPLACE','-include',"$PSScriptRoot/tests/alloc.h"); $testFlags=@('-DMATTER_TEST_ALLOC') }
        $objects=@()
        foreach ($source in @('matter','matter_mdns','matter_discovery')) {
            $object="$out/$source-$variant.o"
            & $compilerPath @flags @moduleFlags -c "$repoDir/main/apps/matter/$source.c" -o $object
            if ($LASTEXITCODE -ne 0) { throw "Compile failed: $source" }
            $objects+=$object
        }
        & $compilerPath @flags @testFlags "$PSScriptRoot/tests/test_discovery.c" @objects -lws2_32 -liphlpapi -lbcrypt -o "$out/test-$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw 'Discovery test build failed' }
        & "$out/test-$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Discovery test failed: $variant" }
        & $compilerPath @flags @testFlags "$PSScriptRoot/tests/test_mdns.c" @objects -o "$out/mdns-$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw 'Existing mDNS lifecycle test build failed' }
        & "$out/mdns-$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Existing mDNS lifecycle regression failed: $variant" }
    }
    Write-Output "Discovery test artifacts: $out"
} finally { $env:PATH=$savedPath; $env:ASAN_OPTIONS=$savedAsan; $env:UBSAN_OPTIONS=$savedUbsan }
