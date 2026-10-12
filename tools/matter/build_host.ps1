param(
    [string]$Compiler = 'gcc',
    [string]$VendorName = 'Matter C',
    [string]$ProductName = 'Matter C host simulation',
    [switch]$Sanitize,
    [switch]$Test,
    [string]$OutputDirectory,
    [string]$MbedtlsDir = "$PSScriptRoot/../../third_party/mbedtls"
)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$identityFlags = @()
foreach ($item in @(@('VENDOR_NAME', $VendorName), @('PRODUCT_NAME', $ProductName))) {
    $value = $item[1]
    $size = [Text.Encoding]::UTF8.GetByteCount($value)
    if ($size -lt 1 -or $size -gt 32 -or $value.IndexOfAny([char[]]@([char]0, [char]10, [char]13, [char]59)) -ge 0) {
        throw "$($item[0]) must contain 1..32 UTF-8 bytes without NUL, line breaks or semicolons"
    }
    $escaped = $value.Replace('\', '\\').Replace('"', '\"')
    $identityFlags += '-DMATTER_HOST_' + $item[0] + '="' + $escaped + '"'
}
$repoDir = (Resolve-Path "$PSScriptRoot/../..").Path
$mbedSource = (Resolve-Path $MbedtlsDir).Path
$dependency = (Get-Content -LiteralPath "$repoDir/cmake/dependencies.json" -Raw | ConvertFrom-Json).mbedtls
$revision = & git -C $mbedSource -c "safe.directory=$($mbedSource.Replace('\', '/'))" rev-parse HEAD
if ($LASTEXITCODE -ne 0 -or $revision -ne $dependency.revision) { throw 'Unexpected mbedTLS revision' }
& git -C $mbedSource -c "safe.directory=$($mbedSource.Replace('\', '/'))" diff --quiet HEAD -- include library
if ($LASTEXITCODE -ne 0) { throw 'Modified mbedTLS sources' }
if ($Sanitize -and !$PSBoundParameters.ContainsKey('Compiler')) {
    $Compiler = 'clang'
}
$compilerPath = (Get-Command $Compiler -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$out = "$repoDir/build/matter-host/" + $(if ($Sanitize) { 'sanitize' } else { 'gcc' })
if ($OutputDirectory) { $out = [IO.Path]::GetFullPath($OutputDirectory).Replace('\', '/') }
New-Item -ItemType Directory -Force $out | Out-Null
$savedPath = $env:PATH
try {
    $env:PATH = (Split-Path $compilerPath) + [IO.Path]::PathSeparator + $savedPath
    $flags = @('-std=c99', '-Wall', '-Wextra', '-Werror', '-g', '-O1', '-ffunction-sections', '-fdata-sections',
        '-DMATTER_TRANSPORT_CAPACITY=56', '-DMATTER_EVENTS_CAPACITY=128',
        '-I', "$repoDir/main/apps/matter", '-I', "$PSScriptRoot/host", '-I', "$mbedSource/include", '-DMBEDTLS_CONFIG_FILE="matter_mbedtls_config.h"')
    if ($Sanitize) { $flags += @('-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer') }
    # Explicit host composition. No firmware registration or test fixture linkage.
    $sourceManifest = Get-Content -Raw "$repoDir/cmake/sources.json" | ConvertFrom-Json
    $sources = @($sourceManifest.core) + @($sourceManifest.runtime)
    $objects = @()
    foreach ($source in $sources) {
        $object = "$out/" + $source.Replace('/', '_') + '.o'
        & $compilerPath @flags -c "$repoDir/main/apps/matter/$source.c" -o $object
        if ($LASTEXITCODE -ne 0) { throw "Compile failed: $source" }
        $objects += $object
    }
    foreach ($source in $sourceManifest.host_windows) {
        $object = "$out/$source.o"
        & $compilerPath @flags -c "$PSScriptRoot/host/$source.c" -o $object
        if ($LASTEXITCODE -ne 0) { throw "Compile failed: $source" }
        $objects += $object
    }
    foreach ($source in $sourceManifest.mbedtls) {
        $object = "$out/mbedtls_$source.o"
        $warnings = @()
        if ($source -eq 'x509_crt' -and $compilerPath -match 'clang') { $warnings = @('-Wno-error=uninitialized-const-pointer') }
        & $compilerPath @flags @warnings -c "$mbedSource/library/$source.c" -o $object
        if ($LASTEXITCODE -ne 0) { throw "Compile failed: mbedTLS/$source" }
        $objects += $object
    }
    & $compilerPath @flags @identityFlags "$PSScriptRoot/host/matter_node.c" @objects '-Wl,--gc-sections' '-Wl,--stack,8388608' `
        -lws2_32 -liphlpapi -lbcrypt -o "$out/matter-node.exe"
    if ($LASTEXITCODE -ne 0) { throw 'Host link failed' }
    Write-Output "Host executable: $out/matter-node.exe"
    if ($Test) {
        & $compilerPath @flags "$PSScriptRoot/tests/test_switch_sim.c" @objects '-Wl,--gc-sections' -lws2_32 -liphlpapi -lbcrypt -o "$out/test-switch-sim.exe"
        if ($LASTEXITCODE -ne 0) { throw 'Switch simulation test compile failed' }
        & "$out/test-switch-sim.exe"
        if ($LASTEXITCODE -ne 0) { throw 'Switch simulation test failed' }
        $clockObjects = @($objects | Where-Object { [IO.Path]::GetFileName($_) -ne 'runtime_matter_runtime.o' })
        & $compilerPath @flags "$PSScriptRoot/tests/test_server_time.c" @clockObjects '-Wl,--gc-sections' -lws2_32 -liphlpapi -lbcrypt -o "$out/test-server-time.exe"
        if ($LASTEXITCODE -ne 0) { throw 'Host clock test compile failed' }
        & "$out/test-server-time.exe"
        if ($LASTEXITCODE -ne 0) { throw 'Host clock test failed' }
        foreach ($variant in @('libc', 'alloc')) {
            $updateObjects = $objects
            $testFlags = @()
            if ($variant -eq 'alloc') {
                $testFlags = @('-DMATTER_TEST_ALLOC')
                $updateObjects = @($objects | Where-Object { [IO.Path]::GetFileName($_) -notin @('clusters_matter_ota_update.o','matter_ota_file.o') })
                foreach ($source in @('main/apps/matter/clusters/matter_ota_update', 'tools/matter/host/matter_ota_file')) {
                    $object = "$out/update-alloc-$([IO.Path]::GetFileName($source)).o"
                    & $compilerPath @flags '-Dcalloc=matter_test_calloc' '-Dmalloc=matter_test_malloc' '-Dfree=matter_test_free' -c "$repoDir/$source.c" -o $object
                    if ($LASTEXITCODE -ne 0) { throw 'Update allocation compile failed' }
                    $updateObjects += $object
                }
            }
            & $compilerPath @flags @testFlags "$PSScriptRoot/tests/test_ota_update.c" @updateObjects '-Wl,--gc-sections' -lws2_32 -liphlpapi -lbcrypt -o "$out/test-ota-update-$variant.exe"
            if ($LASTEXITCODE -ne 0) { throw 'Update test link failed' }
            & "$out/test-ota-update-$variant.exe" "$out/ota-update.tlv"
            if ($LASTEXITCODE -ne 0) { throw 'Update tests failed' }
        }
        foreach ($variant in @('libc', 'alloc')) {
            $applyObjects = $objects
            $testFlags = @()
            if ($variant -eq 'alloc') {
                $testFlags = @('-DMATTER_TEST_ALLOC')
                $applyObjects = @($objects | Where-Object { [IO.Path]::GetFileName($_) -ne 'clusters_matter_ota_apply.o' })
                $object = "$out/alloc_clusters_matter_ota_apply.o"
                & $compilerPath @flags '-DMATTER_TEST_ALLOC_REPLACE' -include "$PSScriptRoot/tests/alloc.h" -c "$repoDir/main/apps/matter/clusters/matter_ota_apply.c" -o $object
                if ($LASTEXITCODE -ne 0) { throw 'Apply allocation compile failed' }
                $applyObjects += $object
            }
            & $compilerPath @flags @testFlags "$PSScriptRoot/tests/test_ota_apply.c" @applyObjects '-Wl,--gc-sections' -lws2_32 -liphlpapi -lbcrypt -o "$out/test-ota-apply-$variant.exe"
            if ($LASTEXITCODE -ne 0) { throw 'Apply test link failed' }
            & "$out/test-ota-apply-$variant.exe"
            if ($LASTEXITCODE -ne 0) { throw 'Apply tests failed' }
        }
        & $compilerPath @flags "$PSScriptRoot/tests/test_bdx.c" @objects '-Wl,--gc-sections' -lws2_32 -liphlpapi -lbcrypt -o "$out/test-bdx.exe"
        if ($LASTEXITCODE -ne 0) { throw 'BDX compile failed' }
        & "$out/test-bdx.exe" "$out/bdx-test.ota"
        if ($LASTEXITCODE -ne 0) { throw 'BDX test failed' }
        $bdxObjects = @($objects | Where-Object { [IO.Path]::GetFileName($_) -notin @('transport_matter_bdx.o','matter_ota_file.o') })
        foreach ($source in @("$repoDir/main/apps/matter/transport/matter_bdx.c", "$PSScriptRoot/host/matter_ota_file.c")) {
            $obj = "$out/$([IO.Path]::GetFileNameWithoutExtension($source))-alloc.o"
            & $compilerPath @flags '-Dcalloc=matter_test_calloc' '-Dmalloc=matter_test_malloc' '-Dfree=matter_test_free' -c $source -o $obj
            if ($LASTEXITCODE -ne 0) { throw 'BDX allocation compile failed' }
            $bdxObjects += $obj
        }
        & $compilerPath @flags '-DMATTER_TEST_ALLOC' "$PSScriptRoot/tests/test_bdx.c" @bdxObjects '-Wl,--gc-sections' -lws2_32 -liphlpapi -lbcrypt -o "$out/test-bdx-alloc.exe"
        if ($LASTEXITCODE -ne 0) { throw 'BDX allocation link failed' }
        & "$out/test-bdx-alloc.exe" "$out/bdx-test.ota"
        if ($LASTEXITCODE -ne 0) { throw 'BDX allocation test failed' }
        & $compilerPath @flags "$PSScriptRoot/tests/test_ota_query.c" @objects '-Wl,--gc-sections' -lws2_32 -liphlpapi -lbcrypt -o "$out/test-ota-query.exe"
        if ($LASTEXITCODE -ne 0) { throw 'OTA query test link failed' }
        & "$out/test-ota-query.exe"
        if ($LASTEXITCODE -ne 0) { throw 'OTA query tests failed' }
        $queryObjects = $objects | Where-Object { [IO.Path]::GetFileNameWithoutExtension($_) -notin @('clusters_matter_ota_query', 'model_matter_im_client') }
        foreach ($source in @('clusters/matter_ota_query', 'model/matter_im_client')) {
            $object = "$out/alloc_" + $source.Replace('/', '_') + '.o'
            & $compilerPath @flags '-DMATTER_TEST_ALLOC_REPLACE' -include "$PSScriptRoot/tests/alloc.h" -c "$repoDir/main/apps/matter/$source.c" -o $object
            if ($LASTEXITCODE -ne 0) { throw "Query allocation compile failed: $source" }
            $queryObjects += $object
        }
        & $compilerPath @flags '-DMATTER_TEST_ALLOC' "$PSScriptRoot/tests/test_ota_query.c" @queryObjects '-Wl,--gc-sections' -lws2_32 -liphlpapi -lbcrypt -o "$out/test-ota-query-alloc.exe"
        if ($LASTEXITCODE -ne 0) { throw 'Query allocation test link failed' }
        & "$out/test-ota-query-alloc.exe"
        if ($LASTEXITCODE -ne 0) { throw 'Query allocation tests failed' }
        foreach ($variant in @('libc', 'alloc')) {
            $otaObjects = $objects
            $testFlags = @()
            if ($variant -eq 'alloc') {
                $testFlags = @('-DMATTER_TEST_ALLOC')
                $replaced = @('clusters_matter_ota_requestor', 'model_matter_cluster', 'model_matter_events')
                $otaObjects = $objects | Where-Object { [IO.Path]::GetFileNameWithoutExtension($_) -notin $replaced }
                foreach ($source in @('clusters/matter_ota_requestor', 'model/matter_cluster', 'model/matter_events')) {
                    $object = "$out/alloc_" + $source.Replace('/', '_') + '.o'
                    & $compilerPath @flags '-DMATTER_TEST_ALLOC_REPLACE' -include "$PSScriptRoot/tests/alloc.h" -c "$repoDir/main/apps/matter/$source.c" -o $object
                    if ($LASTEXITCODE -ne 0) { throw "OTA allocation compile failed: $source" }
                    $otaObjects += $object
                }
            }
            & $compilerPath @flags @testFlags "$PSScriptRoot/tests/test_ota_requestor.c" @otaObjects '-Wl,--gc-sections' -lws2_32 -liphlpapi -lbcrypt -o "$out/test-ota-$variant.exe"
            if ($LASTEXITCODE -ne 0) { throw 'OTA test link failed' }
            & "$out/test-ota-$variant.exe"
            if ($LASTEXITCODE -ne 0) { throw "OTA test failed: $variant" }
        }
        & $compilerPath @flags "$PSScriptRoot/tests/test_im_write.c" @objects '-Wl,--gc-sections' -lws2_32 -liphlpapi -lbcrypt -o "$out/test-im-write.exe"
        if ($LASTEXITCODE -ne 0) { throw 'IM Write test link failed' }
        & "$out/test-im-write.exe"
        if ($LASTEXITCODE -ne 0) { throw 'IM Write tests failed' }
        & $compilerPath @flags "$PSScriptRoot/tests/test_store_file_windows.c" @objects '-Wl,--gc-sections' -lws2_32 -liphlpapi -lbcrypt -o "$out/test-store-file.exe"
        if ($LASTEXITCODE -ne 0) { throw 'Windows file test link failed' }
        & "$out/test-store-file.exe" "$out/file-lock-$([Guid]::NewGuid().ToString('N')).tlv"
        if ($LASTEXITCODE -ne 0) { throw 'Windows file tests failed' }
        & $compilerPath @flags "$PSScriptRoot/tests/test_store.c" @objects '-Wl,--gc-sections' -lws2_32 -liphlpapi -lbcrypt -o "$out/test-store.exe"
        if ($LASTEXITCODE -ne 0) { throw 'Store test link failed' }
        foreach ($mode in @('committed', 'pending')) {
            foreach ($phase in @('seed', 'load')) {
                & "$out/test-store.exe" $phase "$out/ota-store-$mode.tlv" $mode
                if ($LASTEXITCODE -ne 0) { throw "Store test failed: $mode $phase" }
            }
        }
        & $compilerPath @flags "$PSScriptRoot/tests/test_case_mrp.c" @objects '-Wl,--gc-sections' '-Wl,--stack,8388608' `
            -lws2_32 -liphlpapi -lbcrypt -o "$out/test-case-mrp.exe"
        if ($LASTEXITCODE -ne 0) { throw 'CASE/MRP test link failed' }
        & "$out/test-case-mrp.exe"
        if ($LASTEXITCODE -ne 0) { throw 'CASE/MRP tests failed' }
        $testObjects = $objects | Where-Object { $_ -ne "$out/runtime_matter_dispatch.o" }
        & $compilerPath @flags "$PSScriptRoot/tests/test_dispatch.c" @testObjects '-Wl,--gc-sections' '-Wl,--stack,8388608' `
            -lws2_32 -liphlpapi -lbcrypt -o "$out/test-dispatch.exe"
        if ($LASTEXITCODE -ne 0) { throw 'Dispatcher test link failed' }
        & "$out/test-dispatch.exe"
        if ($LASTEXITCODE -ne 0) { throw 'Dispatcher tests failed' }
    }
} finally { $env:PATH = $savedPath }
