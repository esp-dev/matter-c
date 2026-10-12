param(
    [string]$Compiler = 'gcc',
    [switch]$Sanitize,
    [switch]$HostUdp,
    [string]$MbedtlsDir = "$PSScriptRoot/../../third_party/mbedtls"
)

$ErrorActionPreference = 'Stop'
# Check native exit codes explicitly, including the intentional failing probes.
$PSNativeCommandUseErrorActionPreference = $false
$repoDir = (Resolve-Path "$PSScriptRoot/../..").Path
$mbedSource = (Resolve-Path $MbedtlsDir -ErrorAction Stop).Path
$dependency = (Get-Content -LiteralPath "$repoDir/cmake/dependencies.json" -Raw | ConvertFrom-Json).mbedtls
$mbedRevision = & git -C $mbedSource -c "safe.directory=$($mbedSource.Replace('\', '/'))" rev-parse HEAD
if ($LASTEXITCODE -ne 0 -or $mbedRevision -ne $dependency.revision) {
    throw 'Expected official upstream mbedTLS revision from cmake/dependencies.json. See README.md.'
}
& git -C $mbedSource -c "safe.directory=$($mbedSource.Replace('\', '/'))" diff --quiet HEAD -- include library
if ($LASTEXITCODE -ne 0) { throw 'mbedTLS headers/library differ from the pinned revision.' }
if ($Sanitize -and !$PSBoundParameters.ContainsKey('Compiler')) {
    $Compiler = 'clang'
}
$compilerPath = (Get-Command $Compiler -CommandType Application -ErrorAction Stop |
    Select-Object -First 1).Source
$testDir = Join-Path $repoDir ('build/matter-tests/' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $testDir -Force | Out-Null
Write-Output "Test artifacts: $testDir"

# MSYS2 compiler subprocesses need their DLL directory. Restore the caller's PATH.
$savedPath = $env:PATH
$savedAsan = $env:ASAN_OPTIONS
$savedUbsan = $env:UBSAN_OPTIONS
$savedStoreDir = $env:MATTER_TEST_STORE_DIR
$sourceManifest = Get-Content -Raw "$repoDir/cmake/sources.json" | ConvertFrom-Json
$sanitizerFlags = @()
try {
    $env:MATTER_TEST_STORE_DIR = $testDir
    $env:PATH = (Split-Path $compilerPath) + [IO.Path]::PathSeparator + $savedPath
    if ($Sanitize) {
        $sanitizerFlags = @('-fsanitize=address,undefined', '-fno-sanitize-recover=all',
            '-fno-omit-frame-pointer', '-g', '-O1')
        # LeakSanitizer is not supported by this Windows runtime.
        $env:ASAN_OPTIONS = 'halt_on_error=1:detect_leaks=0'
        $env:UBSAN_OPTIONS = 'halt_on_error=1:print_stacktrace=1'
    }
    & $compilerPath --version
    if ($LASTEXITCODE -ne 0) { throw 'Cannot run compiler' }
    & $compilerPath -dumpmachine
    if ($LASTEXITCODE -ne 0) { throw 'Cannot determine compiler target' }

    # Product list.c/test_list.c remain outside the library export.

    # Exercise normal libc first, then inject OOM and track allocation balance.
    # Replacement macros apply only to matter.c, following tools/https tests.
    foreach ($variant in @('libc', 'alloc')) {
        $moduleFlags = @()
        $testFlags = @()
        if ($variant -eq 'alloc') {
            $moduleFlags = @('-DMATTER_TEST_ALLOC_REPLACE', '-include', "$PSScriptRoot/tests/alloc.h")
            $testFlags = @('-DMATTER_TEST_ALLOC')
        }
        $cryptoFlags = @('-DMBEDTLS_CONFIG_FILE="matter_mbedtls_config.h"',
            '-I', "$PSScriptRoot/host", '-I', "$mbedSource/include")
        $cryptoObjects = @()
        foreach ($source in $sourceManifest.mbedtls) {
            $object = "$testDir/mbedtls_${source}_$variant.o"
            $sourceWarnings = @()
            if ($source -eq 'x509_crt' -and $compilerPath -match 'clang') {
                # Pinned 3.6.0 passes &now but never reads it with HAVE_TIME_DATE
                # disabled (x509_crt_find_parent_in). Our callback checks explicit
                # application time. Keep Clang 23's diagnostic visible, SDK untouched.
                $sourceWarnings = @('-Wno-error=uninitialized-const-pointer')
            }
            & $compilerPath -std=gnu99 -Wall -Wextra -Werror @sourceWarnings @sanitizerFlags @moduleFlags @cryptoFlags `
                -c "$mbedSource/library/$source.c" -o $object
            if ($LASTEXITCODE -ne 0) { throw "mbedTLS $source compilation failed: $variant" }
            $cryptoObjects += $object
        }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags @cryptoFlags `
            -c "$repoDir/main/apps/matter/crypto/matter_crypto_mbedtls.c" -o "$testDir/crypto_mbedtls_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "Crypto backend compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
            -I "$repoDir/main/apps/matter" "$PSScriptRoot/tests/test_crypto_mbedtls.c" `
            "$testDir/crypto_mbedtls_$variant.o" @cryptoObjects -lbcrypt -lws2_32 -o "$testDir/test_crypto_mbedtls_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Crypto backend tests compilation failed: $variant" }
        & "$testDir/test_crypto_mbedtls_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Crypto backend tests failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
            -I "$repoDir/main/apps/matter" "$PSScriptRoot/tests/test_credentials.c" `
            "$testDir/crypto_mbedtls_$variant.o" @cryptoObjects -lbcrypt -lws2_32 -o "$testDir/test_credentials_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Credentials tests compilation failed: $variant" }
        & "$testDir/test_credentials_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Credentials tests failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags @cryptoFlags `
            -c "$repoDir/main/apps/matter/crypto/matter_operational_cert.c" -o "$testDir/operational_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "Operational certificate compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
            -I "$repoDir/main/apps/matter" "$PSScriptRoot/tests/test_operational_cert.c" `
            "$repoDir/main/apps/matter/codec/matter_tlv.c" "$testDir/operational_$variant.o" `
            "$testDir/crypto_mbedtls_$variant.o" @cryptoObjects -lbcrypt -lws2_32 -o "$testDir/test_operational_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Operational certificate test compilation failed: $variant" }
        & "$testDir/test_operational_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Operational certificate tests failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags @cryptoFlags `
            -c "$repoDir/main/apps/matter/crypto/matter_attestation_cert.c" -o "$testDir/attestation_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "Attestation certificate compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
            -I "$repoDir/main/apps/matter" "$PSScriptRoot/tests/test_attestation_cert.c" `
            "$testDir/attestation_$variant.o" "$testDir/crypto_mbedtls_$variant.o" @cryptoObjects `
            -lbcrypt -lws2_32 -o "$testDir/test_attestation_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Attestation certificate test compilation failed: $variant" }
        & "$testDir/test_attestation_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Attestation certificate tests failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -I "$repoDir/main/apps/matter" -c "$repoDir/main/apps/matter/crypto/matter_spake2p.c" -o "$testDir/spake2p_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "SPAKE2+ compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
            -I "$repoDir/main/apps/matter" "$PSScriptRoot/tests/test_spake2p.c" `
            "$testDir/spake2p_$variant.o" "$testDir/crypto_mbedtls_$variant.o" @cryptoObjects -lbcrypt -lws2_32 -o "$testDir/test_spake2p_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "SPAKE2+ test compilation failed: $variant" }
        & "$testDir/test_spake2p_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "SPAKE2+ tests failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/matter.c" -o "$testDir/matter_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "Matter compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
            -I "$repoDir/main/apps/matter" "$PSScriptRoot/tests/test_lifecycle.c" `
            "$testDir/matter_$variant.o" -o "$testDir/test_lifecycle_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Lifecycle test compilation failed: $variant" }
        & "$testDir/test_lifecycle_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Lifecycle tests failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/matter_mdns.c" -o "$testDir/mdns_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "mDNS compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
            -I "$repoDir/main/apps/matter" "$PSScriptRoot/tests/test_mdns.c" `
            "$testDir/matter_$variant.o" "$testDir/mdns_$variant.o" -o "$testDir/test_mdns_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "mDNS test compilation failed: $variant" }
        & "$testDir/test_mdns_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "mDNS tests failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/matter_udp.c" -o "$testDir/udp_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "UDP compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
            -I "$repoDir/main/apps/matter" "$PSScriptRoot/tests/test_udp.c" `
            "$testDir/matter_$variant.o" "$testDir/udp_$variant.o" -o "$testDir/test_udp_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "UDP test compilation failed: $variant" }
        & "$testDir/test_udp_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "UDP tests failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/transport/matter_exchange.c" -o "$testDir/exchange_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "Exchange compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
            -I "$repoDir/main/apps/matter" "$PSScriptRoot/tests/test_exchange.c" `
            "$repoDir/main/apps/matter/codec/matter_protocol_header.c" `
            "$testDir/matter_$variant.o" "$testDir/exchange_$variant.o" -o "$testDir/test_exchange_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Exchange test compilation failed: $variant" }
        & "$testDir/test_exchange_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Exchange tests failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/transport/matter_rx_policy.c" -o "$testDir/rx_policy_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "RX policy compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
            -I "$repoDir/main/apps/matter" "$PSScriptRoot/tests/test_rx_policy.c" `
            "$repoDir/main/apps/matter/codec/matter_protocol_header.c" "$testDir/matter_$variant.o" `
            "$testDir/exchange_$variant.o" "$testDir/rx_policy_$variant.o" -o "$testDir/test_rx_policy_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "RX policy test compilation failed: $variant" }
        & "$testDir/test_rx_policy_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "RX policy tests failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/transport/matter_ack.c" -o "$testDir/ack_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "ACK compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
            -I "$repoDir/main/apps/matter" "$PSScriptRoot/tests/test_ack.c" `
            "$testDir/ack_$variant.o" -o "$testDir/test_ack_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "ACK test compilation failed: $variant" }
        & "$testDir/test_ack_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "ACK tests failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/transport/matter_ack_sender.c" -o "$testDir/ack_sender_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "ACK sender compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
            -I "$repoDir/main/apps/matter" "$PSScriptRoot/tests/test_ack_sender.c" `
            "$repoDir/main/apps/matter/codec/matter_protocol_header.c" `
            "$testDir/ack_$variant.o" "$testDir/ack_sender_$variant.o" -o "$testDir/test_ack_sender_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "ACK sender test compilation failed: $variant" }
        & "$testDir/test_ack_sender_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "ACK sender tests failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
            -I "$repoDir/main/apps/matter" "$PSScriptRoot/tests/test_exchange_close.c" `
            "$repoDir/main/apps/matter/codec/matter_protocol_header.c" "$testDir/matter_$variant.o" `
            "$testDir/exchange_$variant.o" "$testDir/rx_policy_$variant.o" `
            "$testDir/ack_$variant.o" "$testDir/ack_sender_$variant.o" -o "$testDir/test_exchange_close_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Exchange close test compilation failed: $variant" }
        & "$testDir/test_exchange_close_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Exchange close tests failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/transport/matter_rx.c" -o "$testDir/rx_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "RX executor compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
            -I "$repoDir/main/apps/matter" "$PSScriptRoot/tests/test_rx.c" `
            "$repoDir/main/apps/matter/codec/matter_protocol_header.c" "$testDir/matter_$variant.o" `
            "$testDir/udp_$variant.o" "$testDir/exchange_$variant.o" "$testDir/rx_policy_$variant.o" `
            "$testDir/ack_$variant.o" "$testDir/ack_sender_$variant.o" "$testDir/rx_$variant.o" `
            -o "$testDir/test_rx_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "RX executor test compilation failed: $variant" }
        & "$testDir/test_rx_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "RX executor tests failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/transport/matter_retransmission.c" -o "$testDir/retransmission_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "Retransmission compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
            -I "$repoDir/main/apps/matter" "$PSScriptRoot/tests/test_retransmission.c" `
            "$repoDir/main/apps/matter/codec/matter_protocol_header.c" "$testDir/matter_$variant.o" `
            "$testDir/exchange_$variant.o" "$testDir/rx_policy_$variant.o" "$testDir/ack_$variant.o" `
            "$testDir/ack_sender_$variant.o" "$testDir/rx_$variant.o" "$testDir/retransmission_$variant.o" `
            -o "$testDir/test_retransmission_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Retransmission test compilation failed: $variant" }
        & "$testDir/test_retransmission_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Retransmission tests failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/transport/matter_retransmission_sender.c" -o "$testDir/retransmission_sender_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "Retransmission sender compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
            -I "$repoDir/main/apps/matter" "$PSScriptRoot/tests/test_retransmission_sender.c" `
            "$repoDir/main/apps/matter/codec/matter_protocol_header.c" "$testDir/ack_$variant.o" `
            "$testDir/ack_sender_$variant.o" "$testDir/retransmission_$variant.o" `
            "$testDir/retransmission_sender_$variant.o" -o "$testDir/test_retransmission_sender_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Retransmission sender test compilation failed: $variant" }
        & "$testDir/test_retransmission_sender_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Retransmission sender tests failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags `
            -c "$repoDir/main/apps/matter/transport/matter_reception.c" -o "$testDir/reception_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "Reception window compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags `
            -I "$repoDir/main/apps/matter" "$PSScriptRoot/tests/test_reception.c" `
            "$testDir/reception_$variant.o" -o "$testDir/test_reception_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Reception tests compilation failed: $variant" }
        & "$testDir/test_reception_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Reception tests failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags `
            -c "$repoDir/main/apps/matter/transport/matter_counter.c" -o "$testDir/counter_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "Outgoing counter compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags `
            -I "$repoDir/main/apps/matter" "$PSScriptRoot/tests/test_counter.c" `
            "$testDir/counter_$variant.o" -o "$testDir/test_counter_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Outgoing counter tests compilation failed: $variant" }
        & "$testDir/test_counter_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Outgoing counter tests failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/transport/matter_unsecured.c" -o "$testDir/unsecured_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "Unsecured compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
            -I "$repoDir/main/apps/matter" "$PSScriptRoot/tests/test_unsecured.c" `
            "$repoDir/main/apps/matter/codec/matter_message_header.c" `
            "$testDir/unsecured_$variant.o" "$testDir/reception_$variant.o" -o "$testDir/test_unsecured_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Unsecured tests compilation failed: $variant" }
        & "$testDir/test_unsecured_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Unsecured tests failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/transport/matter_unsecured_prepare.c" -o "$testDir/unsecured_prepare_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "Unsecured preparation compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
            -I "$repoDir/main/apps/matter" "$PSScriptRoot/tests/test_unsecured_prepare.c" `
            "$repoDir/main/apps/matter/codec/matter_message_header.c" `
            "$repoDir/main/apps/matter/codec/matter_protocol_header.c" "$testDir/unsecured_prepare_$variant.o" `
            "$testDir/counter_$variant.o" "$testDir/unsecured_$variant.o" "$testDir/reception_$variant.o" `
            -o "$testDir/test_unsecured_prepare_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Unsecured preparation tests compilation failed: $variant" }
        & "$testDir/test_unsecured_prepare_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Unsecured preparation tests failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/transport/matter_unsecured_rx.c" -o "$testDir/unsecured_rx_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "Unsecured RX compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
            -I "$repoDir/main/apps/matter" "$PSScriptRoot/tests/test_unsecured_rx.c" `
            "$repoDir/main/apps/matter/codec/matter_message_header.c" `
            "$repoDir/main/apps/matter/codec/matter_protocol_header.c" "$testDir/unsecured_rx_$variant.o" `
            "$testDir/unsecured_$variant.o" "$testDir/reception_$variant.o" "$testDir/matter_$variant.o" `
            "$testDir/rx_$variant.o" "$testDir/exchange_$variant.o" "$testDir/rx_policy_$variant.o" `
            "$testDir/ack_$variant.o" "$testDir/ack_sender_$variant.o" -o "$testDir/test_unsecured_rx_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Unsecured RX tests compilation failed: $variant" }
        & "$testDir/test_unsecured_rx_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Unsecured RX tests failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/transport/matter_unsecured_tx.c" -o "$testDir/unsecured_tx_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "Unsecured TX compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
            -I "$repoDir/main/apps/matter" "$PSScriptRoot/tests/test_unsecured_tx.c" `
            "$repoDir/main/apps/matter/codec/matter_message_header.c" "$testDir/unsecured_tx_$variant.o" `
            "$testDir/unsecured_$variant.o" "$testDir/reception_$variant.o" `
            "$testDir/udp_$variant.o" "$testDir/matter_$variant.o" -o "$testDir/test_unsecured_tx_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Unsecured TX tests compilation failed: $variant" }
        & "$testDir/test_unsecured_tx_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Unsecured TX tests failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
            -I "$repoDir/main/apps/matter" "$PSScriptRoot/tests/test_mrp_pair.c" `
            "$testDir/unsecured_rx_$variant.o" "$testDir/unsecured_prepare_$variant.o" `
            "$testDir/reception_$variant.o" "$testDir/counter_$variant.o" "$testDir/unsecured_$variant.o" `
            "$repoDir/main/apps/matter/codec/matter_message_header.c" `
            "$repoDir/main/apps/matter/codec/matter_protocol_header.c" "$testDir/matter_$variant.o" `
            "$testDir/exchange_$variant.o" "$testDir/rx_policy_$variant.o" "$testDir/ack_$variant.o" `
            "$testDir/ack_sender_$variant.o" "$testDir/rx_$variant.o" "$testDir/retransmission_$variant.o" `
            "$testDir/retransmission_sender_$variant.o" -o "$testDir/test_mrp_pair_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "MRP pair compilation failed: $variant" }
        & "$testDir/test_mrp_pair_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "MRP pair tests failed: $variant" }
        if ($HostUdp) {
            & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
                -I "$repoDir/main/apps/matter" -c "$PSScriptRoot/host/matter_udp_windows.c" `
                -o "$testDir/udp_windows_$variant.o"
            if ($LASTEXITCODE -ne 0) { throw "Windows UDP compilation failed: $variant" }
            & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
                -I "$repoDir/main/apps/matter" -I "$PSScriptRoot/host" `
                "$PSScriptRoot/tests/test_udp_windows.c" "$testDir/udp_windows_$variant.o" `
                "$testDir/matter_$variant.o" "$testDir/udp_$variant.o" -lws2_32 `
                -o "$testDir/test_udp_windows_$variant.exe"
            if ($LASTEXITCODE -ne 0) { throw "Windows UDP test compilation failed: $variant" }
            & "$testDir/test_udp_windows_$variant.exe"
            if ($LASTEXITCODE -ne 0) { throw "Windows UDP tests failed: $variant" }
            & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
                -I "$repoDir/main/apps/matter" -I "$PSScriptRoot/host" `
                "$PSScriptRoot/tests/test_unsecured_tx_windows.c" "$testDir/udp_windows_$variant.o" `
                "$repoDir/main/apps/matter/codec/matter_message_header.c" "$testDir/unsecured_tx_$variant.o" `
                "$testDir/unsecured_$variant.o" "$testDir/reception_$variant.o" `
                "$testDir/matter_$variant.o" "$testDir/udp_$variant.o" -lws2_32 `
                -o "$testDir/test_unsecured_tx_windows_$variant.exe"
            if ($LASTEXITCODE -ne 0) { throw "Windows unsecured TX test compilation failed: $variant" }
            & "$testDir/test_unsecured_tx_windows_$variant.exe"
            if ($LASTEXITCODE -ne 0) { throw "Windows unsecured TX tests failed: $variant" }
            & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
                -DMATTER_TEST_HOST_UDP -I "$repoDir/main/apps/matter" -I "$PSScriptRoot/host" `
                "$PSScriptRoot/tests/test_mrp_pair.c" "$testDir/udp_windows_$variant.o" `
                "$testDir/unsecured_rx_$variant.o" "$testDir/unsecured_prepare_$variant.o" `
                "$testDir/udp_$variant.o" "$testDir/unsecured_tx_$variant.o" `
                "$testDir/reception_$variant.o" "$testDir/counter_$variant.o" "$testDir/unsecured_$variant.o" `
                "$repoDir/main/apps/matter/codec/matter_message_header.c" `
                "$repoDir/main/apps/matter/codec/matter_protocol_header.c" "$testDir/matter_$variant.o" `
                "$testDir/exchange_$variant.o" "$testDir/rx_policy_$variant.o" "$testDir/ack_$variant.o" `
                "$testDir/ack_sender_$variant.o" "$testDir/rx_$variant.o" "$testDir/retransmission_$variant.o" `
                "$testDir/retransmission_sender_$variant.o" -lws2_32 -o "$testDir/test_mrp_pair_windows_$variant.exe"
            if ($LASTEXITCODE -ne 0) { throw "Windows MRP pair compilation failed: $variant" }
            & "$testDir/test_mrp_pair_windows_$variant.exe"
            if ($LASTEXITCODE -ne 0) { throw "Windows MRP pair tests failed: $variant" }
        }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/model/matter_events.c" -o "$testDir/events_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "Events compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/model/matter_im_read.c" -o "$testDir/im_read_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "IM read compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
            -I "$repoDir/main/apps/matter" "$PSScriptRoot/tests/test_im_read.c" "$testDir/im_read_$variant.o" "$testDir/events_$variant.o" `
            "$repoDir/main/apps/matter/codec/matter_tlv.c" "$repoDir/main/apps/matter/codec/matter_tlv_writer.c" `
            "$repoDir/main/apps/matter/codec/matter_tlv_validate.c" -o "$testDir/test_im_read_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "IM read tests compilation failed: $variant" }
        & "$testDir/test_im_read_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "IM read tests failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/model/matter_im_invoke.c" -o "$testDir/im_invoke_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "IM invoke compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
            -I "$repoDir/main/apps/matter" "$PSScriptRoot/tests/test_im_invoke.c" "$testDir/im_invoke_$variant.o" `
            "$repoDir/main/apps/matter/codec/matter_tlv.c" "$repoDir/main/apps/matter/codec/matter_tlv_writer.c" `
            "$repoDir/main/apps/matter/codec/matter_tlv_validate.c" -o "$testDir/test_im_invoke_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "IM invoke tests compilation failed: $variant" }
        & "$testDir/test_im_invoke_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "IM invoke tests failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/model/matter_im_write.c" -o "$testDir/im_write_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "IM write compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
            -I "$repoDir/main/apps/matter" "$PSScriptRoot/tests/test_im_write.c" "$testDir/im_write_$variant.o" `
            "$repoDir/main/apps/matter/codec/matter_tlv.c" "$repoDir/main/apps/matter/codec/matter_tlv_writer.c" `
            "$repoDir/main/apps/matter/codec/matter_tlv_validate.c" -o "$testDir/test_im_write_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "IM write tests compilation failed: $variant" }
        & "$testDir/test_im_write_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "IM write tests failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/model/matter_im_subscribe.c" -o "$testDir/im_subscribe_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "IM subscribe compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
            -I "$repoDir/main/apps/matter" "$PSScriptRoot/tests/test_im_subscribe.c" "$testDir/im_subscribe_$variant.o" "$testDir/events_$variant.o" `
            "$repoDir/main/apps/matter/codec/matter_tlv.c" "$repoDir/main/apps/matter/codec/matter_tlv_writer.c" `
            "$repoDir/main/apps/matter/codec/matter_tlv_validate.c" -o "$testDir/test_im_subscribe_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "IM subscribe tests compilation failed: $variant" }
        & "$testDir/test_im_subscribe_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "IM subscribe tests failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/session/matter_pase.c" -o "$testDir/pase_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "PASE compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/session/matter_case.c" -o "$testDir/case_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "case compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/session/matter_secure.c" -o "$testDir/secure_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "Secure session compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/transport/matter_secure_channel.c" -o "$testDir/secure_channel_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "Secure channel compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
            -I "$repoDir/main/apps/matter" "$PSScriptRoot/tests/test_secure.c" `
            "$repoDir/main/apps/matter/codec/matter_message_header.c" "$repoDir/main/apps/matter/codec/matter_protocol_header.c" `
            "$testDir/counter_$variant.o" "$testDir/reception_$variant.o" "$testDir/crypto_mbedtls_$variant.o" `
            @cryptoObjects -lbcrypt -lws2_32 -o "$testDir/test_secure_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Secure session tests compilation failed: $variant" }
        & "$testDir/test_secure_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Secure session tests failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/clusters/matter_diagnostics.c" -o "$testDir/diagnostics_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "Diagnostics compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -I "$repoDir/main/apps/matter" -c "$PSScriptRoot/host/matter_diagnostics_host.c" -o "$testDir/diagnostics_host_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "Diagnostics host compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/model/matter_cluster.c" -o "$testDir/cluster_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "Cluster compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/clusters/matter_admin_commissioning.c" -o "$testDir/admin_commissioning_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "Administrator Commissioning compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/clusters/matter_power_topology.c" -o "$testDir/power_topology_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "Power Topology compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/clusters/matter_eem.c" -o "$testDir/eem_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "EEM compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/clusters/matter_epm.c" -o "$testDir/epm_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "EPM compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/clusters/matter_groupkey.c" -o "$testDir/groupkey_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "Group Key Management compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/clusters/matter_acl.c" -o "$testDir/acl_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "ACL compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
            -I "$repoDir/main/apps/matter" "$PSScriptRoot/tests/test_acl.c" "$testDir/cluster_$variant.o" "$testDir/acl_$variant.o" "$testDir/im_write_$variant.o" "$testDir/events_$variant.o" `
            "$repoDir/main/apps/matter/codec/matter_tlv.c" "$repoDir/main/apps/matter/codec/matter_tlv_writer.c" `
            "$repoDir/main/apps/matter/codec/matter_tlv_validate.c" -o "$testDir/test_acl_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "ACL tests compilation failed: $variant" }
        & "$testDir/test_acl_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "ACL tests failed: $variant" }

        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/clusters/matter_wifi.c" -o "$testDir/wifi_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "Wi-Fi compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -I "$repoDir/main/apps/matter" -c "$PSScriptRoot/host/matter_wifi_sim.c" -o "$testDir/wifi_sim_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "Wi-Fi simulation compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
            -I "$repoDir/main/apps/matter" -I "$PSScriptRoot/host" "$PSScriptRoot/tests/test_diagnostics.c" "$testDir/cluster_$variant.o" `
            "$testDir/diagnostics_$variant.o" "$testDir/diagnostics_host_$variant.o" "$testDir/wifi_$variant.o" "$testDir/wifi_sim_$variant.o" "$testDir/events_$variant.o" `
            "$repoDir/main/apps/matter/codec/matter_tlv.c" "$repoDir/main/apps/matter/codec/matter_tlv_writer.c" `
            "$repoDir/main/apps/matter/codec/matter_tlv_validate.c" -o "$testDir/test_diagnostics_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Diagnostics tests compilation failed: $variant" }
        & "$testDir/test_diagnostics_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Diagnostics tests failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/clusters/matter_opcreds.c" -o "$testDir/opcreds_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "Operational Credentials compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/clusters/matter_fabric.c" -o "$testDir/fabric_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "Fabric model compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -I "$repoDir/main/apps/matter" -c "$PSScriptRoot/host/matter_fabric_host.c" -o "$testDir/fabric_host_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "Fabric host compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -I "$repoDir/main/apps/matter" -c "$PSScriptRoot/host/matter_commissioning_host.c" -o "$testDir/commissioning_host_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "Commissioning host compilation failed: $variant" }

        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -I "$repoDir/main/apps/matter" -c "$PSScriptRoot/host/matter_opcreds_host.c" -o "$testDir/opcreds_host_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "Operational Credentials host compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/clusters/matter_root.c" -o "$testDir/root_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "Root model compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
            -c "$repoDir/main/apps/matter/clusters/matter_root_case.c" -o "$testDir/root_case_$variant.o"
        if ($LASTEXITCODE -ne 0) { throw "root_case compilation failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
            -I "$repoDir/main/apps/matter" "$PSScriptRoot/tests/test_root.c" "$testDir/eem_$variant.o" "$testDir/epm_$variant.o" "$testDir/power_topology_$variant.o" "$testDir/root_$variant.o" "$testDir/diagnostics_$variant.o" "$testDir/groupkey_$variant.o" "$testDir/cluster_$variant.o" "$testDir/acl_$variant.o" "$testDir/opcreds_$variant.o" "$testDir/fabric_$variant.o" "$testDir/wifi_$variant.o" "$testDir/wifi_sim_$variant.o" `
            "$testDir/im_read_$variant.o" "$testDir/events_$variant.o" "$testDir/im_write_$variant.o" "$testDir/im_invoke_$variant.o" `
            "$repoDir/main/apps/matter/codec/matter_tlv.c" "$repoDir/main/apps/matter/codec/matter_tlv_writer.c" `
            "$repoDir/main/apps/matter/codec/matter_tlv_validate.c" -o "$testDir/test_root_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Root model test compilation failed: $variant" }
        & "$testDir/test_root_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Root model tests failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
            -I "$repoDir/main/apps/matter" "$PSScriptRoot/tests/test_cluster.c" "$testDir/root_$variant.o" "$testDir/diagnostics_$variant.o" "$testDir/groupkey_$variant.o" "$testDir/cluster_$variant.o" "$testDir/acl_$variant.o" "$testDir/opcreds_$variant.o" "$testDir/fabric_$variant.o" "$testDir/wifi_$variant.o" "$testDir/wifi_sim_$variant.o" `
            "$testDir/im_read_$variant.o" "$testDir/events_$variant.o" "$testDir/im_write_$variant.o" "$testDir/im_invoke_$variant.o" `
            "$repoDir/main/apps/matter/codec/matter_tlv.c" "$repoDir/main/apps/matter/codec/matter_tlv_writer.c" `
            "$repoDir/main/apps/matter/codec/matter_tlv_validate.c" -o "$testDir/test_cluster_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Generic cluster test compilation failed: $variant" }
        & "$testDir/test_cluster_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Generic cluster tests failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
            -I "$repoDir/main/apps/matter" -I "$PSScriptRoot/host" "$PSScriptRoot/tests/test_opcreds.c" "$testDir/cluster_$variant.o" `
            "$testDir/opcreds_$variant.o" "$testDir/fabric_$variant.o" "$testDir/opcreds_host_$variant.o" "$testDir/attestation_$variant.o" `
            "$testDir/crypto_mbedtls_$variant.o" @cryptoObjects `
            "$repoDir/main/apps/matter/codec/matter_tlv.c" "$repoDir/main/apps/matter/codec/matter_tlv_writer.c" `
            "$repoDir/main/apps/matter/codec/matter_tlv_validate.c" -lbcrypt -lws2_32 -o "$testDir/test_opcreds_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Operational Credentials test compilation failed: $variant" }
        & "$testDir/test_opcreds_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Operational Credentials tests failed: $variant" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
            -I "$repoDir/main/apps/matter" -I "$PSScriptRoot/host" "$PSScriptRoot/tests/test_fabric.c" "$testDir/cluster_$variant.o" "$testDir/im_subscribe_$variant.o" `
            "$testDir/acl_$variant.o" "$testDir/fabric_$variant.o" "$testDir/fabric_host_$variant.o" "$testDir/operational_$variant.o" "$testDir/events_$variant.o" `
            "$testDir/opcreds_$variant.o" "$testDir/opcreds_host_$variant.o" "$testDir/attestation_$variant.o" `
            "$testDir/crypto_mbedtls_$variant.o" @cryptoObjects "$repoDir/main/apps/matter/codec/matter_tlv.c" `
            "$repoDir/main/apps/matter/codec/matter_tlv_writer.c" "$repoDir/main/apps/matter/codec/matter_tlv_validate.c" `
            -lbcrypt -lws2_32 -o "$testDir/test_fabric_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Fabric test compilation failed: $variant" }
        & "$testDir/test_fabric_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Fabric tests failed: $variant" }
        $storeModules = @{
            store_tlv = "$repoDir/main/apps/matter/storage/matter_store_tlv.c"
            store_host = "$PSScriptRoot/host/matter_store_host.c"
            store_file = "$PSScriptRoot/host/matter_store_file_windows.c"
        }
        foreach ($name in $storeModules.Keys) {
            & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @moduleFlags `
                -I "$repoDir/main/apps/matter" -c $storeModules[$name] -o "$testDir/${name}_$variant.o"
            if ($LASTEXITCODE -ne 0) { throw "Store compilation failed: $name $variant" }
        }
        $caseObjects = @('cluster', 'groupkey', 'acl', 'case', 'secure', 'pase', 'spake2p', 'counter', 'reception', 'fabric', 'fabric_host', 'opcreds', 'opcreds_host', 'operational', 'attestation', 'crypto_mbedtls', 'events') |
            ForEach-Object { "$testDir/${_}_$variant.o" }
        $caseSources = @('matter_tlv', 'matter_tlv_writer', 'matter_tlv_validate', 'matter_message_header', 'matter_protocol_header') |
            ForEach-Object { "$repoDir/main/apps/matter/codec/$_.c" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
            -I "$repoDir/main/apps/matter" -I "$PSScriptRoot/host" "$PSScriptRoot/tests/test_case.c" `
            @caseSources @caseObjects @cryptoObjects -lbcrypt -lws2_32 -o "$testDir/test_case_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "CASE tests compilation failed: $variant" }
        & "$testDir/test_case_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "CASE tests failed: $variant" }
        $storeObjects = @('eem', 'store_tlv', 'store_host', 'store_file', 'commissioning_host', 'wifi', 'wifi_sim') |
            ForEach-Object { "$testDir/${_}_$variant.o" }
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
            -I "$repoDir/main/apps/matter" -I "$PSScriptRoot/host" "$PSScriptRoot/tests/test_store.c" `
            @caseSources @caseObjects @storeObjects @cryptoObjects -lbcrypt -lws2_32 -o "$testDir/test_store_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Store tests compilation failed: $variant" }
        foreach ($mode in @('committed', 'pending')) {
            foreach ($operation in @('seed', 'load')) {
                & "$testDir/test_store_$variant.exe" $operation "$testDir/store-$variant-$mode.tlv" $mode
                if ($LASTEXITCODE -ne 0) { throw "Store tests failed: $variant $operation $mode" }
            }
        }
        $paseObjects = @("$testDir/eem_$variant.o", "$testDir/epm_$variant.o", "$testDir/power_topology_$variant.o", "$testDir/admin_commissioning_$variant.o", "$testDir/pase_$variant.o", "$testDir/secure_$variant.o", "$testDir/secure_channel_$variant.o", "$testDir/udp_$variant.o", "$testDir/crypto_mbedtls_$variant.o", "$testDir/spake2p_$variant.o") + $cryptoObjects
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags `
            -I "$repoDir/main/apps/matter" -I "$PSScriptRoot/host" "$PSScriptRoot/tests/test_groupkey.c" `
            @caseSources @caseObjects @cryptoObjects -lbcrypt -lws2_32 -o "$testDir/test_groupkey_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Group key tests compilation failed: $variant" }
        & "$testDir/test_groupkey_$variant.exe"
        if ($LASTEXITCODE -ne 0) { throw "Group key tests failed: $variant" }
        foreach ($name in @('cluster', 'store_tlv', 'store_host', 'store_file', 'diagnostics', 'diagnostics_host', 'groupkey', 'acl', 'commissioning_host', 'case', 'root_case', 'root', 'opcreds', 'opcreds_host', 'fabric', 'fabric_host', 'operational', 'attestation', 'wifi', 'wifi_sim', 'events', 'im_read', 'im_invoke', 'im_write', 'im_subscribe', 'matter', 'exchange', 'rx_policy', 'ack', 'ack_sender', 'rx', 'retransmission',
                'retransmission_sender', 'unsecured_rx', 'unsecured_prepare', 'reception', 'counter', 'unsecured')) {
            $paseObjects += "$testDir/${name}_$variant.o"
        }
        $paseSources = @('matter_message_header', 'matter_protocol_header', 'matter_tlv', 'matter_tlv_writer', 'matter_tlv_validate') |
            ForEach-Object { "$repoDir/main/apps/matter/codec/$_.c" }
        $paseTransports = @('fake')
        if ($HostUdp) { $paseTransports += @('windows', 'windows-exhaustion') }
        foreach ($transport in $paseTransports) {
            $paseFlags = @(); $paseNetwork = @()
            $linkedPaseObjects = $paseObjects
            if ($transport -like 'windows*') {
                $paseFlags = @('-DMATTER_TEST_HOST_UDP')
                $paseNetwork = @("$testDir/udp_windows_$variant.o", "$testDir/unsecured_tx_$variant.o", '-lws2_32')
            }
            if ($transport -eq 'windows-exhaustion') {
                $paseFlags += '-DMATTER_TEST_SECURE_EXHAUSTION'
                $linkedPaseObjects = @($paseObjects | Where-Object { $_ -ne "$testDir/secure_$variant.o" })
            }
            & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags @testFlags @paseFlags `
                -I "$repoDir/main/apps/matter" -I "$PSScriptRoot/host" "$PSScriptRoot/tests/test_pase.c" `
                @paseSources @linkedPaseObjects @paseNetwork -lbcrypt -lws2_32 -o "$testDir/test_pase_${transport}_$variant.exe"
            if ($LASTEXITCODE -ne 0) { throw "PASE test compilation failed: $transport $variant" }
            & "$testDir/test_pase_${transport}_$variant.exe"
            if ($LASTEXITCODE -ne 0) { throw "PASE tests failed: $transport $variant" }
        }
    }

    & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags `
        -I "$repoDir/main/apps/matter" "$PSScriptRoot/tests/test_async.c" `
        "$testDir/matter_libc.o" -o "$testDir/test_async.exe"
    if ($LASTEXITCODE -ne 0) { throw 'Async test compilation failed' }
    & "$testDir/test_async.exe"
    if ($LASTEXITCODE -ne 0) { throw 'Async tests failed' }

    & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags `
        -I "$repoDir/main/apps/matter" "$repoDir/main/apps/matter/codec/matter_tlv.c" `
        "$PSScriptRoot/tests/test_tlv.c" -o "$testDir/test_tlv.exe"
    if ($LASTEXITCODE -ne 0) { throw 'TLV test compilation failed' }
    & "$testDir/test_tlv.exe"
    if ($LASTEXITCODE -ne 0) { throw 'TLV tests failed' }

    & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags `
        -I "$repoDir/main/apps/matter" "$repoDir/main/apps/matter/codec/matter_tlv.c" `
        "$repoDir/main/apps/matter/codec/matter_tlv_writer.c" `
        "$PSScriptRoot/tests/test_tlv_writer.c" -o "$testDir/test_tlv_writer.exe"
    if ($LASTEXITCODE -ne 0) { throw 'TLV writer test compilation failed' }
    & "$testDir/test_tlv_writer.exe"
    if ($LASTEXITCODE -ne 0) { throw 'TLV writer tests failed' }

    & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags `
        -I "$repoDir/main/apps/matter" "$repoDir/main/apps/matter/codec/matter_tlv.c" `
        "$repoDir/main/apps/matter/codec/matter_tlv_validate.c" `
        "$PSScriptRoot/tests/test_tlv_validate.c" -o "$testDir/test_tlv_validate.exe"
    if ($LASTEXITCODE -ne 0) { throw 'TLV validation test compilation failed' }
    & "$testDir/test_tlv_validate.exe"
    if ($LASTEXITCODE -ne 0) { throw 'TLV validation tests failed' }

    & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags `
        -I "$repoDir/main/apps/matter" "$repoDir/main/apps/matter/codec/matter_message_header.c" `
        "$PSScriptRoot/tests/test_message_header.c" -o "$testDir/test_message_header.exe"
    if ($LASTEXITCODE -ne 0) { throw 'Message header test compilation failed' }
    & "$testDir/test_message_header.exe"
    if ($LASTEXITCODE -ne 0) { throw 'Message header tests failed' }

    & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags `
        -I "$repoDir/main/apps/matter" "$repoDir/main/apps/matter/codec/matter_protocol_header.c" `
        "$repoDir/main/apps/matter/codec/matter_message_header.c" `
        "$PSScriptRoot/tests/test_protocol_header.c" -o "$testDir/test_protocol_header.exe"
    if ($LASTEXITCODE -ne 0) { throw 'Protocol header test compilation failed' }
    & "$testDir/test_protocol_header.exe"
    if ($LASTEXITCODE -ne 0) { throw 'Protocol header tests failed' }

    if ($HostUdp) {
        & "$PSScriptRoot/run_discovery_tests.ps1" -Compiler $compilerPath -Sanitize:$Sanitize
        & "$PSScriptRoot/build_host.ps1" -Compiler $compilerPath -Sanitize:$Sanitize -MbedtlsDir $mbedSource -Test
    }
    if ($Sanitize) {
        & $compilerPath -std=c99 -Wall -Wextra -Werror @sanitizerFlags `
            "$PSScriptRoot/tests/test_sanitizers.c" -o "$testDir/test_sanitizers.exe"
        if ($LASTEXITCODE -ne 0) { throw 'Sanitizer probe compilation failed' }
        foreach ($probe in @(
            @{ Name = 'asan'; Expected = 'AddressSanitizer: heap-buffer-overflow' },
            @{ Name = 'ubsan'; Expected = 'runtime error: signed integer overflow' }
        )) {
            $logPath = Join-Path $testDir ($probe.Name + '.log')
            # Nonzero is expected here; require the specific diagnostic as well.
            & "$testDir/test_sanitizers.exe" $probe.Name > $logPath 2>&1
            $probeExit = $LASTEXITCODE
            if ($probeExit -eq 0 -or !(Select-String -LiteralPath $logPath `
                    -SimpleMatch $probe.Expected -Quiet)) {
                throw "Sanitizer did not detect $($probe.Name) probe; see $logPath"
            }
            Write-Output "PASS $($probe.Name) detected deliberate error (exit $probeExit); $logPath"
        }
    }
} finally {
    $env:PATH = $savedPath
    $env:ASAN_OPTIONS = $savedAsan
    $env:UBSAN_OPTIONS = $savedUbsan
    $env:MATTER_TEST_STORE_DIR = $savedStoreDir
}
