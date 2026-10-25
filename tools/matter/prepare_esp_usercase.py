"""Prepare isolated, same-IDF user-case C6 projects from the recorded lab.

Run on the build host with the external ESP-Matter SDK exported. No credentials,
signing keys, upstream edits or flash operations. Artifacts require local signing
and local NVS provisioning before use. Existing outputs are never overwritten.
"""
import argparse
from pathlib import Path
import shutil


def config(path, values):
    lines = path.read_text().splitlines() if path.exists() else []
    lines = [line for line in lines if not any(line.startswith(key + '=') or
             line.startswith('# ' + key + ' ') for key in values)]
    lines += [key + '=' + value if value != 'n' else '# ' + key + ' is not set'
              for key, value in values.items()]
    path.write_text('\n'.join(lines) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = args.source.resolve()
    if (root / '.git').exists():
        parser.error('--source must be an exported copy: this tool changes its C lab defaults and partitions')
    out = args.output.resolve()
    out.mkdir(exist_ok=False)
    common = root / 'examples/esp32-common'
    # The recorded reference is a copy already instrumented by Memory41. Its
    # lifecycle shutdown includes the task-exit barrier required by that SDK.
    ref = out / 'reference'
    shutil.copytree(args.reference, ref, ignore=shutil.ignore_patterns('build', '__pycache__'))
    for name in ('matter_lab_heap_sample.h', 'matter_lab_usercase.h', 'matter_lab_provision.h'):
        shutil.copyfile(common / name, ref / 'main' / name)
    app = ref / 'main/app_main.cpp'
    text = app.read_text()
    assert text.count('    matter_lab_lifecycle_settle("never-created-wifi-up");') == 1
    text = text.replace('    matter_lab_lifecycle_settle("never-created-wifi-up");', '    vTaskDelay(pdMS_TO_TICKS(2000)); matter_lab_usercase_report();')
    text = text.replace('    matter_lab_lifecycle_reserve();', '')
    text = text.replace('#include "reference_memory.h"', '#include "reference_memory.h"\n#include "matter_lab_usercase.h"\n#include "matter_lab_provision.h"\n#include "driver/uart_vfs.h"\n#include <unistd.h>\n#include "esp_app_desc.h"\n#include "esp_ota_ops.h"\n#include <app/clusters/ota-requestor/OTARequestorInterface.h>')
    text = text.replace('    reference_memory_start();', '    reference_memory_start();\n    matter_lab_usercase_begin(0);')
    begin = text.index('    while (true) {', text.index('extern "C" void app_main'))
    text = text[:begin] + '''    vTaskDelay(pdMS_TO_TICKS(2000));
    esp_ota_img_states_t state;
    if(esp_ota_get_state_partition(esp_ota_get_running_partition(),&state)==ESP_OK && state==ESP_OTA_IMG_PENDING_VERIFY)
        ESP_ERROR_CHECK(esp_ota_mark_app_valid_cancel_rollback());
    uart_vfs_dev_use_nonblocking(CONFIG_ESP_CONSOLE_UART_NUM);
    printf("REFERENCE_READY version=%s\\n",esp_app_get_description()->version);
    uint64_t last=esp_timer_get_time();
    while(true) {
        char c=0; (void)read(STDIN_FILENO,&c,1);
        matter_lab_usercase_control(c);
        if(c=='u') {
            chip::DeviceLayer::PlatformMgr().LockChipStack();
            auto* requestor=chip::GetRequestorInstance();
            auto result=requestor?requestor->TriggerImmediateQuery():CHIP_ERROR_INCORRECT_STATE;
            chip::DeviceLayer::PlatformMgr().UnlockChipStack();
            printf("NATIVE_OTA_QUERY result=%lu\\n",(unsigned long)result.AsInteger());
        }
        if(c=='q') reference_lifecycle_shutdown();
        if(esp_timer_get_time()-last>1000000) { matter_lab_usercase_report(); last=esp_timer_get_time(); }
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}
'''
    app.write_text(text)
    lifecycle = ref / 'main/reference_lifecycle.h'
    text = lifecycle.read_text()
    start = text.index('    ESP_ERROR_CHECK(esp_wifi_get_config(WIFI_IF_STA,config));')
    end = text.index('    ESP_ERROR_CHECK(esp_event_handler_register', start)
    text = text[:start] + '''    size_t ssid=0,password=0;
    if(!matter_lab_wifi_config(config,&ssid,&password)) abort();
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA,config));
    memset(config,0,sizeof(*config)); free(config);
''' + text[end:]
    # The provisioning helper must be visible before lifecycle's definition.
    text = '#include "matter_lab_provision.h"\n' + text
    text = text.replace('    reference_memory_report("platform-shutdown");',
                        '    matter_lab_usercase_begin(9);\n    reference_memory_report("platform-shutdown");')
    # The shared user-case monitor already owns the SDK's local watermark.
    # Observe settlement without starting a second monitor over the first one.
    text = text.replace('    matter_lab_lifecycle_settle("deleted-wifi-up");', '''    const int64_t settled_begin=esp_timer_get_time();
    const unsigned points[]={0,1000,5000,15000,30000,65000};
    for(unsigned point:points) {
        while((uint64_t)(esp_timer_get_time()-settled_begin)<(uint64_t)point*1000)
            vTaskDelay(pdMS_TO_TICKS(20));
        matter_lab_usercase_report();
    }''')
    lifecycle.write_text(text)
    cmake = ref / 'main/CMakeLists.txt'
    cmake.write_text(cmake.read_text() + '\ntarget_compile_options(${COMPONENT_LIB} PRIVATE -fstack-usage)\n')
    shutil.copyfile(root / 'examples/esp-matter-memory/usercase-partitions.csv', ref / 'partitions.csv')
    shared = {
        'CONFIG_PARTITION_TABLE_OFFSET': '0xC000',
        'CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE': 'y',
        'CONFIG_SECURE_SIGNED_APPS_NO_SECURE_BOOT': 'y',
        'CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME': 'y',
        'CONFIG_SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT': 'y',
        'CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES': 'n',
        'CONFIG_SECURE_BOOT': 'n',
        'CONFIG_APP_PROJECT_VER_FROM_CONFIG': 'y', 'CONFIG_APP_PROJECT_VER': '"1"',
        'CONFIG_COMPILER_OPTIMIZATION_DEBUG': 'n', 'CONFIG_COMPILER_OPTIMIZATION_SIZE': 'y',
        'CONFIG_COMPILER_OPTIMIZATION_LEVEL_DEBUG': 'n', 'CONFIG_COMPILER_OPTIMIZATION_DEFAULT': 'n',
        'CONFIG_LOG_DEFAULT_LEVEL_INFO': 'n', 'CONFIG_LOG_DEFAULT_LEVEL_WARN': 'y', 'CONFIG_LOG_DEFAULT_LEVEL': '2',
        'CONFIG_ESP_CONSOLE_UART_DEFAULT': 'n', 'CONFIG_ESP_CONSOLE_UART_CUSTOM': 'y',
        'CONFIG_ESP_CONSOLE_UART_CUSTOM_NUM_0': 'y',
        'CONFIG_ESP_CONSOLE_UART_TX_GPIO': '16', 'CONFIG_ESP_CONSOLE_UART_RX_GPIO': '17',
        'CONFIG_ESP_CONSOLE_UART_BAUDRATE': '1000000',
        'CONFIG_SPI_FLASH_ROM_IMPL': 'y',
        'CONFIG_ESP_WIFI_IRAM_OPT': 'n', 'CONFIG_ESP_WIFI_RX_IRAM_OPT': 'n', 'CONFIG_ESP_WIFI_EXTRA_IRAM_OPT': 'n',
        'CONFIG_ENABLE_CHIPOBLE': 'n', 'CONFIG_BT_ENABLED': 'n',
        'CONFIG_HEAP_PLACE_FUNCTION_INTO_FLASH': 'n', 'CONFIG_FREERTOS_PLACE_ISR_FUNCTIONS_INTO_FLASH': 'n',
        'CONFIG_RINGBUF_PLACE_ISR_FUNCTIONS_INTO_FLASH': 'n',
    }
    config(ref / 'sdkconfig', {**shared, 'CONFIG_ENABLE_CHIP_SHELL': 'n',
           'CONFIG_ESP_MATTER_MAX_DEVICE_TYPE_COUNT': '2', 'CONFIG_ESP_MATTER_MAX_DYNAMIC_ENDPOINT_COUNT': '2',
           'CONFIG_DEVICE_SOFTWARE_VERSION_NUMBER': '1', 'CONFIG_DEVICE_SOFTWARE_VERSION_STRING': '"1"'})
    c = root / 'examples/esp32-runtime'
    shutil.copyfile(root / 'examples/esp-matter-memory/usercase-partitions.csv', c / 'partitions.csv')
    config(c / 'sdkconfig.defaults', {**shared, 'CONFIG_MATTER_C_RUNTIME_RGB': 'y',
           'CONFIG_MATTER_C_RUNTIME_USERCASE': 'y', 'CONFIG_MATTER_C_RUNTIME_NATIVE_OTA': 'y',
           'CONFIG_MATTER_C_RUNTIME_OOM_SWEEP': 'n', 'CONFIG_MATTER_C_RUNTIME_SOAK': 'n',
           'CONFIG_MATTER_C_RUNTIME_COMPARE_SAMPLER': 'n'})
    print('Prepared new reference and C user-case defaults; no keys/provisioning/build/flash')


if __name__ == '__main__':
    main()
