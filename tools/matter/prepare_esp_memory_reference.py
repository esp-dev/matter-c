"""Copy the pinned external ESP-Matter light into a NEW private build project.

No change to the upstream checkout, protocol code, resource limits or credentials.
Adds observation hooks and matches the existing C lab's Wi-Fi code placement.
The optional Hue/Saturation feature enables the common RGB wire workload.
Run with the external ESP-Matter/IDF environments already exported, then idf.py.
"""
import argparse
from pathlib import Path
import shutil
import subprocess

PIN = '4c9dd7aa80b3ddfa64c814bdfabe76c60944cc75'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--esp-matter', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--sdkconfig', required=True, type=Path)
    p.add_argument('--hue-saturation', action='store_true')
    a = p.parse_args()
    source = a.esp_matter.resolve()
    if subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip() != PIN:
        p.error('Expected the recorded ESP-Matter release/v1.6.1 commit')
    destination = a.output.resolve()
    if destination.exists():
        p.error('Output must be a new project directory')
    shutil.copytree(source / 'examples/light', destination,
                    ignore=shutil.ignore_patterns('build', 'sdkconfig', '__pycache__'))
    helper = Path(__file__).resolve().parents[2] / 'examples/esp-matter-memory/reference_memory.h'
    shutil.copyfile(helper, destination / 'main/reference_memory.h')
    shutil.copyfile(helper.parent.parent / 'esp32-common/matter_lab_heap_sample.h',
                    destination / 'main/matter_lab_heap_sample.h')
    app = destination / 'main/app_main.cpp'
    text = app.read_text()
    assert text.count('#include <log_heap_numbers.h>') == 1
    text = text.replace('#include <log_heap_numbers.h>', '#include "reference_memory.h"')
    text = text.replace('MEMORY_PROFILER_DUMP_HEAP_STAT(', 'reference_memory_report(')
    anchor = '    /* Initialize the ESP NVS layer */'
    assert text.count(anchor) == 1
    text = text.replace(anchor, '    reference_memory_start();\n    reference_memory_report("boot-before-nvs");\n\n' + anchor)
    anchor = '    esp_matter::console::init();'
    assert text.count(anchor) == 1
    text = text.replace(anchor, anchor + '\n    reference_memory_console();')
    if a.hue_saturation:
        anchor = '    light_endpoint_id = endpoint::get_id(endpoint);'
        assert text.count(anchor) == 1
        text = text.replace(anchor, hue_saturation_patch() + anchor)
    app.write_text(text)
    config = a.sdkconfig.read_text()
    overrides = {'CONFIG_ESP_WIFI_IRAM_OPT': 'n', 'CONFIG_ESP_WIFI_RX_IRAM_OPT': 'n',
                 'CONFIG_ESP_WIFI_EXTRA_IRAM_OPT': 'n', 'CONFIG_FREERTOS_USE_TRACE_FACILITY': 'y'}
    lines = [line for line in config.splitlines()
             if not any(line.startswith(key + '=') or line.startswith('# ' + key + ' ') for key in overrides)]
    lines += [key + '=' + value for key, value in overrides.items()]
    (destination / 'sdkconfig').write_text('\n'.join(lines) + '\n')
    print('Prepared pinned reference light with memory observation; no build/flash yet')


def hue_saturation_patch():
    return '''    /* Laboratory comparison: stock light already handles HS driver updates. */
    cluster::color_control::feature::hue_saturation::config_t hue_saturation;
    hue_saturation.current_hue = DEFAULT_HUE;
    hue_saturation.current_saturation = DEFAULT_SATURATION;
    ESP_ERROR_CHECK(cluster::color_control::feature::hue_saturation::add(
        cluster::get(endpoint, ColorControl::Id), &hue_saturation));

'''


if __name__ == '__main__':
    main()
