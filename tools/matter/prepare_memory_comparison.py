"""Generate isolated C6 lifecycle observers; never edit either stack or SDK.

C input must be a clean exported copy of matter-c-memory. Reference input is a
new copy prepared by prepare_esp_memory_reference.py with Hue/Saturation enabled.
The output directory must not exist. Normal firmware does not include these hooks.
"""
import argparse
from pathlib import Path
import shutil


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Unexpected source anchor: ' + old[:100])
    return text.replace(old, new)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kind', choices=('c', 'reference'), required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--reserve-bytes', type=int, default=0)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Output must not exist')
    if args.output.resolve().is_relative_to(args.source.resolve()):
        parser.error('Output must be outside the input source tree')
    if not 0 <= args.reserve_bytes <= 65536:
        parser.error('Reservation must be between 0 and 65536 bytes')
    shutil.copytree(args.source, args.output,
                    ignore=shutil.ignore_patterns('build', 'local', '.git', '__pycache__', 'node_modules'))
    helper = Path(__file__).resolve().parents[2] / 'examples/esp32-common/matter_lab_lifecycle.h'
    if args.kind == 'c':
        app = args.output / 'examples/esp32-runtime/main/app_main.c'
        (app.parent / 'matter_lab_lifecycle.h').write_text(
            '#define MATTER_LAB_RESERVE_BYTES ' + str(args.reserve_bytes) + '\n' + helper.read_text())
        text = app.read_text()
        text = replace_once(text, 'void app_main(void) {',
                            '#include "matter_lab_lifecycle.h"\nvoid app_main(void) {')
        text = replace_once(text, '    boot_wifi(a);',
                            '    boot_wifi(a);\n    matter_lab_lifecycle_settle("never-created-wifi-up");\n'
                            '    matter_lab_lifecycle_reserve();')
        text = replace_once(text, '    HEAP_STATE("backend-deleted");',
                            '    HEAP_STATE("backend-deleted");\n'
                            '    REQUIRE(!matter_idf_memory().live && !matter_idf_memory().live_bytes);\n'
                            '    matter_lab_lifecycle_settle("deleted-wifi-up");\n'
                            '    matter_lab_lifecycle_unreserve();')
    else:
        app = args.output / 'main/app_main.cpp'
        (app.parent / 'matter_lab_lifecycle.h').write_text(
            '#define MATTER_LAB_RESERVE_BYTES ' + str(args.reserve_bytes) + '\n' + helper.read_text())
        text = app.read_text()
        text = replace_once(text, '#include "reference_memory.h"',
                            '#include "reference_memory.h"\n#include "matter_lab_lifecycle.h"\n'
                            '#include "reference_lifecycle.h"')
        text = replace_once(text, '    reference_memory_report("Bootup");',
                            '    reference_memory_report("Bootup");\n'
                            '    reference_lifecycle_wifi();\n'
                            '    matter_lab_lifecycle_settle("never-created-wifi-up");\n'
                            '    matter_lab_lifecycle_reserve();')
        text = replace_once(text, '        vTaskDelay(10000 / portTICK_PERIOD_MS);',
                            '        for(unsigned wait=0;wait<100 && !reference_lifecycle_stop; ++wait)\n'
                            '            vTaskDelay(pdMS_TO_TICKS(100));\n'
                            '        if(reference_lifecycle_stop) { reference_lifecycle_shutdown(); break; }')
        text += '\n'
        header = args.output / 'main/reference_memory.h'
        value = header.read_text()
        value = replace_once(value, 'static void reference_memory_report(',
                             '#include <atomic>\n#include <cstring>\n'
                             'static std::atomic<bool> reference_lifecycle_stop{false};\n'
                             'static void reference_memory_report(')
        value = replace_once(value, '    reference_memory_report(phase); reference_memory_tasks(); return 0;',
                             '    reference_memory_report(phase); reference_memory_tasks();\n'
                             '    if(strcmp(phase,"shutdown")==0) reference_lifecycle_stop=true;\n'
                             '    return 0;')
        header.write_text(value)
        shutil.copyfile(helper.parent.parent / 'esp-matter-memory/reference_lifecycle.h',
                        args.output / 'main/reference_lifecycle.h')
    app.write_text(text)
    print('Prepared isolated ' + args.kind + ' lifecycle comparison; no build or flash')


if __name__ == '__main__':
    main()
