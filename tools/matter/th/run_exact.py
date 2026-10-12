"""Run exact TH case IDs with the installed th-cli Python environment.

Avoid the CLI's hyphen/underscore alias expansion (which can also select manual
YAML). Test implementations and results are unchanged. Do not interpret CLI
exit code zero as PASS: inspect the resulting run/case/step states in TH.
"""
import importlib

runner = importlib.import_module('th_cli.commands.run_tests')


def exact_selection(collections, requested):
    selection = {}
    counts = dict.fromkeys(requested, 0)
    for name, collection in collections.test_collections.items():
        for suite_name, suite in collection.test_suites.items():
            for case in suite.test_cases:
                if case in counts:
                    counts[case] += 1
                    selection.setdefault(name, {}).setdefault(suite_name, {})[case] = 1
    if any(count != 1 for count in counts.values()):
        raise ValueError(f'Test IDs must match exactly once: {counts}')
    return selection


runner.build_test_selection = exact_selection
if __name__ == '__main__':
    runner.run_tests.main()
