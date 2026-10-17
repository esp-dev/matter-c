"""Offline regression for an external TC_SU_2_5 source and reporting helper.

Execute the actual progress-wait AST with deterministic queue/clock adapters.
No SDK imports, device credentials, sockets or installed-source changes. Supply
the original source as a reference to check preservation of its assertions.
This is a helper regression, never an official CSA acceptance result.
"""
import argparse
import ast
from collections import Counter
import hashlib
import json
from pathlib import Path
import queue
from types import SimpleNamespace
from typing import Iterable


class TestFailure(AssertionError):
    pass


class Asserts:
    @staticmethod
    def fail(message):
        raise TestFailure(message)

    @staticmethod
    def assert_greater(value, bound, message):
        if value <= bound:
            raise TestFailure(message)


class Clock:
    def __init__(self):
        self.elapsed = 0.0

    def time(self):
        return self.elapsed

    monotonic = time

    def sleep(self, duration):
        self.elapsed += duration


class Reports:
    def __init__(self, reports, clock):
        self.reports = list(reports)
        self.clock = clock

    def get(self, block=True, timeout=0):
        del block
        self.clock.sleep(min(.01, timeout))
        if self.reports:
            return self.reports.pop(0)
        self.clock.sleep(max(0, timeout - .01))
        raise queue.Empty


class Matcher:
    @classmethod
    def from_callable(cls, description, matcher):
        return SimpleNamespace(description=description, matches=matcher)


def method(tree, name):
    return next(node for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name)


def function_module(function):
    return ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[]))


def wait_block(tree):
    body = method(tree, 'test_TC_SU_2_5').body
    first = next(i for i, stmt in enumerate(body) if isinstance(stmt, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == 'progress_seen' for t in stmt.targets))
    last = next(i for i in range(first, len(body)) if isinstance(body[i], ast.Expr)
                and isinstance(body[i].value, ast.Call)
                and isinstance(body[i].value.func, ast.Attribute)
                and isinstance(body[i].value.func.value, ast.Name)
                and body[i].value.func.value.id == 'download_progress_attr_handler'
                and body[i].value.func.attr == 'reset')
    wrapper = ast.parse('def run(self, download_progress_attr_handler): pass').body[0]
    wrapper.body = body[first:last]
    return function_module(wrapper)


def run_sequence(case_tree, helper_tree, values):
    null = object()
    clock = Clock()
    reports = [SimpleNamespace(value=null if v is None else v, endpoint_id=0, attribute='progress') for v in values]
    scope = dict(NullValue=null, time=clock, asserts=Asserts, queue=queue, Iterable=Iterable,
                 AttributeMatcher=Matcher, AttributeValue=SimpleNamespace,
                 LOGGER=SimpleNamespace(info=lambda *a: None, error=lambda *a: None))
    holder = SimpleNamespace(_q=Reports(reports, clock), _attribute_reports={'progress': reports})
    for name in ['wait_next_report', 'await_all_expected_report_matches']:
        exec(compile(function_module(method(helper_tree, name)), '<sdk-helper>', 'exec'), scope)
        setattr(holder, name, lambda *args, _fn=scope[name], **kw: _fn(holder, *args, **kw))
    exec(compile(wait_block(case_tree), '<sdk-test-progress>', 'exec'), scope)
    try:
        scope['run'](SimpleNamespace(ota_image_download_timeout=3.0), holder)
        return True, clock.elapsed
    except TestFailure:
        return False, clock.elapsed


def assertion_calls(tree):
    return Counter(ast.dump(n, include_attributes=False) for n in ast.walk(method(tree, 'test_TC_SU_2_5'))
                   if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                   and isinstance(n.func.value, ast.Name) and n.func.value.id == 'asserts')


def scenario_subscriptions(tree):
    result = {}
    step = None
    for stmt in method(tree, 'test_TC_SU_2_5').body:
        if not isinstance(stmt, ast.Expr):
            continue
        call = stmt.value
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and call.func.attr == 'step':
            step = call.args[0].value
        if isinstance(call, ast.Await):
            call = call.value
            if step in (3, 4, 5) and isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and call.func.attr == 'start':
                keep = next((k.value.value for k in call.keywords if k.arg == 'keepSubscriptions'), True)
                result.setdefault(step, []).append(keep)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--test-source', type=Path, required=True)
    parser.add_argument('--helper-source', type=Path, required=True)
    parser.add_argument('--original-source', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    case = ast.parse(args.test_source.read_text(encoding='utf-8'))
    helper = ast.parse(args.helper_source.read_text(encoding='utf-8'))
    original = ast.parse(args.original_source.read_text(encoding='utf-8'))
    results = []
    sequences = [
        ('initial-null-is-not-completion', [None, 0, 1], False),
        ('completion-after-progress', [None, 0, 1, None], True),
        ('null-without-positive-progress', [None, None, 0, None], False),
        ('sparse-valid-progress', [None, 50, None], True),
        ('hundred-without-later-null', [None, 1, 100], False),
        ('null-only', [None], False),
        ('full-valid-progress', [None, 0, 99, 100, None], True),
        ('invalid-percent-does-not-arm-completion', [None, -1, 101, None], False),
        ('reports-do-not-extend-deadline', [None] + [0] * 1000, False),
    ]
    for name, values, expected in sequences:
        completed, elapsed = run_sequence(case, helper, values)
        results.append(dict(name=name, passed=completed == expected and elapsed <= 3.11,
                            expected_completion=expected, actual_completion=completed, virtual_seconds=elapsed))
    groups = scenario_subscriptions(case)
    results.append(dict(name='fresh-scenario-preserves-its-second-subscription',
                        passed=set(groups) == {3, 4, 5} and all(flags == [False, True] for flags in groups.values())))
    preserved = not (assertion_calls(original) - assertion_calls(case))
    same_predicate = ast.dump(method(case, 'check_ota_download_matcher'), include_attributes=False) == ast.dump(
        method(original, 'check_ota_download_matcher'), include_attributes=False)
    results.append(dict(name='original-assertions-and-progress-predicate-preserved', passed=preserved and same_predicate))
    result = dict(scope='Offline source regression, not official CSA acceptance', checks=results,
                  test_sha256=hashlib.sha256(args.test_source.read_bytes()).hexdigest(),
                  helper_sha256=hashlib.sha256(args.helper_source.read_bytes()).hexdigest(),
                  reference_sha256=hashlib.sha256(args.original_source.read_bytes()).hexdigest())
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    for item in results:
        print(('PASS ' if item['passed'] else 'FAIL ') + item['name'])
    return 0 if all(item['passed'] for item in results) else 1


if __name__ == '__main__':
    raise SystemExit(main())
