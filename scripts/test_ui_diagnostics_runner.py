import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import sys
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('ui_acceptance', Path(__file__).with_name('test-acceptance.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class UIDiagnosticsTests(unittest.TestCase):
    source_path = 'web/src/Example.test.tsx'
    sources = {source_path: "import {it} from 'vitest';\nit('known test', () => {});\n"}
    canary = 'PRIVATE_CANARY_do_not_publish'

    def setUp(self):
        # Parser semantics are separately exercised by npm pretest's real TS AST
        # tests. Python gate regressions stay independent of installed Node deps.
        patcher = mock.patch.object(runner, 'ui_declarations', return_value={
            self.source_path: [{'title': 'known test', 'line': 2, 'column': 1}],
        })
        self.addCleanup(patcher.stop)
        self.declarations = patcher.start()

    def document(self, status='passed'):
        return {'success': status != 'failed', 'testResults': [{
            'name': str(runner.ROOT / self.source_path),
            'status': 'failed' if status == 'failed' else 'passed',
            'assertionResults': [{'title': 'known test', 'fullName': 'suite known test',
                                  'status': status, 'location': {'line': 2, 'column': 1},
                                  'failureMessages': [self.canary]}],
        }]}

    def check(self, document, code=0, process_status='exited'):
        with tempfile.TemporaryDirectory() as temp:
            report = Path(temp) / 'ui.json'
            if document is not None:
                report.write_text(json.dumps(document))
            return runner.ui_check(report, code, self.sources, process_status)

    def test_success_and_failed_assertion_have_distinct_safe_diagnostics(self):
        self.assertTrue(callable(getattr(runner, 'ui_check', None)), 'UI structured diagnostics missing')
        passed, row = self.check(self.document())
        self.assertEqual(passed, {('src/Example.test.tsx', 'suite known test')})
        self.assertEqual(row, {'returncode': 0, 'process_status': 'exited',
                              'report_present': True, 'report_status': 'valid',
                              'categories': [], 'tests': [], 'locations': [], 'files': []})
        passed, row = self.check(self.document('failed'), 1)
        self.assertFalse(passed)
        self.assertIn('ui_test_failed', row['categories'])
        self.assertIn('process_failed', row['categories'])
        self.assertEqual(row['tests'], [self.source_path + '::test@2'])
        self.assertEqual(row['locations'], [self.source_path + ':2'])
        self.assertNotIn(self.canary, json.dumps(row))

    def test_skip_todo_empty_and_suite_failure_remain_failures(self):
        for status in ('pending', 'skipped', 'todo', 'disabled'):
            with self.subTest(status=status):
                passed, row = self.check(self.document(status))
                self.assertFalse(passed)
                self.assertIn('ui_test_skipped', row['categories'])
        for document in ({'success': True, 'testResults': []},
                         {'success': True, 'testResults': [{'name': 'x', 'status': 'passed', 'assertionResults': []}]}):
            passed, row = self.check(document)
            self.assertFalse(passed)
            self.assertIn('ui_empty_results', row['categories'])
        document = self.document()
        document['testResults'][0]['status'] = 'failed'
        document['testResults'][0]['message'] = self.canary
        passed, row = self.check(document)
        self.assertFalse(passed)
        self.assertIn('ui_suite_failed', row['categories'])
        self.assertEqual(row['files'], [self.source_path])

    def test_missing_malformed_invalid_and_unreadable_reports(self):
        passed, row = self.check(None, 1)
        self.assertFalse(passed)
        self.assertEqual((row['report_present'], row['report_status']), (False, 'missing'))
        self.assertIn('process_failed', row['categories'])
        for invalid in ([], {}, {'testResults': None}, {'success': 'yes', 'testResults': []},
                        {'success': True, 'testResults': [None]}):
            with self.subTest(invalid=invalid):
                passed, row = self.check(invalid)
                self.assertFalse(passed)
                self.assertEqual(row['report_status'], 'invalid_schema')
        with tempfile.TemporaryDirectory() as temp:
            report = Path(temp) / 'ui.json'
            for malformed in ('{'+self.canary, '[[' * 1500, '\ufffd'):
                report.write_text(malformed)
                passed, row = runner.ui_check(report, 0, self.sources)
                self.assertFalse(passed)
                self.assertEqual(row['report_status'], 'malformed')
                self.assertNotIn(self.canary, json.dumps(row))
            report.unlink()
            report.mkdir()
            passed, row = runner.ui_check(report, 0, self.sources)
            self.assertFalse(passed)
            self.assertEqual(row['report_status'], 'unreadable')

    def test_unknown_status_bad_identity_and_duplicate_results_fail_closed(self):
        for field, value in (('status', 'invented'), ('status', []), ('fullName', None), ('title', {})):
            document = self.document()
            document['testResults'][0]['assertionResults'][0][field] = value
            passed, row = self.check(document)
            self.assertFalse(passed)
            self.assertEqual(row['report_status'], 'invalid_schema')
        document = self.document()
        document['testResults'][0]['assertionResults'] *= 2
        self.assertFalse(self.check(document)[0])

    def test_report_size_type_encoding_and_source_limits(self):
        with tempfile.TemporaryDirectory() as temp:
            report = Path(temp) / 'ui.json'
            report.write_bytes(b'x' * (8 * 1024 * 1024 + 1))
            self.assertEqual(runner.ui_check(report, 0, {})[1]['report_status'], 'too_large')
            report.write_bytes(b'\xff')
            self.assertEqual(runner.ui_check(report, 0, {})[1]['report_status'], 'malformed')
            report.unlink()
            report.symlink_to(Path(temp) / 'absent')
            row = runner.ui_check(report, 0, {})[1]
            self.assertEqual((row['report_present'], row['report_status']), (True, 'unreadable'))
            report.unlink()
            os.mkfifo(report)
            self.assertEqual(runner.ui_check(report, 0, {})[1]['report_status'], 'unreadable')

    def test_ast_location_required_and_parser_failure_only_omits_identifiers(self):
        for location in (None, {}, {'line': 3, 'column': 1}, {'line': 2, 'column': 2},
                         {'line': True, 'column': 1}, {'line': self.canary, 'column': 1}):
            document = self.document('failed')
            document['testResults'][0]['assertionResults'][0]['location'] = location
            passed, row = self.check(document, 1)
            self.assertFalse(passed)
            self.assertEqual(row['tests'], [])
            self.assertEqual(row['locations'], [])
            self.assertNotIn(self.canary, json.dumps(row))
        self.declarations.return_value = {}
        passed, row = self.check(self.document('failed'), 1)
        self.assertFalse(passed)
        self.assertEqual(row['tests'], [])
        self.assertEqual(row['files'], [self.source_path])
        self.assertIn('ui_test_failed', row['categories'])

    def test_main_enforces_ui_gate_and_emits_safe_summary_on_abort(self):
        # Exercise the actual acceptance orchestration without Go/DB/browser work.
        for outcome in ('pass', 'assertion', 'skip', 'missing', 'malformed', 'pretest', 'start', 'timeout', 'interrupt'):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                (root / 'tests/acceptance').mkdir(parents=True)
                (root / 'tests/acceptance/coverage.json').write_text('{}')
                browser = root / '.local/e2e/browser-results.json'
                browser.parent.mkdir(parents=True)
                def command(argv, *, log, **kwargs):
                    log.write_bytes(self.canary.encode() + b'\xff')
                    if log.stem == 'e2e': browser.write_text('{}')
                    if log.stem != 'ui': return 0
                    if outcome == 'start': raise OSError(self.canary)
                    if outcome == 'timeout': raise runner.AcceptanceTimeout('acceptance command timed out; active harness cleanup requested')
                    if outcome == 'interrupt': raise runner.AcceptanceInterrupted(15)
                    report = log.with_suffix('.json')
                    if outcome == 'malformed': report.write_text('{'+self.canary)
                    elif outcome not in ('missing', 'pretest'):
                        report.write_text(json.dumps(self.document({'assertion': 'failed', 'skip': 'pending'}.get(outcome, 'passed'))))
                    return 9 if outcome == 'pretest' else 1 if outcome == 'assertion' else 0
                captured = io.StringIO()
                with contextlib.ExitStack() as stack:
                    for name, replacement in {
                        'ROOT': root, 'install_signal_handlers': lambda: None,
                        'validate_manifest': lambda _: None, 'checkout_is_clean': lambda _: True,
                        'production_sources': lambda: {}, 'generated_snapshot': lambda: {},
                        'go_results': lambda _: (set(), []), 'harness_results': lambda *a: (set(), []),
                        'browser_results': lambda _: set(), 'evaluate': lambda *a: [],
                        'run_command': command,
                    }.items(): stack.enter_context(mock.patch.object(runner, name, replacement))
                    stack.enter_context(mock.patch.dict(os.environ, {}, clear=True))
                    stack.enter_context(mock.patch.object(sys, 'argv', ['test-acceptance.py', '--automated-only']))
                    stack.enter_context(mock.patch.object(runner.subprocess, 'check_output', side_effect=lambda args, **kw: 'revision' if kw.get('text') else b''))
                    stack.enter_context(contextlib.redirect_stdout(captured))
                    if outcome in ('timeout', 'interrupt'):
                        with self.assertRaises((runner.AcceptanceTimeout, runner.AcceptanceInterrupted)): runner.main()
                    else:
                        self.assertEqual(runner.main(), 0 if outcome == 'pass' else 1)
                public = captured.getvalue()
                self.assertNotIn(self.canary, public)
                rows = [json.loads(line.removeprefix('CI_CHECK ')) for line in public.splitlines() if line.startswith('CI_CHECK ')]
                ui = next(row for row in rows if row['command'] == 'ui')
                self.assertEqual(ui['status'], 'PASS' if outcome == 'pass' else 'FAIL')
                if outcome == 'pretest':
                    self.assertEqual(ui['returncode'], 9)
                    self.assertEqual(ui['categories'], ['process_failed', 'ui_report_missing'])
                if outcome in ('start', 'timeout', 'interrupt'): self.assertIsNone(ui['returncode'])

    def test_process_failure_is_not_inferred_as_an_assertion_or_pretest_cause(self):
        passed, row = self.check(self.document(), 7)
        self.assertFalse(passed)
        self.assertEqual(row['categories'], ['process_failed'])
        self.assertEqual(row['returncode'], 7)
        for process in ('start_failed', 'timed_out', 'interrupted'):
            passed, row = self.check(None, None, process)
            self.assertFalse(passed)
            self.assertIsNone(row['returncode'])
            self.assertIn('process_' + process, row['categories'])

    def test_hostile_paths_titles_and_runtime_text_are_never_published(self):
        document = self.document('failed')
        for path in ('/private/' + self.canary, '../' + self.source_path,
                     str(runner.ROOT / 'web/src/../src/Example.test.tsx'),
                     'src\\Example.test.tsx', 'src/Example.test.tsx\n' + self.canary,
                     'src/' + self.canary + '.test.tsx', self.source_path + '/extra'):
            document['testResults'][0]['name'] = path
            _, row = self.check(document, 1)
            self.assertEqual(row['files'], [])
            self.assertEqual(row['tests'], [])
            self.assertNotIn(self.canary, json.dumps(row))
        for title in (self.canary, 'known test/' + self.canary, 'known test\n' + self.canary):
            document = self.document('failed')
            document['testResults'][0]['assertionResults'][0].update(title=title, fullName=self.canary)
            _, row = self.check(document, 1)
            self.assertEqual(row['tests'], [])
            self.assertNotIn(self.canary, json.dumps(row))

    def test_public_summary_reads_report_and_ignores_ui_log_entirely(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / self.source_path
            source.parent.mkdir(parents=True)
            source.write_text(self.sources[self.source_path])
            local = root / '.local/run'
            local.mkdir(parents=True)
            (local / 'ui.log').write_text(self.canary + '\nAssertionError\nExample.test.tsx:1:\n')
            with mock.patch.object(runner, 'ROOT', root):
                (local / 'ui.json').write_text(json.dumps(self.document('failed')))
                captured = io.StringIO()
                with mock.patch.object(runner.subprocess, 'check_output', return_value=(self.source_path + '\0').encode()), contextlib.redirect_stdout(captured):
                    runner.print_public_summary([{'name': 'ui', 'status': 'FAIL', 'returncode': 1,
                                                  'log': '.local/run/ui.log', 'report': '.local/run/ui.json'}])
            output = captured.getvalue()
            row = json.loads(output.removeprefix('CI_CHECK '))
            self.assertIn('ui_test_failed', row['categories'])
            self.assertNotIn('assertion_failed', row['categories'])
            self.assertEqual(row['locations'], [self.source_path + ':2'])
            self.assertNotIn(self.canary, output)


if __name__ == '__main__':
    unittest.main()
