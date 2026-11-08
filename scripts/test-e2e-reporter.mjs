import assert from 'node:assert/strict';
import NoSkips from '../web/e2e/no-skips.ts';
for (const [statuses, expected] of [
  [[], 'failed'], [['passed'], 'failed'], [['skipped'], 'failed'],
  [['failed'], 'failed'], [['passed', 'skipped'], 'failed'],
  [['passed', 'passed'], 'passed'],
  [['passed', 'passed', 'passed'], 'failed'],
]) {
  const reporter = new NoSkips();
  for (const status of statuses) reporter.onTestEnd({ expectedStatus: 'passed' }, { status });
  assert.equal(reporter.onEnd({ status: 'passed' }).status, expected);
}
const expectedFailure = new NoSkips({ expectedTests: 1 });
expectedFailure.onTestEnd({ expectedStatus: 'failed' }, { status: 'passed' });
assert.equal(expectedFailure.onEnd({ status: 'passed' }).status, 'failed');
for (const [statuses, expected] of [
  [[], 'failed'], [['passed'], 'passed'], [['skipped'], 'failed'],
  [['failed'], 'failed'], [['passed', 'passed'], 'failed'],
]) {
  const reporter = new NoSkips({ expectedTests: 1 });
  for (const status of statuses) reporter.onTestEnd({ expectedStatus: 'passed' }, { status });
  assert.equal(reporter.onEnd({ status: 'passed' }).status, expected);
}
console.log('PASS: browser reporter rejects empty, skipped, failed, extra and expected-failure workflows');
