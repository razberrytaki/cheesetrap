import type {
  Reporter,
  TestCase,
  TestResult,
  FullResult,
} from "@playwright/test/reporter";
// A selected workflow must actually execute and pass; skips/expected failures
// cannot produce a green acceptance run.
export default class NoSkips implements Reporter {
  expectedTests: number;
  constructor(options: { expectedTests?: number } = {}) {
    this.expectedTests = options.expectedTests ?? 2;
    if (!Number.isInteger(this.expectedTests) || this.expectedTests < 1)
      throw new Error('expectedTests must be a positive integer');
  }
  passed = 0;
  invalid = false;
  onTestEnd(test: TestCase, result: TestResult) {
    if (result.status === "passed" && test.expectedStatus === "passed")
      this.passed++;
    else this.invalid = true;
  }
  onEnd(result: FullResult): { status: FullResult["status"] } {
    return {
      status:
        result.status === "passed" && this.passed === this.expectedTests && !this.invalid
          ? "passed"
          : "failed",
    };
  }
}
