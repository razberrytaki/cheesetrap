import assert from 'node:assert/strict';
import { test } from 'node:test';
import { declarations } from './ui-test-identities.mjs';

test('source AST excludes comments, strings and parameterized or dynamic calls', () => {
  const source = `import { it } from 'vitest';
/*
it('generated case 1', () => {});
*/
it.each([1])('generated case %i', () => {});
const text = "it('invented', () => {});";
it(process.env.PRIVATE_CANARY, () => {});
it('known test', () => {});
`;
  assert.deepEqual(declarations({ 'Example.test.ts': source }), {
    'Example.test.ts': [{ title: 'known test', line: 8, column: 1 }],
  });
});

test('literal declarations retain exact locations, including duplicate titles and aliases', () => {
  const source = `import {it, test as check} from 'vitest';
  it('same', () => {});
check.skip('same', () => {});
`;
  assert.deepEqual(declarations({ 'Example.test.tsx': source })['Example.test.tsx'], [
    { title: 'same', line: 2, column: 3 },
    { title: 'same', line: 3, column: 7 },
  ]);
});

test('unimported calls and syntactically invalid source provide no identifiers', () => {
  assert.deepEqual(declarations({ 'Example.test.ts': "it('unbound', () => {});" }), { 'Example.test.ts': [] });
  assert.deepEqual(declarations({ 'Example.test.ts': "import {it} from 'vitest'; it('broken'," }), {});
});
