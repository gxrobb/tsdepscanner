import test from 'node:test';
import assert from 'node:assert/strict';
import { shouldFail } from '../src/utils.js';

test('shouldFail returns true when finding severity meets threshold', () => {
  assert.equal(shouldFail('high', 'critical'), true);
  assert.equal(shouldFail('high', 'high'), true);
  assert.equal(shouldFail('high', 'medium'), false);
});

test('shouldFail never fails when failOn is none', () => {
  assert.equal(shouldFail('none', 'critical'), false);
  assert.equal(shouldFail('none', 'unknown'), false);
});

test('shouldFail safely handles unexpected values', () => {
  assert.equal(shouldFail('invalid-threshold', 'high'), false);
  assert.equal(shouldFail('high', 'invalid-severity'), false);
});
