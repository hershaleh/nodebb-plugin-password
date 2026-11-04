'use strict';
const test = require('node:test');
const assert = require('node:assert');
const policy = require('../../lib/policy');

test('requiredKeys: single protections', () => {
	assert.deepStrictEqual(policy.requiredKeys({ cat: 'c:1', topic: null, mode: 'topic' }), ['c:1']);
	assert.deepStrictEqual(policy.requiredKeys({ cat: null, topic: 't:2', mode: 'topic' }), ['t:2']);
	assert.deepStrictEqual(policy.requiredKeys({ cat: null, topic: null, mode: 'both' }), []);
});

test('requiredKeys: collision policy topic / category / both', () => {
	const base = { cat: 'c:1', topic: 't:2', exempt: false };
	assert.deepStrictEqual(policy.requiredKeys({ ...base, mode: 'topic' }), ['t:2']);
	assert.deepStrictEqual(policy.requiredKeys({ ...base, mode: 'category' }), ['c:1']);
	assert.deepStrictEqual(policy.requiredKeys({ ...base, mode: 'both' }), ['c:1', 't:2']);
});

test('exemption removes only the inherited category protection', () => {
	assert.deepStrictEqual(policy.requiredKeys({ cat: 'c:1', topic: null, exempt: true, mode: 'topic' }), []);
	assert.deepStrictEqual(policy.requiredKeys({ cat: 'c:1', topic: 't:2', exempt: true, mode: 'both' }), ['t:2']);
});

test('isActive honours enabled flag, hash and time window', () => {
	const now = 1000;
	assert.strictEqual(policy.isActive(null, now), false);
	assert.strictEqual(policy.isActive({ enabled: false, hash: 'x' }, now), false);
	assert.strictEqual(policy.isActive({ enabled: true, hash: '' }, now), false);
	assert.strictEqual(policy.isActive({ enabled: true, hash: 'x' }, now), true);
	assert.strictEqual(policy.isActive({ enabled: true, hash: 'x', startAt: 2000 }, now), false);
	assert.strictEqual(policy.isActive({ enabled: true, hash: 'x', endAt: 1000 }, now), false);
	assert.strictEqual(policy.isActive({ enabled: true, hash: 'x', startAt: 500, endAt: 2000 }, now), true);
});

test('grantValid: password change (new version) invalidates old grants; expiry enforced', () => {
	const prot = { version: 3 };
	assert.strictEqual(policy.grantValid('3:5000', prot, 1000), true);
	assert.strictEqual(policy.grantValid('2:5000', prot, 1000), false);
	assert.strictEqual(policy.grantValid('3:900', prot, 1000), false);
	assert.strictEqual(policy.grantValid(undefined, prot, 1000), false);
	assert.strictEqual(policy.grantValid('3:5000', null, 1000), false);
});

test('parseKey', () => {
	assert.deepStrictEqual(policy.parseKey('c:12'), { type: 'c', id: 12 });
	assert.deepStrictEqual(policy.parseKey('t:7'), { type: 't', id: 7 });
	assert.strictEqual(policy.parseKey('x:1'), null);
	assert.strictEqual(policy.parseKey('t:abc'), null);
});
