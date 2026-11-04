'use strict';
const test = require('node:test');
const assert = require('node:assert');
const pc = require('../../lib/crypto');

test('hash is salted, never plaintext, and verifies', async () => {
	const a = await pc.hash('correct horse');
	const b = await pc.hash('correct horse');
	assert.notStrictEqual(a, b, 'salt must differ');
	assert.ok(!a.includes('correct horse'));
	assert.strictEqual(await pc.verify('correct horse', a), true);
	assert.strictEqual(await pc.verify('wrong', a), false);
});

test('invalid input fails closed', async () => {
	await assert.rejects(pc.hash(''));
	await assert.rejects(pc.hash('x'.repeat(257)));
	assert.strictEqual(await pc.verify('x', ''), false);
	assert.strictEqual(await pc.verify('x', 'garbage'), false);
	assert.strictEqual(await pc.verify(null, 'scrypt$1$1$1$a$b'), false);
});
