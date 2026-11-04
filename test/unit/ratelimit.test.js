'use strict';
const test = require('node:test');
const assert = require('node:assert');
const db = require('./_stub');
const limiter = require('../../lib/ratelimit')(db);

const cfg = { maxAttempts: 5, blockMinutes: 5, progressive: false };

test('blocks after maxAttempts failures for 5 minutes', async () => {
	db._reset();
	const id = 'u1:c:1';
	for (let i = 0; i < 4; i++) {
		await limiter.fail([id], cfg);
		assert.strictEqual((await limiter.check([id])).blocked, false);
	}
	await limiter.fail([id], cfg);
	const r = await limiter.check([id]);
	assert.strictEqual(r.blocked, true);
	assert.ok(r.retryAfter > 290 && r.retryAfter <= 300);
});

test('repeated blocks grow progressively and are capped', async () => {
	db._reset();
	const id = 'ip:1.2.3.4';
	const c = { ...cfg, progressive: true, maxAttempts: 1 };
	// stub sleep cost: progressive adds <=3s delay per failure; keep the loop small
	await limiter.fail([id], c);
	const first = (await limiter.check([id])).retryAfter;
	await limiter.fail([id], c);
	const second = (await limiter.check([id])).retryAfter;
	assert.ok(second > first * 1.5, `expected growth, got ${first} -> ${second}`);
	assert.ok(second <= 24 * 3600);
});

test('success resets the counter; other ids unaffected', async () => {
	db._reset();
	await limiter.fail(['a'], cfg);
	await limiter.succeed(['a']);
	for (let i = 0; i < 4; i++) await limiter.fail(['a'], cfg);
	assert.strictEqual((await limiter.check(['a'])).blocked, false);
	assert.strictEqual((await limiter.check(['b'])).blocked, false);
});
