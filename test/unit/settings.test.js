'use strict';
const test = require('node:test');
const assert = require('node:assert');
require('./_stub');
const settings = require('../../lib/settings');

test('defaults: bypass is separate from management and empty', () => {
	assert.deepStrictEqual(settings.DEFAULTS.permissions.bypass, []);
	assert.ok(settings.DEFAULTS.permissions.manageSettings.includes('administrators'));
});

test('default limits match the spec (5 attempts, 5 minutes, progressive)', () => {
	assert.strictEqual(settings.DEFAULTS.limits.maxAttempts, 5);
	assert.strictEqual(settings.DEFAULTS.limits.blockMinutes, 5);
	assert.strictEqual(settings.DEFAULTS.limits.progressive, true);
	assert.strictEqual(settings.DEFAULTS.remember.mode, 'session');
	assert.strictEqual(settings.DEFAULTS.notifications.reminderHours, 24);
	assert.strictEqual(settings.DEFAULTS.policy, 'topic');
});

test('sanitize clamps bad input and rejects unknown enums', () => {
	const s = settings.sanitize({
		policy: 'nonsense', remember: { mode: 'forever', minutes: -4 },
		limits: { maxAttempts: 'x', blockMinutes: 99999999 },
		notifications: { reminderHours: 0, replyContent: 'full' },
	}, settings.DEFAULTS);
	assert.strictEqual(s.policy, 'topic');
	assert.strictEqual(s.remember.mode, 'session');
	assert.strictEqual(s.remember.minutes, 1);
	assert.strictEqual(s.limits.maxAttempts, 5);
	assert.strictEqual(s.limits.blockMinutes, 10080);
	assert.strictEqual(s.notifications.reminderHours, 1);
	assert.strictEqual(s.notifications.replyContent, 'generic');
});

test('administrators can never be removed from manageSettings', () => {
	const s = settings.sanitize({ permissions: { manageSettings: [] } }, settings.DEFAULTS);
	assert.ok(s.permissions.manageSettings.includes('administrators'));
});
