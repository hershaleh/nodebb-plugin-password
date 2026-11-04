'use strict';

const db = require.main.require('./src/database');

const PERMISSIONS = [
	'createTopicProtection', 'changeTopicPassword', 'removeTopicProtection', 'protectOthersTopics',
	'lockChange', 'lockRemove', 'manageCategoryProtection', 'manageAutoRules',
	'grantPersonalAccess', 'viewLog', 'manageSettings', 'bypass',
];

const DEFAULTS = {
	policy: 'topic', // topic | category | both
	remember: { mode: 'session', minutes: 60 }, // none | session | timed
	sessionMaxHours: 24,
	limits: { maxAttempts: 5, blockMinutes: 5, progressive: true },
	notifications: {
		ownerAdded: true, ownerChanged: true, ownerRemoved: true, ownerLocked: true,
		adminAlerts: true, adminAlertThreshold: 5,
		expiryReminder: true, reminderHours: 24,
		replyContent: 'generic', // generic | none  (never reveals content to unauthorised users)
	},
	permissions: {
		createTopicProtection: ['registered-users'],
		changeTopicPassword: ['administrators'],
		removeTopicProtection: ['administrators'],
		protectOthersTopics: ['administrators'],
		lockChange: ['administrators'],
		lockRemove: ['administrators'],
		manageCategoryProtection: ['administrators'],
		manageAutoRules: ['administrators'],
		grantPersonalAccess: ['administrators'],
		viewLog: ['administrators'],
		manageSettings: ['administrators'],
		bypass: [], // deliberately separate: managing protections never implies viewing them
	},
};

const clone = o => JSON.parse(JSON.stringify(o));
function merge(base, over) {
	const out = clone(base);
	if (!over || typeof over !== 'object') return out;
	Object.keys(out).forEach((k) => {
		if (over[k] === undefined) return;
		if (out[k] && typeof out[k] === 'object' && !Array.isArray(out[k])) out[k] = merge(out[k], over[k]);
		else out[k] = over[k];
	});
	return out;
}

let cache = null;
let cacheAt = 0;

exports.PERMISSIONS = PERMISSIONS;
exports.DEFAULTS = DEFAULTS;

exports.get = async () => {
	if (cache && Date.now() - cacheAt < 3000) return cache;
	const o = await db.getObject('pp:settings');
	let stored = {};
	try { stored = o && o.json ? JSON.parse(o.json) : {}; } catch (e) { stored = {}; }
	cache = merge(DEFAULTS, stored);
	cacheAt = Date.now();
	return cache;
};

const int = (v, min, max, d) => {
	const n = parseInt(v, 10);
	return Number.isFinite(n) ? Math.min(Math.max(n, min), max) : d;
};

exports.sanitize = (input, current) => {
	const s = merge(current, input);
	if (!['topic', 'category', 'both'].includes(s.policy)) s.policy = 'topic';
	if (!['none', 'session', 'timed'].includes(s.remember.mode)) s.remember.mode = 'session';
	s.remember.minutes = int(s.remember.minutes, 1, 525600, 60);
	s.sessionMaxHours = int(s.sessionMaxHours, 1, 720, 24);
	s.limits.maxAttempts = int(s.limits.maxAttempts, 1, 100, 5);
	s.limits.blockMinutes = int(s.limits.blockMinutes, 1, 10080, 5);
	s.limits.progressive = !!s.limits.progressive;
	const n = s.notifications;
	['ownerAdded', 'ownerChanged', 'ownerRemoved', 'ownerLocked', 'adminAlerts', 'expiryReminder']
		.forEach((f) => { n[f] = !!n[f]; });
	n.adminAlertThreshold = int(n.adminAlertThreshold, 1, 1000, 5);
	n.reminderHours = int(n.reminderHours, 1, 8760, 24);
	if (!['generic', 'none'].includes(n.replyContent)) n.replyContent = 'generic';
	PERMISSIONS.forEach((p) => {
		const list = s.permissions[p];
		s.permissions[p] = Array.isArray(list) ? list.filter(g => typeof g === 'string').slice(0, 100) : [];
	});
	// never lock administrators out of managing the plugin
	if (!s.permissions.manageSettings.includes('administrators')) s.permissions.manageSettings.push('administrators');
	return s;
};

exports.set = async (input) => {
	const next = exports.sanitize(input, await exports.get());
	await db.setObject('pp:settings', { json: JSON.stringify(next) });
	cache = next;
	cacheAt = Date.now();
	return next;
};

exports.invalidate = () => { cache = null; };
