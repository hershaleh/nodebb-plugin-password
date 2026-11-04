'use strict';

// Automatic protection rules + background jobs (expiry reminders).

const winston = require.main.require('winston');
const groupsLib = require.main.require('./src/groups');

const store = require('./store');
const perms = require('./perms');
const pcrypto = require('./crypto');
const settings = require('./settings');
const notify = require('./notify');
const { PPError } = require('./manage');

const ids = a => (Array.isArray(a) ? a.map(Number).filter(n => Number.isFinite(n) && n > 0) : []);
const strs = a => (Array.isArray(a) ? a.filter(x => typeof x === 'string').slice(0, 100) : []);
const ts = (v) => {
	if (!v) return 0;
	const n = typeof v === 'number' ? v : Date.parse(v);
	if (!Number.isFinite(n)) throw new PPError('invalid-date');
	return n;
};

const publicRule = r => ({ ...r, hash: undefined, hasPassword: !!r.hash });
exports.publicRule = publicRule;

async function authorize(uid) {
	if (!(await perms.can(uid, 'manageAutoRules'))) throw new PPError('forbidden', 403);
}

exports.list = async (uid) => {
	await authorize(uid);
	return (await store.listRules()).map(publicRule);
};

exports.save = async ({ actorUid, rule, ip }) => {
	await authorize(actorUid);
	const existing = rule.id ? await store.getRule(rule.id) : null;
	if (rule.id && !existing) throw new PPError('not-found', 404);
	const clean = {
		id: existing ? existing.id : undefined,
		name: String(rule.name || '').slice(0, 100) || 'Rule',
		enabled: rule.enabled !== false,
		conditions: { cids: ids(rule.conditions && rule.conditions.cids), uids: ids(rule.conditions && rule.conditions.uids), groups: strs(rule.conditions && rule.conditions.groups) },
		exceptions: { cids: ids(rule.exceptions && rule.exceptions.cids), uids: ids(rule.exceptions && rule.exceptions.uids), groups: strs(rule.exceptions && rule.exceptions.groups) },
		startAt: ts(rule.startAt),
		endAt: ts(rule.endAt),
		removeAt: ts(rule.removeAt),
		durationHours: Math.max(0, parseInt(rule.durationHours, 10) || 0),
		message: String(rule.message || '').slice(0, 1000),
		lockChange: !!rule.lockChange,
		lockRemove: !!rule.lockRemove,
		hash: existing ? existing.hash : '',
	};
	const c = clean.conditions;
	if (!c.cids.length && !c.uids.length && !c.groups.length) throw new PPError('rule-needs-condition');
	if (rule.password) clean.hash = await pcrypto.hash(String(rule.password));
	if (!clean.hash) throw new PPError('password-required');
	const saved = await store.saveRule(clean);
	await store.log({ uid: actorUid, action: existing ? 'rule-updated' : 'rule-created', key: `rule:${saved.id}`, ip, detail: { name: saved.name, enabled: saved.enabled } });
	return publicRule(saved);
};

exports.toggle = async ({ actorUid, id, enabled, ip }) => {
	await authorize(actorUid);
	const r = await store.getRule(id);
	if (!r) throw new PPError('not-found', 404);
	r.enabled = !!enabled;
	await store.saveRule(r);
	await store.log({ uid: actorUid, action: 'rule-toggled', key: `rule:${id}`, ip, detail: { enabled: r.enabled } });
	return publicRule(r);
};

exports.delete = async ({ actorUid, id, ip }) => {
	await authorize(actorUid);
	await store.deleteRule(id);
	await store.log({ uid: actorUid, action: 'rule-deleted', key: `rule:${id}`, ip });
	return { id };
};

async function matches(rule, topic) {
	const now = Date.now();
	if (!rule.enabled) return false;
	if (rule.startAt && now < rule.startAt) return false;
	if (rule.endAt && now >= rule.endAt) return false;
	const uid = parseInt(topic.uid, 10) || 0;
	const cid = parseInt(topic.cid, 10);
	const inGroups = async (list) => {
		if (!list.length || !(uid > 0)) return false;
		return (await groupsLib.isMemberOfGroups(uid, list)).some(Boolean);
	};
	const x = rule.exceptions || {};
	if ((x.cids || []).includes(cid) || (x.uids || []).includes(uid) || await inGroups(x.groups || [])) return false;
	const c = rule.conditions;
	if (c.cids.length && !c.cids.includes(cid)) return false;
	if (c.uids.length && !c.uids.includes(uid)) return false;
	if (c.groups.length && !(await inGroups(c.groups))) return false;
	return true;
}
exports.matches = matches;

/** action:topic.post - protect new topics matching an enabled rule. */
exports.onTopicPost = async (data) => {
	try {
		const topic = data && data.topic;
		if (!topic || !topic.tid) return;
		const key = `t:${topic.tid}`;
		if (await store.get(key)) return; // never override an existing protection
		for (const rule of await store.listRules()) {
			// eslint-disable-next-line no-await-in-loop
			if (!(await matches(rule, topic))) continue;
			const now = Date.now();
			let endAt = 0;
			if (rule.durationHours) endAt = now + rule.durationHours * 3600000;
			if (rule.removeAt) endAt = endAt ? Math.min(endAt, rule.removeAt) : rule.removeAt;
			// eslint-disable-next-line no-await-in-loop
			await store.save(key, {
				hash: rule.hash, version: now, message: rule.message, enabled: true, startAt: 0, endAt,
				createdAt: now, setBy: 0, creatorUid: topic.uid, source: 'auto', ruleId: String(rule.id),
				lockChange: rule.lockChange, lockRemove: rule.lockRemove,
			});
			// eslint-disable-next-line no-await-in-loop
			await store.log({ uid: 0, action: 'auto-protection', key, detail: { rule: rule.name, ruleId: rule.id } });
			// eslint-disable-next-line no-await-in-loop
			await notify.ownerEvent({ event: 'added', tid: topic.tid, actorUid: 0 });
			return; // first matching rule wins
		}
	} catch (e) {
		winston.error(`[password-protect] auto rule failed: ${e.stack}`);
	}
};

// ---------- background job: expiry reminders ----------

let timer = null;

async function tick() {
	try {
		const cfg = await settings.get();
		if (!cfg.notifications.expiryReminder) return;
		const due = await store.dueReminders(Date.now() + cfg.notifications.reminderHours * 3600000);
		for (const a of due) {
			// eslint-disable-next-line no-await-in-loop
			if (await store.claimReminder(a.id)) {
				// eslint-disable-next-line no-await-in-loop
				await notify.expiryReminder({ uid: a.uid, key: a.key, expiresAt: a.expiresAt });
			}
		}
	} catch (e) {
		winston.warn(`[password-protect] reminder job: ${e.message}`);
	}
}

exports.startJobs = () => {
	if (timer) return;
	timer = setInterval(tick, 60000);
	if (timer.unref) timer.unref();
};
exports.tick = tick;
