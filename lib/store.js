'use strict';

// Persistence layer: protections, exemptions, personal access, rules, log.
// Passwords are only ever stored as hashes and never appear in log entries.

const db = require.main.require('./src/database');
const policy = require('./policy');

const PK = key => `pp:prot:${key}`;
const NUM = ['version', 'creatorUid', 'setBy', 'startAt', 'endAt', 'createdAt', 'updatedAt'];
const BOOL = ['lockChange', 'lockRemove', 'hidden'];

function parse(o) {
	if (!o || !Object.keys(o).length) return null;
	const p = { ...o };
	NUM.forEach((f) => { p[f] = o[f] ? Number(o[f]) : 0; });
	BOOL.forEach((f) => { p[f] = o[f] === '1'; });
	p.enabled = o.enabled !== '0';
	p.hash = o.hash || '';
	p.message = o.message || '';
	p.source = o.source || 'manual';
	p.ruleId = o.ruleId || '';
	p.bypassGroups = [];
	try { const l = JSON.parse(o.bypassGroups || '[]'); if (Array.isArray(l)) p.bypassGroups = l.filter(g => typeof g === 'string'); } catch (e) { /* none */ }
	return p;
}

function serialize(fields) {
	const out = {};
	Object.keys(fields).forEach((f) => {
		const v = fields[f];
		if (v === undefined) return;
		out[f] = typeof v === 'boolean' ? (v ? '1' : '0') : (Array.isArray(v) ? JSON.stringify(v) : String(v));
	});
	return out;
}

exports.isActive = policy.isActive;

exports.get = async key => parse(await db.getObject(PK(key)));

exports.getMany = async (keys) => {
	const out = {};
	if (!keys.length) return out;
	const objs = await db.getObjects(keys.map(PK));
	keys.forEach((k, i) => { out[k] = parse(objs[i]); });
	return out;
};

exports.save = async (key, fields) => {
	await db.setObject(PK(key), serialize({ ...fields, updatedAt: Date.now() }));
	await db.setAdd('pp:prots', key);
};

exports.remove = async (key) => {
	await db.delete(PK(key));
	await db.setRemove('pp:prots', key);
};

exports.keys = async () => await db.getSetMembers('pp:prots');
exports.count = async () => await db.setCount('pp:prots');

exports.list = async () => {
	const keys = await exports.keys();
	const map = await exports.getMany(keys);
	return keys.filter(k => map[k]).map(k => ({ key: k, ...map[k] }));
};

// ---- topic exemption from inherited category protection ----
exports.setExempt = async (tid, on) => {
	if (on) await db.setAdd('pp:exempt', String(tid));
	else await db.setRemove('pp:exempt', String(tid));
};
exports.exemptMap = async (tids) => {
	const res = await db.isSetMembers('pp:exempt', tids.map(String));
	const out = {};
	tids.forEach((t, i) => { out[t] = !!res[i]; });
	return out;
};

// ---- personal access ----
const AK = id => `pp:acc:${id}`;

exports.grantAccess = async ({ uid, key, grantedBy, expiresAt }) => {
	const id = await db.incrObjectField('global', 'nextPPAccessId');
	const now = Date.now();
	await db.setObject(AK(id), serialize({
		id, uid, key, grantedBy, grantedAt: now, expiresAt: expiresAt || 0, revokedAt: 0, remindedAt: 0,
	}));
	await db.sortedSetAdd('pp:acc:all', now, id);
	await db.sortedSetAdd(`pp:acc:uid:${uid}`, now, id);
	if (expiresAt) await db.sortedSetAdd('pp:acc:exp', expiresAt, id);
	return id;
};

function parseAccess(o) {
	if (!o || !o.id) return null;
	return {
		id: Number(o.id), uid: Number(o.uid), key: o.key, grantedBy: Number(o.grantedBy),
		grantedAt: Number(o.grantedAt), expiresAt: Number(o.expiresAt) || 0,
		revokedAt: Number(o.revokedAt) || 0, remindedAt: Number(o.remindedAt) || 0,
	};
}
const accessActive = (a, now) => a && !a.revokedAt && (!a.expiresAt || now < a.expiresAt);
exports.accessActive = accessActive;

exports.getAccess = async id => parseAccess(await db.getObject(AK(id)));

exports.revokeAccess = async (id) => {
	await db.setObject(AK(id), { revokedAt: String(Date.now()) });
	await db.sortedSetRemove('pp:acc:exp', id);
};

exports.listAccess = async () => {
	const ids = await db.getSortedSetRevRange('pp:acc:all', 0, 999);
	const objs = await db.getObjects(ids.map(AK));
	return objs.map(parseAccess).filter(Boolean);
};

exports.activePersonalKeys = async (uid) => {
	const out = new Set();
	if (!(uid > 0)) return out;
	const ids = await db.getSortedSetRange(`pp:acc:uid:${uid}`, 0, -1);
	if (!ids.length) return out;
	const now = Date.now();
	(await db.getObjects(ids.map(AK))).map(parseAccess).forEach((a) => {
		if (accessActive(a, now)) out.add(a.key);
	});
	return out;
};

exports.dueReminders = async (untilTs) => {
	const ids = await db.getSortedSetRangeByScore('pp:acc:exp', 0, 100, Date.now(), untilTs);
	return (await db.getObjects(ids.map(AK))).map(parseAccess).filter(a => a && !a.revokedAt && !a.remindedAt);
};
exports.claimReminder = async (id) => {
	const n = await db.incrObjectField(AK(id), 'remindTicket');
	if (n !== 1) return false; // another instance took it
	await db.setObject(AK(id), { remindedAt: String(Date.now()) });
	return true;
};

// ---- rules ----
const RK = id => `pp:rule:${id}`;
exports.saveRule = async (rule) => {
	if (!rule.id) {
		rule.id = await db.incrObjectField('global', 'nextPPRuleId');
		await db.sortedSetAdd('pp:rules', Date.now(), rule.id);
	}
	await db.setObject(RK(rule.id), { json: JSON.stringify(rule) });
	return rule;
};
exports.getRule = async (id) => {
	const o = await db.getObject(RK(id));
	return o && o.json ? JSON.parse(o.json) : null;
};
exports.listRules = async () => {
	const ids = await db.getSortedSetRange('pp:rules', 0, -1);
	return (await db.getObjects(ids.map(RK))).filter(o => o && o.json).map(o => JSON.parse(o.json));
};
exports.deleteRule = async (id) => {
	await db.delete(RK(id));
	await db.sortedSetRemove('pp:rules', id);
};

// ---- audit log ----
function scrub(detail) {
	if (!detail || typeof detail !== 'object') return {};
	const out = {};
	Object.keys(detail).forEach((k) => {
		if (/pass|hash|secret|token/i.test(k)) return;
		out[k] = detail[k];
	});
	return out;
}

exports.log = async ({ uid = 0, action, key = '', result = 'ok', detail = {}, ip = '' }) => {
	try {
		const id = await db.incrObjectField('global', 'nextPPLogId');
		const ts = Date.now();
		await db.setObject(`pp:log:${id}`, {
			id, uid, action, key, result, ts, ip, detail: JSON.stringify(scrub(detail)),
		});
		await db.sortedSetAdd('pp:log', ts, id);
	} catch (e) {
		// logging must never break or open access
	}
};

exports.getLog = async (start = 0, stop = 99) => {
	const ids = await db.getSortedSetRevRange('pp:log', start, stop);
	const objs = await db.getObjects(ids.map(id => `pp:log:${id}`));
	return objs.filter(Boolean).map(o => ({
		id: Number(o.id), uid: Number(o.uid), action: o.action, key: o.key, result: o.result,
		ts: Number(o.ts), detail: o.detail ? JSON.parse(o.detail) : {},
	}));
};
exports.logCount = async () => await db.sortedSetCard('pp:log');

exports.removeAllForKey = async (key) => {
	await exports.remove(key);
	const m = policy.parseKey(key);
	if (m && m.type === 't') await exports.setExempt(m.id, false);
};
