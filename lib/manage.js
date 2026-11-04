'use strict';

// Business logic for protections and personal access. Every function checks
// permissions itself; the HTTP layer never decides authorisation.

const topics = require.main.require('./src/topics');
const categories = require.main.require('./src/categories');
const user = require.main.require('./src/user');

const store = require('./store');
const perms = require('./perms');
const pcrypto = require('./crypto');
const policy = require('./policy');
const notify = require('./notify');
const settings = require('./settings');

class PPError extends Error {
	constructor(code, status, extra) {
		super(code);
		this.code = code;
		this.status = status || 400;
		this.extra = extra || {};
	}
}
exports.PPError = PPError;

const toTs = (v) => {
	if (v === undefined || v === null || v === '' || v === 0) return 0;
	const n = typeof v === 'number' ? v : Date.parse(v);
	if (!Number.isFinite(n) || n < 0) throw new PPError('invalid-date');
	return n;
};

async function describe(key) {
	const k = policy.parseKey(key);
	if (!k) throw new PPError('invalid-key');
	if (k.type === 't') {
		const t = await topics.getTopicFields(k.id, ['tid', 'uid', 'cid', 'title', 'slug']);
		if (!t || !t.tid) throw new PPError('not-found', 404);
		return { type: 't', id: k.id, owner: parseInt(t.uid, 10) || 0, cid: parseInt(t.cid, 10), title: t.title, slug: t.slug };
	}
	const c = await categories.getCategoryFields(k.id, ['cid', 'name', 'slug']);
	if (!c || !c.cid) throw new PPError('not-found', 404);
	return { type: 'c', id: k.id, owner: 0, title: c.name, slug: c.slug };
}
exports.describe = describe;

async function authorize(uid, action, item, existing) {
	if (item.type === 'c') return await perms.can(uid, 'manageCategoryProtection');
	const isOwner = uid > 0 && item.owner === uid;
	if (action === 'create') {
		if (await perms.can(uid, 'protectOthersTopics')) return true;
		return isOwner && await perms.can(uid, 'createTopicProtection');
	}
	const name = action === 'change' ? 'changeTopicPassword' : 'removeTopicProtection';
	if (await perms.can(uid, name)) return true;
	if (isOwner && existing && existing.setBy === uid) {
		return !(action === 'change' ? existing.lockChange : existing.lockRemove);
	}
	return false;
}

// Custom prompt message: only groups with the permission, or any creator who may
// protect, depending on the "messageWho" setting. Authorisation to protect is checked separately.
async function canSetMessage(uid) {
	const cfg = await settings.get();
	if (cfg.messageWho === 'creators') return true;
	return await perms.can(uid, 'customMessage');
}
exports.canSetMessage = canSetMessage;

function publicView(key, p, item) {
	if (!p) return { key, protected: false };
	return {
		key,
		protected: true,
		type: item ? item.type : policy.parseKey(key).type,
		id: item ? item.id : policy.parseKey(key).id,
		title: item ? item.title : '',
		enabled: p.enabled,
		message: p.message,
		startAt: p.startAt,
		endAt: p.endAt,
		hidden: p.hidden,
		source: p.source,
		ruleId: p.ruleId,
		setBy: p.setBy,
		createdAt: p.createdAt,
		lockChange: p.lockChange,
		lockRemove: p.lockRemove,
		active: policy.isActive(p, Date.now()),
	};
}
exports.publicView = publicView;

exports.getForActor = async (uid, key) => {
	const item = await describe(key);
	const p = await store.get(key);
	const can = {
		create: await authorize(uid, 'create', item, null),
		change: await authorize(uid, 'change', item, p),
		remove: await authorize(uid, 'remove', item, p),
		lockChange: await perms.can(uid, 'lockChange'),
		lockRemove: await perms.can(uid, 'lockRemove'),
		exempt: item.type === 't' && await perms.can(uid, 'manageCategoryProtection'),
		message: await canSetMessage(uid),
	};
	if (!p && !can.create) throw new PPError('forbidden', 403);
	if (p && !(can.change || can.remove || can.create)) throw new PPError('forbidden', 403);
	const exemptMap = item.type === 't' ? await store.exemptMap([item.id]) : {};
	return { ...publicView(key, p, item), can, exempt: !!exemptMap[item.id] };
};

exports.set = async ({ actorUid, key, password, message, startAt, endAt, hidden, enabled, exempt, ip }) => {
	const item = await describe(key);
	const existing = await store.get(key);
	const action = existing ? 'change' : 'create';
	if (!(await authorize(actorUid, action, item, existing))) throw new PPError('forbidden', 403);

	const s = toTs(startAt);
	const e = toTs(endAt);
	if (s && e && e <= s) throw new PPError('invalid-date-range');
	const mayMessage = await canSetMessage(actorUid);
	if (mayMessage && typeof message === 'string' && message.length > 1000) throw new PPError('message-too-long');
	if (!existing && !password) throw new PPError('password-required');

	const fields = {
		message: mayMessage && typeof message === 'string' ? message.trim() : (existing ? existing.message : ''),
		startAt: s,
		endAt: e,
		enabled: enabled === undefined ? (existing ? existing.enabled : true) : !!enabled,
	};
	if (item.type === 'c') fields.hidden = hidden === undefined ? (existing ? existing.hidden : false) : !!hidden;
	if (password) {
		fields.hash = await pcrypto.hash(String(password));
		fields.version = Date.now(); // invalidates every grant made with the old password
	}
	if (!existing) {
		Object.assign(fields, {
			createdAt: Date.now(), setBy: actorUid, creatorUid: item.owner, source: 'manual', ruleId: '', lockChange: false, lockRemove: false,
		});
	}
	await store.save(key, fields);

	if (item.type === 't' && exempt !== undefined && await perms.can(actorUid, 'manageCategoryProtection')) {
		await store.setExempt(item.id, !!exempt);
	}

	const event = !existing ? 'protection-created' : (password ? 'password-changed' : 'protection-updated');
	await store.log({ uid: actorUid, action: event, key, ip, detail: { title: item.title, passwordChanged: !!password } });
	if (item.type === 't') await notify.ownerEvent({ event: !existing ? 'added' : (password ? 'changed' : null), tid: item.id, actorUid }).catch(() => {});
	return publicView(key, await store.get(key), item);
};

exports.remove = async ({ actorUid, key, ip }) => {
	const item = await describe(key);
	const existing = await store.get(key);
	if (!existing) throw new PPError('not-protected', 404);
	if (!(await authorize(actorUid, 'remove', item, existing))) throw new PPError('forbidden', 403);
	await store.removeAllForKey(key);
	await store.log({ uid: actorUid, action: 'protection-removed', key, ip, detail: { title: item.title } });
	if (item.type === 't') await notify.ownerEvent({ event: 'removed', tid: item.id, actorUid });
	return { key, protected: false };
};

exports.setLock = async ({ actorUid, key, lockChange, lockRemove, ip }) => {
	const item = await describe(key);
	if (item.type !== 't') throw new PPError('invalid-key');
	const existing = await store.get(key);
	if (!existing) throw new PPError('not-protected', 404);
	const fields = {};
	if (lockChange !== undefined) {
		if (!(await perms.can(actorUid, 'lockChange'))) throw new PPError('forbidden', 403);
		fields.lockChange = !!lockChange;
	}
	if (lockRemove !== undefined) {
		if (!(await perms.can(actorUid, 'lockRemove'))) throw new PPError('forbidden', 403);
		fields.lockRemove = !!lockRemove;
	}
	if (!Object.keys(fields).length) throw new PPError('nothing-to-change');
	await store.save(key, fields);
	await store.log({ uid: actorUid, action: 'creator-lock', key, ip, detail: fields });
	const locked = fields.lockChange || fields.lockRemove;
	await notify.ownerEvent({ event: locked ? 'locked' : 'unlocked', tid: item.id, actorUid });
	return publicView(key, await store.get(key), item);
};

/** "Forgot password": owner re-authenticates against NodeBB itself, then sets a new password. */
exports.ownerReset = async ({ actorUid, key, accountPassword, newPassword, ip }) => {
	const item = await describe(key);
	if (item.type !== 't') throw new PPError('invalid-key');
	const existing = await store.get(key);
	if (!existing) throw new PPError('not-protected', 404);
	if (!(actorUid > 0) || item.owner !== actorUid || existing.setBy !== actorUid || existing.lockChange) {
		throw new PPError('forbidden', 403);
	}
	if (!newPassword) throw new PPError('password-required');
	if (!(await user.hasPassword(actorUid))) throw new PPError('reauth-unavailable', 400);
	const auth = user.auth;
	if (auth && auth.logAttempt) await auth.logAttempt(actorUid, ip); // throws when NodeBB's own limiter trips
	const ok = await user.isPasswordCorrect(actorUid, String(accountPassword || ''), ip);
	if (!ok) {
		await store.log({ uid: actorUid, action: 'password-reset', key, ip, result: 'reauth-failed' });
		throw new PPError('reauth-failed', 403);
	}
	if (auth && auth.clearLoginAttempts) await auth.clearLoginAttempts(actorUid);
	await store.save(key, { hash: await pcrypto.hash(String(newPassword)), version: Date.now() });
	await store.log({ uid: actorUid, action: 'password-reset', key, ip });
	return { key, reset: true };
};

// ---------- personal access ----------

exports.grantAccess = async ({ actorUid, uid, key, expiresAt, ip }) => {
	if (!(await perms.can(actorUid, 'grantPersonalAccess'))) throw new PPError('forbidden', 403);
	const item = await describe(key);
	if (!(await user.exists(uid))) throw new PPError('user-not-found', 404);
	const exp = toTs(expiresAt);
	if (exp && exp <= Date.now()) throw new PPError('invalid-date');
	const id = await store.grantAccess({ uid, key, grantedBy: actorUid, expiresAt: exp });
	await store.log({ uid: actorUid, action: 'access-granted', key, ip, detail: { target: uid, expiresAt: exp, title: item.title } });
	return { id };
};

exports.revokeAccess = async ({ actorUid, id, ip }) => {
	if (!(await perms.can(actorUid, 'grantPersonalAccess'))) throw new PPError('forbidden', 403);
	const a = await store.getAccess(id);
	if (!a) throw new PPError('not-found', 404);
	await store.revokeAccess(id);
	await store.log({ uid: actorUid, action: 'access-revoked', key: a.key, ip, detail: { target: a.uid } });
	return { id };
};

exports.listAccess = async (actorUid) => {
	if (!(await perms.can(actorUid, 'grantPersonalAccess'))) throw new PPError('forbidden', 403);
	const list = await store.listAccess();
	const names = await user.getUsersFields([...new Set(list.map(a => a.uid))], ['uid', 'username']);
	const byUid = {};
	names.forEach((u) => { byUid[u.uid] = u.username; });
	const now = Date.now();
	return list.map(a => ({ ...a, username: byUid[a.uid] || '', active: store.accessActive(a, now) }));
};
