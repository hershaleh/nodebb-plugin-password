'use strict';

// HTTP API: /api/v3/plugins/password-protect/*  (all non-GET routes carry CSRF protection)
// plus the seven ACP page routes.

const winston = require.main.require('winston');
const db = require.main.require('./src/database');
const topics = require.main.require('./src/topics');
const categories = require.main.require('./src/categories');
const user = require.main.require('./src/user');
const groupsLib = require.main.require('./src/groups');

const store = require('./store');
const settings = require('./settings');
const perms = require('./perms');
const pcrypto = require('./crypto');
const grantsLib = require('./grants');
const policy = require('./policy');
const guard = require('./guard');
const manage = require('./manage');
const auto = require('./auto');
const notify = require('./notify');
const limiter = require('./ratelimit')(db);

const { PPError } = manage;
const BASE = '/api/v3/plugins/password-protect';
const ACP_PAGES = ['manage', 'settings', 'categories', 'topics', 'permissions', 'rules', 'access', 'log'];

const uidOf = req => guard.uidOf(req);
const ok = (res, response) => res.json({ status: { code: 'ok', message: 'OK' }, response: response || {} });

function fail(res, e) {
	if (e instanceof PPError) {
		return res.status(e.status).json({
			status: { code: e.status === 403 ? 'forbidden' : (e.status === 404 ? 'not-found' : (e.status === 429 ? 'too-many-requests' : 'bad-request')), message: `[[password-protect:error.${e.code}]]` },
			response: e.extra,
		});
	}
	winston.error(`[password-protect] ${e.stack}`);
	return res.status(500).json({ status: { code: 'internal-server-error', message: '[[error:invalid-data]]' }, response: {} });
}

const h = fn => async (req, res) => {
	try {
		ok(res, await fn(req, res));
	} catch (e) {
		fail(res, e);
	}
};

const keyOf = req => `${req.params.type === 'c' ? 'c' : 't'}:${parseInt(req.params.id, 10)}`;
const mustLogin = (req) => {
	const uid = uidOf(req);
	if (!(uid > 0)) throw new PPError('forbidden', 403);
	return uid;
};

async function anyManager(uid) {
	const res = await perms.canMany(uid, ['manageCategoryProtection', 'protectOthersTopics', 'changeTopicPassword', 'removeTopicProtection']);
	if (!Object.values(res).some(Boolean)) throw new PPError('forbidden', 403);
}

async function requirePerm(req, perm) {
	const uid = mustLogin(req);
	if (!(await perms.can(uid, perm))) throw new PPError('forbidden', 403);
	return uid;
}

// ---------- public: status + unlock ----------

async function status(req) {
	const uid = uidOf(req);
	const path = String(req.query.path || '').split('?')[0];
	const target = guard.matchPath(path.startsWith('/') ? path : `/${path}`);
	if (!target || target.kind === 'upload') return { protected: false, pending: [] };
	const items = await guard.resolve(target);
	if (!items) return { protected: false, pending: [] };
	const ctx = await guard.context(uid, req);
	const [r] = await guard.evaluateMany(ctx, items);
	if (r.ok) return { protected: false, pending: [] };
	const pending = [];
	for (const key of r.pending) {
		const p = r.prots[key];
		const k = policy.parseKey(key);
		// eslint-disable-next-line no-await-in-loop
		const title = k.type === 't' ? await topics.getTopicField(k.id, 'title') : await categories.getCategoryField(k.id, 'name');
		pending.push({ key, type: k.type, title, message: p ? p.message : '' });
	}
	return { protected: true, pending };
}

async function unlock(req) {
	const uid = uidOf(req);
	const key = String(req.body.key || '');
	const password = typeof req.body.password === 'string' ? req.body.password : '';
	if (!policy.parseKey(key) || !password) throw new PPError('invalid-data');
	if (!req.sessionID) throw new PPError('no-session', 400);
	const cfg = await settings.get();
	const prot = await store.get(key);
	if (!prot || !policy.isActive(prot, Date.now())) return { key, unlocked: true, notProtected: true };

	const ids = [`ip:${req.ip}|${key}`];
	if (uid > 0) ids.push(`u:${uid}|${key}`);
	const gate = await limiter.check(ids);
	if (gate.blocked) {
		await store.log({ uid, action: 'attempt-blocked', key, result: 'rate-limited', ip: req.ip });
		throw new PPError('too-many-attempts', 429, { retryAfter: gate.retryAfter });
	}

	if (!(await pcrypto.verify(password, prot.hash))) {
		const n = await limiter.fail(ids, cfg.limits);
		await store.log({ uid, action: 'attempt-failed', key, result: 'wrong-password', ip: req.ip });
		if (n >= cfg.limits.maxAttempts || n >= cfg.notifications.adminAlertThreshold) {
			notify.adminAlert({ key, count: n, ip: req.ip }).catch(() => {});
		}
		throw new PPError('wrong-password', 403);
	}
	await limiter.succeed(ids);
	await grantsLib.grant(req.sessionID, key, prot.version, grantsLib.ttlMs(cfg));
	await store.log({ uid, action: 'attempt-success', key, ip: req.ip });
	return { key, unlocked: true };
}

// ---------- admin helpers ----------

async function listProtections(req) {
	const uid = mustLogin(req);
	await anyManager(uid);
	const rows = await store.list();
	const tids = rows.filter(r => r.key[0] === 't').map(r => parseInt(r.key.slice(2), 10));
	const cids = rows.filter(r => r.key[0] === 'c').map(r => parseInt(r.key.slice(2), 10));
	const [tf, cf] = await Promise.all([
		tids.length ? topics.getTopicsFields(tids, ['tid', 'uid', 'cid', 'title', 'slug']) : [],
		cids.length ? categories.getCategoriesFields(cids, ['cid', 'name', 'slug']) : [],
	]);
	const tmap = {};
	tf.forEach((t) => { if (t && t.tid) tmap[t.tid] = t; });
	const cmap = {};
	cf.forEach((c) => { if (c && c.cid) cmap[c.cid] = c; });
	const catIds = [...new Set(tf.filter(t => t && t.cid).map(t => parseInt(t.cid, 10)))];
	const catNames = {};
	(catIds.length ? await categories.getCategoriesFields(catIds, ['cid', 'name']) : []).forEach((c) => { catNames[c.cid] = c.name; });
	const owners = [...new Set(tf.filter(t => t && t.uid).map(t => parseInt(t.uid, 10)))];
	const unames = {};
	(owners.length ? await user.getUsersFields(owners, ['uid', 'username']) : []).forEach((u) => { unames[u.uid] = u.username; });
	const rules = {};
	(await store.listRules()).forEach((r) => { rules[r.id] = r.name; });
	const exempt = tids.length ? await store.exemptMap(tids) : {};

	return rows.map((r) => {
		const k = policy.parseKey(r.key);
		const t = k.type === 't' ? tmap[k.id] : null;
		const c = k.type === 'c' ? cmap[k.id] : null;
		if (!t && !c) return null; // orphan
		return {
			...manage.publicView(r.key, r, { type: k.type, id: k.id, title: t ? t.title : c.name }),
			slug: t ? t.slug : c.slug,
			tid: t ? t.tid : undefined,
			cid: t ? parseInt(t.cid, 10) : k.id,
			categoryName: t ? catNames[t.cid] || '' : '',
			creatorName: t ? unames[t.uid] || '' : '',
			ruleName: r.ruleId ? rules[r.ruleId] || `#${r.ruleId}` : '',
			exempt: !!exempt[k.id],
		};
	}).filter(Boolean);
}

async function getSettings(req) {
	await requirePerm(req, 'manageSettings');
	return { settings: await settings.get(), permissions: settings.PERMISSIONS, engine: pcrypto.engine() };
}

async function putSettings(req) {
	const uid = await requirePerm(req, 'manageSettings');
	const before = await settings.get();
	const next = await settings.set(req.body || {});
	const changedPerms = JSON.stringify(before.permissions) !== JSON.stringify(next.permissions);
	await store.log({ uid, action: changedPerms ? 'permissions-changed' : 'settings-changed', ip: req.ip, detail: changedPerms ? { permissions: next.permissions } : {} });
	return { settings: next };
}

async function listGroups(req) {
	await requirePerm(req, 'manageSettings');
	const list = await groupsLib.getNonPrivilegeGroups('groups:createtime', 0, -1);
	return list.map(g => g.name);
}

async function getLog(req) {
	await requirePerm(req, 'viewLog');
	const start = Math.max(0, parseInt(req.query.start, 10) || 0);
	const rows = await store.getLog(start, start + 99);
	const uids = [...new Set(rows.map(r => r.uid).filter(u => u > 0))];
	const names = {};
	(uids.length ? await user.getUsersFields(uids, ['uid', 'username']) : []).forEach((u) => { names[u.uid] = u.username; });
	return { total: await store.logCount(), rows: rows.map(r => ({ ...r, username: names[r.uid] || (r.uid ? `#${r.uid}` : 'system') })) };
}

// ---------- registration ----------

exports.init = ({ router, middleware }) => {
	const csrf = middleware.applyCSRF || ((req, res, next) => next(new Error('csrf-unavailable'))); // fail closed
	const R = (verb, path, fn, write) => router[verb](`${BASE}${path}`, ...(write ? [csrf] : []), h(fn));

	R('get', '/status', status);
	R('post', '/unlock', unlock, true);

	R('get', '/protection/:type/:id', req => manage.getForActor(mustLogin(req), keyOf(req)));
	R('put', '/protection/:type/:id', req => manage.set({ actorUid: mustLogin(req), key: keyOf(req), ip: req.ip, ...req.body }), true);
	R('delete', '/protection/:type/:id', req => manage.remove({ actorUid: mustLogin(req), key: keyOf(req), ip: req.ip }), true);
	R('post', '/protection/:type/:id/lock', req => manage.setLock({ actorUid: mustLogin(req), key: keyOf(req), ip: req.ip, lockChange: req.body.lockChange, lockRemove: req.body.lockRemove }), true);
	R('post', '/protection/:type/:id/reset', req => manage.ownerReset({ actorUid: mustLogin(req), key: keyOf(req), ip: req.ip, accountPassword: req.body.accountPassword, newPassword: req.body.newPassword }), true);

	R('get', '/admin/protections', listProtections);
	R('get', '/admin/settings', getSettings);
	R('put', '/admin/settings', putSettings, true);
	R('get', '/admin/groups', listGroups);
	R('get', '/admin/log', getLog);

	R('get', '/admin/rules', req => auto.list(mustLogin(req)));
	R('post', '/admin/rules', req => auto.save({ actorUid: mustLogin(req), rule: req.body || {}, ip: req.ip }), true);
	R('put', '/admin/rules/:id', req => auto.save({ actorUid: mustLogin(req), rule: { ...req.body, id: parseInt(req.params.id, 10) }, ip: req.ip }), true);
	R('post', '/admin/rules/:id/toggle', req => auto.toggle({ actorUid: mustLogin(req), id: parseInt(req.params.id, 10), enabled: req.body.enabled, ip: req.ip }), true);
	R('delete', '/admin/rules/:id', req => auto.delete({ actorUid: mustLogin(req), id: parseInt(req.params.id, 10), ip: req.ip }), true);

	R('get', '/admin/access', req => manage.listAccess(mustLogin(req)));
	R('post', '/admin/access', async (req) => {
		const actorUid = mustLogin(req);
		let uid = parseInt(req.body.uid, 10);
		if (!uid && req.body.username) uid = await user.getUidByUsername(String(req.body.username));
		return await manage.grantAccess({ actorUid, uid, key: String(req.body.key || ''), expiresAt: req.body.expiresAt, ip: req.ip });
	}, true);
	R('delete', '/admin/access/:id', req => manage.revokeAccess({ actorUid: mustLogin(req), id: parseInt(req.params.id, 10), ip: req.ip }), true);

	// ACP pages: one shared template, the page name selects the section
	const routeHelpers = require.main.require('./src/routes/helpers');
	ACP_PAGES.forEach((page) => {
		routeHelpers.setupAdminPageRoute(router, `/admin/plugins/password-protect/${page}`, [], (req, res) => {
			res.render('admin/plugins/password-protect', { title: '[[password-protect:acp.title]]', page });
		});
	});
	routeHelpers.setupAdminPageRoute(router, '/admin/plugins/password-protect', [], (req, res) => {
		res.render('admin/plugins/password-protect', { title: '[[password-protect:acp.title]]', page: 'manage' });
	});
};
