'use strict';

// Server-side enforcement. Two layers:
//  1. an express middleware that gates every URL that can return protected
//     content (pages, /api, /api/v3, RSS, post redirects, uploads);
//  2. NodeBB filter hooks that remove protected items from lists, search,
//     summaries, notifications and the topic data itself.
// Every error path fails CLOSED.

const crypto = require('crypto');
const winston = require.main.require('winston');
const db = require.main.require('./src/database');
const topics = require.main.require('./src/topics');
const posts = require.main.require('./src/posts');
const categories = require.main.require('./src/categories');

const store = require('./store');
const settings = require('./settings');
const perms = require('./perms');
const grantsLib = require('./grants');
const policy = require('./policy');
const als = require('./als');

const Guard = module.exports;

// ---------- evaluation ----------

async function context(uid, req) {
	const cfg = await settings.get();
	const bypass = await perms.can(uid, 'bypass');
	return {
		uid,
		cfg,
		bypass,
		personal: bypass ? new Set() : await store.activePersonalKeys(uid),
		grants: !bypass && req && req.sessionID ? await grantsLib.load(req.sessionID) : {},
	};
}
Guard.context = context;

async function catChain(cid, memo) {
	if (memo.has(cid)) return memo.get(cid);
	const chain = [];
	let cur = parseInt(cid, 10) || 0;
	for (let i = 0; i < 12 && cur > 0 && !chain.includes(cur); i++) {
		chain.push(cur);
		// eslint-disable-next-line no-await-in-loop
		cur = parseInt(await categories.getCategoryField(cur, 'parentCid'), 10) || 0;
	}
	memo.set(cid, chain);
	return chain;
}

function satisfied(ctx, key, prot, now) {
	if (ctx.personal.has(key)) return true;
	return policy.grantValid(ctx.grants[key], prot, now);
}

/** items: [{tid?, cid}] -> [{ok, required, pending, catKey, topicKey}] */
async function evaluateMany(ctx, items) {
	if (ctx.bypass) return items.map(() => ({ ok: true, required: [], pending: [] }));
	const memo = new Map();
	const keys = new Set();
	const chains = [];
	for (const it of items) {
		// eslint-disable-next-line no-await-in-loop
		const ch = await catChain(it.cid, memo);
		chains.push(ch);
		ch.forEach(c => keys.add(`c:${c}`));
		if (it.tid) keys.add(`t:${it.tid}`);
	}
	const prots = await store.getMany([...keys]);
	const tids = items.filter(i => i.tid).map(i => i.tid);
	const exempt = tids.length ? await store.exemptMap(tids) : {};
	const now = Date.now();
	return items.map((it, i) => {
		const catId = chains[i].find(c => policy.isActive(prots[`c:${c}`], now));
		const catKey = catId ? `c:${catId}` : null;
		const topicKey = it.tid && policy.isActive(prots[`t:${it.tid}`], now) ? `t:${it.tid}` : null;
		const required = policy.requiredKeys({
			cat: catKey, topic: topicKey, exempt: !!(it.tid && exempt[it.tid]), mode: ctx.cfg.policy,
		});
		const pending = required.filter(k => !satisfied(ctx, k, prots[k], now));
		return { ok: pending.length === 0, required, pending, catKey, topicKey, prots };
	});
}
Guard.evaluateMany = evaluateMany;

async function hasAny() {
	return (await store.count()) > 0;
}

// ---------- hook filters ----------

async function allowedTids(uid, tids) {
	const f = await topics.getTopicsFields(tids, ['tid', 'cid']);
	const items = f.filter(t => t && t.tid).map(t => ({ tid: parseInt(t.tid, 10), cid: parseInt(t.cid, 10) }));
	if (!items.length) return new Set(tids);
	const ctx = await context(uid, als.req());
	const res = await evaluateMany(ctx, items);
	const blocked = new Set();
	res.forEach((r, i) => { if (!r.ok) blocked.add(items[i].tid); });
	return new Set(tids.filter(t => !blocked.has(parseInt(t, 10))));
}

Guard.filterTids = async (data) => {
	try {
		if (!data || !Array.isArray(data.tids) || !data.tids.length || !(await hasAny())) return data;
		const ok = await allowedTids(data.uid, data.tids);
		data.tids = data.tids.filter(t => ok.has(t));
	} catch (e) {
		winston.error(`[password-protect] filterTids: ${e.stack}`);
		data.tids = [];
	}
	return data;
};

Guard.filterPids = async (data) => {
	try {
		if (!data || !Array.isArray(data.pids) || !data.pids.length || !(await hasAny())) return data;
		const pf = await posts.getPostsFields(data.pids, ['pid', 'tid']);
		const tids = [...new Set(pf.filter(p => p && p.tid).map(p => parseInt(p.tid, 10)))];
		const ok = await allowedTids(data.uid, tids);
		data.pids = data.pids.filter((pid, i) => !pf[i] || !pf[i].tid || ok.has(parseInt(pf[i].tid, 10)));
	} catch (e) {
		winston.error(`[password-protect] filterPids: ${e.stack}`);
		data.pids = [];
	}
	return data;
};

Guard.filterPosts = async (data) => {
	try {
		if (!data || !Array.isArray(data.posts) || !data.posts.length || !(await hasAny())) return data;
		const tids = [...new Set(data.posts.filter(p => p && p.tid).map(p => parseInt(p.tid, 10)))];
		const ok = await allowedTids(data.uid, tids);
		data.posts = data.posts.filter(p => !p || !p.tid || ok.has(parseInt(p.tid, 10)));
	} catch (e) {
		winston.error(`[password-protect] filterPosts: ${e.stack}`);
		data.posts = [];
	}
	return data;
};

// Hidden categories disappear from lists for users without access.
Guard.filterCids = async (data) => {
	try {
		if (!data || !Array.isArray(data.cids) || !data.cids.length || !(await hasAny())) return data;
		const ctx = await context(data.uid, als.req());
		if (ctx.bypass) return data;
		const memo = new Map();
		const keep = [];
		for (const cid of data.cids) {
			// eslint-disable-next-line no-await-in-loop
			const chain = await catChain(cid, memo);
			// eslint-disable-next-line no-await-in-loop
			const prots = await store.getMany(chain.map(c => `c:${c}`));
			const now = Date.now();
			const hidden = chain.some((c) => {
				const p = prots[`c:${c}`];
				return policy.isActive(p, now) && p.hidden && !satisfied(ctx, `c:${c}`, p, now);
			});
			if (!hidden) keep.push(cid);
		}
		data.cids = keep;
	} catch (e) {
		winston.error(`[password-protect] filterCids: ${e.stack}`);
		data.cids = [];
	}
	return data;
};

// Final defence at the data layer: topic data is never returned to a user who
// has not unlocked it, whichever controller or API asked for it.
Guard.filterTopicGet = async (data) => {
	if (!(await hasAny())) return data;
	try {
		const t = data.topic;
		const [r] = await evaluateMany(await context(data.uid, als.req()), [{ tid: t.tid, cid: t.cid }]);
		if (!r.ok) throw new Error('[[error:no-privileges]]');
	} catch (e) {
		if (e.message === '[[error:no-privileges]]') throw e;
		winston.error(`[password-protect] filterTopicGet: ${e.stack}`);
		throw new Error('[[error:no-privileges]]');
	}
	return data;
};

// ---------- middleware ----------

const ROUTES = [
	{ re: /^\/(?:api\/)?topic\/(?:pagination|teaser|thumb)s?\/(\d+)/, kind: 'tid' },
	{ re: /^\/(?:api\/)?topic\/(\d+)(?:[/.]|$)/, kind: 'tid' },
	{ re: /^\/(?:api\/)?category\/(\d+)(?:[/.]|$)/, kind: 'cid' },
	{ re: /^\/(?:api\/)?post\/(\d+)(?:[/.]|$)/, kind: 'pid' },
	{ re: /^\/api\/v3\/topics\/(\d+)(?:[/.]|$)/, kind: 'tid' },
	{ re: /^\/api\/v3\/posts\/(\d+)(?:[/.]|$)/, kind: 'pid' },
	{ re: /^\/api\/v3\/categories\/(\d+)(?:[/.]|$)/, kind: 'cid' },
	{ re: /^\/assets\/uploads\/(.+)$/, kind: 'upload' },
];

Guard.matchPath = (path) => {
	for (const r of ROUTES) {
		const m = r.re.exec(path);
		if (m) return { kind: r.kind, value: r.kind === 'upload' ? m[1] : parseInt(m[1], 10) };
	}
	return null;
};

async function resolve(target) {
	if (target.kind === 'cid') return [{ cid: target.value }];
	if (target.kind === 'tid') {
		const cid = await topics.getTopicField(target.value, 'cid');
		return cid ? [{ tid: target.value, cid: parseInt(cid, 10) }] : null;
	}
	if (target.kind === 'pid') {
		const tid = await posts.getPostField(target.value, 'tid');
		if (!tid) return null;
		const cid = await topics.getTopicField(tid, 'cid');
		return [{ tid: parseInt(tid, 10), cid: parseInt(cid, 10) }];
	}
	if (target.kind === 'upload') {
		// NodeBB records which posts reference an upload under upload:<md5(path)>:pids
		const rel = `/${target.value.replace(/^\/+/, '')}`;
		const md5 = crypto.createHash('md5').update(rel).digest('hex');
		const pids = await db.getSortedSetRange(`upload:${md5}:pids`, 0, -1);
		if (!pids.length) return null; // not attached to any post
		const pf = await posts.getPostsFields(pids, ['pid', 'tid']);
		const items = [];
		for (const p of pf) {
			if (!p || !p.tid) continue;
			// eslint-disable-next-line no-await-in-loop
			const cid = await topics.getTopicField(p.tid, 'cid');
			items.push({ tid: parseInt(p.tid, 10), cid: parseInt(cid, 10) });
		}
		return items.length ? items : null;
	}
	return null;
}
Guard.resolve = resolve;

const recentSuspicious = new Map();
async function logSuspicious(req, uid, r) {
	const k = `${uid}|${req.ip}|${r.pending.join(',')}`;
	const last = recentSuspicious.get(k) || 0;
	if (Date.now() - last < 60000) return;
	recentSuspicious.set(k, Date.now());
	if (recentSuspicious.size > 5000) recentSuspicious.clear();
	await store.log({
		uid, action: 'bypass-attempt', key: r.pending.join(','), result: 'blocked', ip: req.ip,
		detail: { path: req.path, method: req.method },
	});
}

function deny(req, res, uid, pending) {
	const isApi = /^\/api\/v3\//.test(req.path);
	const isRss = /\.rss$/.test(req.path);
	const isUpload = /^\/assets\/uploads\//.test(req.path);
	if (isUpload || isRss) return res.status(403).type('text/plain').send('Forbidden');
	if (isApi) {
		return res.status(403).json({
			status: { code: 'forbidden', message: '[[error:no-privileges]]' },
			response: { passwordProtected: true, keys: pending || [] },
		});
	}
	return res.status(403).render('403', {
		path: req.path.replace(/^\/api/, ''),
		loggedIn: uid > 0,
		title: '[[global:403.title]]',
		error: '[[password-protect:error.locked]]',
		passwordProtected: true,
	});
}

Guard.uidOf = (req) => {
	if (req.uid !== undefined) return parseInt(req.uid, 10) || 0;
	return parseInt(req.session && req.session.passport && req.session.passport.user, 10) || 0;
};

Guard.middleware = async (req, res, next) => {
	const target = Guard.matchPath(req.path);
	if (!target) return next();
	const uid = Guard.uidOf(req);
	try {
		if (!(await hasAny())) return next();
		const items = await resolve(target);
		if (!items) return next();
		const ctx = await context(uid, req);
		const results = await evaluateMany(ctx, items);
		const bad = results.find(r => !r.ok);
		if (!bad) return next();
		if (/^\/api\/v3\//.test(req.path) || /\.rss$/.test(req.path) || target.kind === 'upload') {
			logSuspicious(req, uid, bad).catch(() => {});
		}
		return deny(req, res, uid, bad.pending);
	} catch (e) {
		winston.error(`[password-protect] middleware failed closed: ${e.stack}`);
		return deny(req, res, uid, []);
	}
};

// ---------- notifications ----------

Guard.filterNotification = async (data) => {
	try {
		const n = data && data.notification;
		if (!n || !Array.isArray(data.uids) || !(await hasAny())) return data;
		let tid = n.tid;
		if (!tid && n.pid) tid = await posts.getPostField(n.pid, 'tid');
		if (!tid) return data;
		const cid = await topics.getTopicField(tid, 'cid');
		const keep = [];
		const generic = [];
		for (const uid of data.uids) {
			// eslint-disable-next-line no-await-in-loop
			const ctx = await context(uid, null);
			// eslint-disable-next-line no-await-in-loop
			const [r] = await evaluateMany(ctx, [{ tid: parseInt(tid, 10), cid: parseInt(cid, 10) }]);
			if (r.ok) keep.push(uid);
			else if (ctx.cfg.notifications.replyContent === 'generic') generic.push(uid);
		}
		data.uids = keep;
		if (generic.length) {
			const notifications = require.main.require('./src/notifications');
			const g = await notifications.create({
				bodyShort: '[[password-protect:notif.generic-reply]]',
				nid: `pp:generic:${tid}:${Date.now()}`,
				path: `/topic/${tid}`,
				from: n.from,
			});
			if (g) await notifications.push(g, generic);
		}
	} catch (e) {
		winston.error(`[password-protect] filterNotification: ${e.stack}`);
		data.uids = [];
	}
	return data;
};
