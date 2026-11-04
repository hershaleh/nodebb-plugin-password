'use strict';

// NodeBB notifications. Bodies never contain passwords or protected content.

const winston = require.main.require('winston');
const notifications = require.main.require('./src/notifications');
const user = require.main.require('./src/user');
const groups = require.main.require('./src/groups');
const topics = require.main.require('./src/topics');
const settings = require('./settings');

const esc = s => String(s || '').replace(/,/g, '&#44;').replace(/\[\[|\]\]/g, '');

async function send(uids, { nid, key, args, path, from, bodyLong }) {
	const list = [...new Set(uids)].filter(u => u > 0);
	if (!list.length) return;
	const n = await notifications.create({
		bodyShort: `[[password-protect:${key}, ${args.map(esc).join(', ')}]]`,
		bodyLong: bodyLong || '',
		nid,
		path,
		from: from > 0 ? from : undefined,
	});
	if (n) await notifications.push(n, list);
}

// Topic owner events: added | changed | removed | locked | unlocked
exports.ownerEvent = async function ({ event, tid, actorUid }) {
	try {
		const cfg = await settings.get();
		const flag = { added: 'ownerAdded', changed: 'ownerChanged', removed: 'ownerRemoved', locked: 'ownerLocked', unlocked: 'ownerLocked' }[event];
		if (!cfg.notifications[flag]) return;
		const t = await topics.getTopicFields(tid, ['uid', 'title']);
		if (!t || !t.uid || Number(t.uid) === Number(actorUid)) return;
		const actor = actorUid > 0 ? await user.getUserField(actorUid, 'username') : 'System';
		await send([parseInt(t.uid, 10)], {
			nid: `pp:${event}:${tid}:${Date.now()}`,
			key: `notif.${event}`,
			args: [t.title, actor || 'System'],
			path: `/topic/${tid}`,
			from: actorUid,
			bodyLong: new Date().toISOString(),
		});
	} catch (e) {
		winston.warn(`[password-protect] owner notification failed: ${e.message}`);
	}
};

exports.adminAlert = async function ({ key, count, ip }) {
	try {
		const cfg = await settings.get();
		if (!cfg.notifications.adminAlerts) return;
		const members = await groups.getMembers('administrators', 0, -1);
		await send(members.map(Number), {
			nid: `pp:alert:${key}:${Math.floor(Date.now() / 600000)}`, // at most one per 10 min per item
			key: 'notif.admin-alert',
			args: [key, String(count)],
			path: '/admin/plugins/password-protect/log',
			bodyLong: ip || '',
		});
	} catch (e) {
		winston.warn(`[password-protect] admin alert failed: ${e.message}`);
	}
};

exports.expiryReminder = async function ({ uid, key, expiresAt }) {
	try {
		let title = key;
		const m = /^([tc]):(\d+)$/.exec(key);
		let path = '/';
		if (m && m[1] === 't') {
			title = await topics.getTopicField(m[2], 'title');
			path = `/topic/${m[2]}`;
		} else if (m) {
			const cats = require.main.require('./src/categories');
			title = await cats.getCategoryField(m[2], 'name');
			path = `/category/${m[2]}`;
		}
		await send([uid], {
			nid: `pp:expiry:${key}:${uid}:${expiresAt}`,
			key: 'notif.expiry',
			args: [title, new Date(expiresAt).toISOString()],
			path,
		});
	} catch (e) {
		winston.warn(`[password-protect] reminder failed: ${e.message}`);
	}
};
