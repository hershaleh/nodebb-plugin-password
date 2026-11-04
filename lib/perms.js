'use strict';

const groups = require.main.require('./src/groups');
const settings = require('./settings');

// Group-based permission check. Guests never hold plugin permissions.
exports.can = async function (uid, perm) {
	try {
		if (!(uid > 0)) return false;
		const cfg = await settings.get();
		const list = cfg.permissions[perm] || [];
		if (!list.length) return false;
		const res = await groups.isMemberOfGroups(uid, list);
		return res.some(Boolean);
	} catch (e) {
		return false; // fail closed
	}
};

exports.canMany = async function (uid, perms) {
	const out = {};
	await Promise.all(perms.map(async (p) => { out[p] = await exports.can(uid, p); }));
	return out;
};
