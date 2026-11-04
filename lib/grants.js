'use strict';

// Server-side unlock grants, stored per session id. The browser only holds the
// regular NodeBB session cookie, never the password or a bearer secret.
// Each grant records the protection's password version, so changing the
// password (new version) invalidates every grant made with the old one.

const db = require.main.require('./src/database');

const GK = sid => `pp:sg:${sid}`;

exports.load = async (sid) => {
	if (!sid) return {};
	return (await db.getObject(GK(sid))) || {};
};

exports.ttlMs = (cfg) => {
	const r = cfg.remember;
	if (r.mode === 'none') return 60 * 1000; // enough for the page load that follows unlock
	if (r.mode === 'timed') return r.minutes * 60000;
	return cfg.sessionMaxHours * 3600 * 1000; // bound to the browser session
};

exports.grant = async (sid, key, version, ttlMs) => {
	if (!sid) throw new Error('no-session');
	await db.setObjectField(GK(sid), key, `${version}:${Date.now() + ttlMs}`);
	if (db.pexpire) await db.pexpire(GK(sid), 30 * 86400000); // entries carry their own expiry
};

exports.revoke = async (sid, key) => {
	if (sid) await db.deleteObjectField(GK(sid), key);
};
