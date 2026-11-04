'use strict';

// Ordered, idempotent data migrations. The applied schema version is stored in
// the database, so upgrading NodeBB or this plugin never discards data.

const db = require.main.require('./src/database');
const winston = require.main.require('winston');

const MIGRATIONS = [
	{
		version: 1,
		name: 'initial schema',
		async up() { /* nothing to transform: schema v1 is created lazily */ },
	},
];

exports.CURRENT = MIGRATIONS[MIGRATIONS.length - 1].version;

exports.run = async () => {
	const o = await db.getObject('pp:meta');
	let current = o && o.schema ? parseInt(o.schema, 10) : 0;
	for (const m of MIGRATIONS) {
		if (m.version <= current) continue;
		winston.info(`[password-protect] migration ${m.version}: ${m.name}`);
		// eslint-disable-next-line no-await-in-loop
		await m.up(db);
		current = m.version;
		// eslint-disable-next-line no-await-in-loop
		await db.setObject('pp:meta', { schema: String(current) });
	}
};
