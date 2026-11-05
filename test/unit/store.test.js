'use strict';
const test = require('node:test');
const assert = require('node:assert');
const db = require('./_stub');
const store = require('../../lib/store');

test('bypassGroups round-trips as an array and defaults to empty', async () => {
	db._reset();
	// the in-memory stub lacks set helpers used by save(); exercise the pure parse/serialize path via getObject
	await db.setObject('pp:prot:c:1', { enabled: '1', hash: 'h', bypassGroups: JSON.stringify(['staff', 'vip']) });
	db.getObjects = async keys => Promise.all(keys.map(k => db.getObject(k)));
	const got = await store.getMany(['c:1', 'c:2']);
	assert.deepStrictEqual(got['c:1'].bypassGroups, ['staff', 'vip']);
	assert.strictEqual(got['c:2'], null);
	await db.setObject('pp:prot:c:3', { enabled: '1', hash: 'h', bypassGroups: 'not json' });
	assert.deepStrictEqual((await store.getMany(['c:3']))['c:3'].bypassGroups, []);
});
