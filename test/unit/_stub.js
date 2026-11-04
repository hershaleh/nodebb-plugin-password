'use strict';
// Minimal in-memory stand-in for NodeBB's database, so pure modules can be
// unit-tested. Integration tests (test/integration) use the real NodeBB.
const data = new Map();
const sets = new Map();
const db = {
	async getObject(k) { return data.has(k) ? { ...data.get(k) } : null; },
	async setObject(k, o) { data.set(k, { ...(data.get(k) || {}), ...o }); },
	async incrObjectField(k, f) {
		const o = data.get(k) || {};
		o[f] = String((parseInt(o[f], 10) || 0) + 1);
		data.set(k, o);
		return parseInt(o[f], 10);
	},
	async deleteAll(k) { data.delete(k); },
	async pexpire() {},
	async setObjectField(k, f, v) { const o = data.get(k) || {}; o[f] = v; data.set(k, o); },
	async deleteObjectField(k, f) { const o = data.get(k); if (o) delete o[f]; },
	_reset() { data.clear(); sets.clear(); },
};
const realRequire = require.main.require.bind(require.main);
require.main.require = (id) => {
	if (id === './src/database') return db;
	if (id === 'winston') return { info() {}, warn() {}, error() {} };
	return realRequire(id);
};
module.exports = db;
