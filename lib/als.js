'use strict';

// Carries the current express request through async calls so filter hooks
// (which only receive a uid) can look up the session that holds unlock grants.

const { AsyncLocalStorage } = require('async_hooks');

const als = new AsyncLocalStorage();

exports.run = (req, next) => als.run({ req }, next);
exports.req = () => {
	const s = als.getStore();
	return s ? s.req : null;
};
