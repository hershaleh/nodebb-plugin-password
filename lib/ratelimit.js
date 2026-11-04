'use strict';

// Failed-attempt limiter. The database object is injected so the module is
// unit-testable. Needs: getObject, incrObjectField, setObject, deleteAll, pexpire.

const MAX_BLOCK_MS = 24 * 3600 * 1000;
const sleep = ms => new Promise(r => setTimeout(r, ms));

module.exports = function (db) {
	const k = id => `pp:att:${id}`;

	async function check(ids) {
		const now = Date.now();
		for (const id of ids) {
			// eslint-disable-next-line no-await-in-loop
			const o = await db.getObject(k(id));
			if (o && Number(o.until) > now) {
				return { blocked: true, retryAfter: Math.ceil((Number(o.until) - now) / 1000) };
			}
		}
		return { blocked: false, retryAfter: 0 };
	}

	async function fail(ids, cfg) {
		let worst = 0;
		for (const id of ids) {
			// eslint-disable-next-line no-await-in-loop
			const count = await db.incrObjectField(k(id), 'count');
			worst = Math.max(worst, count);
			if (count >= cfg.maxAttempts) {
				// eslint-disable-next-line no-await-in-loop
				const strikes = await db.incrObjectField(k(id), 'strikes');
				const factor = cfg.progressive ? 2 ** Math.min(strikes - 1, 10) : 1;
				const ms = Math.min(cfg.blockMinutes * 60000 * factor, MAX_BLOCK_MS);
				// eslint-disable-next-line no-await-in-loop
				await db.setObject(k(id), { until: Date.now() + ms, count: 0 });
			}
			// eslint-disable-next-line no-await-in-loop
			if (db.pexpire) await db.pexpire(k(id), 7 * 86400000);
		}
		// gradual delay before answering a wrong password
		if (cfg.progressive && worst > 0) await sleep(Math.min(worst * 250, 3000));
		return worst;
	}

	async function succeed(ids) {
		for (const id of ids) {
			// eslint-disable-next-line no-await-in-loop
			await db.setObject(k(id), { count: 0 });
		}
	}

	return { check, fail, succeed };
};
