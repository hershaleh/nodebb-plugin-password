'use strict';

// Password hashing. Argon2id when the optional `argon2` module is installed,
// otherwise scrypt from Node's standard library (salted, memory-hard).
// No NodeBB dependency, so it is unit-testable on its own.

const crypto = require('crypto');

let argon2 = null;
try { argon2 = require('argon2'); } catch (e) { argon2 = null; }

const SCRYPT = { N: 2 ** 15, r: 8, p: 1, maxmem: 128 * 1024 * 1024 };

const scrypt = (pw, salt, len, opts) => new Promise((resolve, reject) => {
	crypto.scrypt(pw, salt, len, opts, (err, key) => (err ? reject(err) : resolve(key)));
});

exports.hash = async function (password) {
	if (typeof password !== 'string' || !password.length || password.length > 256) {
		throw new Error('invalid-password');
	}
	if (argon2) {
		return await argon2.hash(password, { type: argon2.argon2id });
	}
	const salt = crypto.randomBytes(16);
	const key = await scrypt(password, salt, 64, SCRYPT);
	return ['scrypt', SCRYPT.N, SCRYPT.r, SCRYPT.p, salt.toString('base64'), key.toString('base64')].join('$');
};

exports.verify = async function (password, stored) {
	try {
		if (typeof password !== 'string' || typeof stored !== 'string' || !stored) return false;
		if (stored.startsWith('$argon2')) {
			return argon2 ? await argon2.verify(stored, password) : false;
		}
		const [kind, N, r, p, salt, hash] = stored.split('$');
		if (kind !== 'scrypt') return false;
		const expected = Buffer.from(hash, 'base64');
		const key = await scrypt(password, Buffer.from(salt, 'base64'), expected.length, {
			N: +N, r: +r, p: +p, maxmem: SCRYPT.maxmem,
		});
		return key.length === expected.length && crypto.timingSafeEqual(key, expected);
	} catch (e) {
		return false; // fail closed
	}
};

exports.engine = () => (argon2 ? 'argon2id' : 'scrypt');
