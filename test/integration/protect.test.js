'use strict';
// Runs against a REAL, running NodeBB with this plugin installed and activated:
//   NODEBB_URL=http://localhost:4567 PP_ADMIN_USER=admin PP_ADMIN_PASS=... npm run test:integration
// Skipped (not faked) when the variables are missing.
const test = require('node:test');
const assert = require('node:assert');
const Client = require('./_client');

const URL = process.env.NODEBB_URL;
const AU = process.env.PP_ADMIN_USER;
const AP = process.env.PP_ADMIN_PASS;
const skip = !(URL && AU && AP) && 'set NODEBB_URL, PP_ADMIN_USER, PP_ADMIN_PASS to run against a real NodeBB';
const API = '/api/v3/plugins/password-protect';
const rnd = Math.random().toString(36).slice(2, 8);
const PW = 'S3cret-pass-1';

let admin; let anon; let member; let memberUid; let cid; let tid; let pid;
const SECRET = `secret-body-${rnd}`;

test('setup: admin, member, category, topic', { skip }, async () => {
	admin = await new Client(URL).login(AU, AP);
	let r = await admin.req('POST', '/api/v3/users', { username: `ppm${rnd}`, password: 'Member-pass-123' });
	assert.ok(r.status < 300, r.text);
	memberUid = r.json.response.uid;
	member = await new Client(URL).login(`ppm${rnd}`, 'Member-pass-123');
	anon = await new Client(URL).init();
	r = await admin.req('POST', '/api/v3/categories', { name: `pp-cat-${rnd}` });
	cid = r.json.response.cid;
	r = await admin.req('POST', '/api/v3/topics', { cid, title: `pp topic ${rnd}`, content: SECRET });
	assert.ok(r.status < 300, r.text);
	tid = r.json.response.tid;
	pid = r.json.response.mainPid;
});

const paths = () => [
	`/api/topic/${tid}`, `/topic/${tid}`, `/api/category/${cid}`, `/category/${cid}`,
	`/api/v3/topics/${tid}`, `/api/v3/posts/${pid}`, `/api/post/${pid}`, `/post/${pid}`,
	`/category/${cid}.rss`, `/topic/${tid}.rss`,
];

test('unprotected content is readable by guests', { skip }, async () => {
	const r = await anon.req('GET', `/api/topic/${tid}`);
	assert.strictEqual(r.status, 200);
});

test('category protection blocks every route for guests and members, incl. admins without bypass', { skip }, async () => {
	const r = await admin.req('PUT', `${API}/protection/c/${cid}`, { password: PW, message: 'hello' });
	assert.ok(r.status < 300, r.text);
	for (const who of [anon, member, admin]) {
		for (const p of paths()) {
			const res = await who.req('GET', p);
			assert.ok([401, 403].includes(res.status) || res.status === 302, `${p} -> ${res.status}`);
			assert.ok(!res.text.includes(SECRET), `${p} leaked the post body`);
		}
	}
});

test('protected topic is absent from search and recent lists', { skip }, async () => {
	const s = await member.req('GET', `/api/search?term=${SECRET}&in=posts`);
	assert.ok(!s.text.includes(SECRET));
	const rec = await member.req('GET', '/api/recent');
	assert.ok(!rec.text.includes(`pp topic ${rnd}`));
});

test('wrong password is rejected; limiter blocks after 5 failures', { skip }, async () => {
	for (let i = 0; i < 5; i++) {
		const r = await member.req('POST', `${API}/unlock`, { key: `c:${cid}`, password: 'nope' });
		assert.ok([400, 401, 403].includes(r.status), String(r.status));
	}
	const blocked = await member.req('POST', `${API}/unlock`, { key: `c:${cid}`, password: PW });
	assert.strictEqual(blocked.status, 429);
});

test('correct password unlocks only for that session', { skip }, async () => {
	const g = await new Client(URL).init();
	const r = await g.req('POST', `${API}/unlock`, { key: `c:${cid}`, password: PW });
	assert.strictEqual(r.status, 200, r.text);
	const ok = await g.req('GET', `/api/topic/${tid}`);
	assert.strictEqual(ok.status, 200);
	assert.ok(ok.text.includes(SECRET));
	const still = await anon.req('GET', `/api/topic/${tid}`);
	assert.notStrictEqual(still.status, 200);
	module.exports.unlocked = g;
});

test('changing the password revokes existing unlocks', { skip }, async () => {
	const g = module.exports.unlocked;
	const r = await admin.req('PUT', `${API}/protection/c/${cid}`, { password: `${PW}-2` });
	assert.ok(r.status < 300, r.text);
	const res = await g.req('GET', `/api/topic/${tid}`);
	assert.ok(!res.text.includes(SECRET));
	assert.notStrictEqual(res.status, 200);
});

test('personal access works without revealing the password, and can be revoked', { skip }, async () => {
	let r = await admin.req('POST', `${API}/admin/access`, { uid: memberUid, key: `c:${cid}` });
	assert.ok(r.status < 300, r.text);
	assert.ok(!r.text.includes(PW));
	const id = r.json.response.id;
	const m = await new Client(URL).login(`ppm${rnd}`, 'Member-pass-123');
	assert.strictEqual((await m.req('GET', `/api/topic/${tid}`)).status, 200);
	r = await admin.req('DELETE', `${API}/admin/access/${id}`);
	assert.ok(r.status < 300, r.text);
	assert.notStrictEqual((await m.req('GET', `/api/topic/${tid}`)).status, 200);
});

test('non-managers cannot change protections; writes require CSRF', { skip }, async () => {
	const r = await member.req('PUT', `${API}/protection/c/${cid}`, { password: 'x1y2z3' });
	assert.strictEqual(r.status, 403);
	const noCsrf = new Client(URL);
	noCsrf.cookies = { ...admin.cookies };
	const res = await noCsrf.req('PUT', `${API}/protection/c/${cid}`, { password: 'abc12345' });
	assert.ok(res.status >= 400, String(res.status));
});

test('passwords never appear in API responses or the log', { skip }, async () => {
	const r = await admin.req('GET', `${API}/admin/log`);
	assert.ok(!r.text.includes(PW));
	const p = await admin.req('GET', `${API}/admin/protections`);
	assert.ok(!/"hash"/.test(p.text));
});

test('removing protection restores access; cleanup', { skip }, async () => {
	const r = await admin.req('DELETE', `${API}/protection/c/${cid}`);
	assert.ok(r.status < 300, r.text);
	assert.strictEqual((await anon.req('GET', `/api/topic/${tid}`)).status, 200);
	await admin.req('DELETE', `/api/v3/topics/${tid}/state`);
});
