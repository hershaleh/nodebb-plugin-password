'use strict';
// Tiny cookie-aware HTTP client for a running NodeBB (Node >= 18 fetch).
module.exports = class Client {
	constructor(base) { this.base = base.replace(/\/$/, ''); this.cookies = {}; this.csrf = ''; }

	_store(res) {
		(res.headers.getSetCookie ? res.headers.getSetCookie() : []).forEach((c) => {
			const [kv] = c.split(';');
			const i = kv.indexOf('=');
			this.cookies[kv.slice(0, i)] = kv.slice(i + 1);
		});
	}

	async req(method, path, body, extra = {}) {
		const headers = { cookie: Object.entries(this.cookies).map(([k, v]) => `${k}=${v}`).join('; '), ...extra };
		if (this.csrf) headers['x-csrf-token'] = this.csrf;
		if (body !== undefined) headers['content-type'] = 'application/json';
		const res = await fetch(this.base + path, {
			method, headers, redirect: 'manual', body: body === undefined ? undefined : JSON.stringify(body),
		});
		this._store(res);
		const text = await res.text();
		let json = null;
		try { json = JSON.parse(text); } catch (e) { /* not json */ }
		return { status: res.status, text, json };
	}

	async init() {
		const r = await this.req('GET', '/api/config');
		this.csrf = r.json.csrf_token;
		return this;
	}

	async login(username, password) {
		await this.init();
		const r = await this.req('POST', '/login', { username, password });
		if (r.status !== 200) throw new Error(`login failed for ${username}: ${r.status} ${r.text.slice(0, 120)}`);
		await this.init(); // new session => new csrf token
		return this;
	}
};
