'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const dir = path.join(__dirname, '../../languages');
const load = l => JSON.parse(fs.readFileSync(path.join(dir, l, 'password-protect.json'), 'utf8'));

test('all languages define the same keys', () => {
	const base = Object.keys(load('he')).sort();
	for (const l of fs.readdirSync(dir)) assert.deepStrictEqual(Object.keys(load(l)).sort(), base, l);
});

test('every [[password-protect:key]] used in templates and scripts exists', () => {
	const keys = new Set(Object.keys(load('he')));
	const files = ['templates/admin/plugins/password-protect.tpl', 'public/js/acp.js', 'public/js/client.js', 'library.js']
		.map(f => fs.readFileSync(path.join(__dirname, '../..', f), 'utf8'));
	const missing = new Set();
	for (const src of files) {
		for (const m of src.matchAll(/password-protect:([a-zA-Z0-9_.-]+)/g)) {
			const k = m[1];
			if (k.endsWith('.')) continue; // dynamic key prefix, e.g. set.${name}
			if (!keys.has(k) && !/\$\{/.test(k)) missing.add(k);
		}
	}
	assert.deepStrictEqual([...missing], []);
});
