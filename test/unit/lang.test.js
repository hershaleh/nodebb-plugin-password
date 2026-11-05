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

test('ACP menu keys (built dynamically) exist', () => {
	const keys = new Set(Object.keys(load('he')));
	const pages = ['manage', 'categories', 'topics', 'settings', 'permissions', 'rules', 'access', 'log'];
	const need = ['acp.title', 'acp.nav.title', 'acp.nav.protections', 'acp.nav.configuration', 'acp.nav.monitoring', ...pages.map(p => `acp.tab.${p}`)];
	assert.deepStrictEqual(need.filter(k => !keys.has(k)), []);
	const src = fs.readFileSync(path.join(__dirname, '../../public/js/acp.js'), 'utf8');
	assert.ok(pages.every(p => src.includes(`'${p}'`)));
});

test('lock page: renders a centred, blurred dialog with strings and no NodeBB theme dependency', async () => {
	require('./_stub');
	const orig = require.main.require;
	require.main.require = (id) => {
		if (id === 'nconf') return { get: () => '' };
		if (id === './src/meta') return { config: { defaultLang: 'he', title: 'Forum <b>' } };
		if (id === './src/user') return { getSettings: async () => ({}) };
		return orig(id);
	};
	const lockpage = require('../../lib/lockpage');
	const html = await lockpage.render({ headers: {} }, 0);
	assert.match(html, /dir="rtl"/);
	assert.match(html, /backdrop-filter:blur/);
	assert.match(html, /type="password"/);
	assert.ok(!html.includes('Forum <b>'), 'site title must be escaped');
	assert.ok(html.includes('הקטגוריה הזו מוגנת בסיסמה'));
	require.main.require = orig;
});
