'use strict';

const winston = require.main.require('winston');

const als = require('./lib/als');
const guard = require('./lib/guard');
const routes = require('./lib/routes');
const auto = require('./lib/auto');
const store = require('./lib/store');
const manage = require('./lib/manage');
const settings = require('./lib/settings');
const perms = require('./lib/perms');
const migrations = require('./lib/migrations');

const Plugin = module.exports;

// Runs before NodeBB's routes: request context + the server-side gate.
Plugin.preload = async ({ app, middleware }) => {
	guard.setMiddleware(middleware);
	app.use((req, res, next) => als.run(req, next));
	app.use(guard.middleware);
};

Plugin.init = async (params) => {
	await migrations.run();
	routes.init(params);
	auto.startJobs();
	winston.info('[password-protect] initialised');
};

Plugin.adminMenu = async (header) => {
	header.plugins.push({
		route: '/plugins/password-protect',
		icon: 'fa-lock',
		name: '[[password-protect:acp.title]]',
	});
	return header;
};

Plugin.filterTopicGet = guard.filterTopicGet;
Plugin.filterTids = guard.filterTids;
Plugin.filterPids = guard.filterPids;
Plugin.filterCids = guard.filterCids;
Plugin.filterPosts = guard.filterPosts;
Plugin.filterNotification = guard.filterNotification;
Plugin.onTopicPost = auto.onTopicPost;

// Show the "Password protection" entry in topic tools for users who may manage this topic.
Plugin.threadTools = async (data) => {
	try {
		const uid = data.uid;
		const tid = data.topic.tid;
		await manage.getForActor(uid, `t:${tid}`);
		data.tools.push({ class: 'pp-protect', title: '[[password-protect:tools.protect]]', icon: 'fa-lock' });
	} catch (e) {
		// no permission: no entry
	}
	return data;
};

// Cleanup so purged items leave no orphaned protections or live personal grants.
Plugin.onTopicPurge = async ({ topic }) => {
	try {
		const key = `t:${topic.tid}`;
		await store.removeAllForKey(key);
		await store.log({ action: 'protection-removed', key, detail: { reason: 'topic purged' } });
	} catch (e) {
		winston.warn(`[password-protect] purge cleanup: ${e.message}`);
	}
};

Plugin.onCategoryDelete = async ({ cid }) => {
	try {
		await store.removeAllForKey(`c:${cid}`);
		await store.log({ action: 'protection-removed', key: `c:${cid}`, detail: { reason: 'category deleted' } });
	} catch (e) {
		winston.warn(`[password-protect] category cleanup: ${e.message}`);
	}
};

// exposed for other plugins / tests
Plugin._internal = { settings, perms, store };
