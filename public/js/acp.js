'use strict';
/* global $, ajaxify, require, utils, config */

define('admin/plugins/password-protect', ['api', 'alerts', 'translator', 'bootbox'], function (api, alerts, translator, bootbox) {
	const ACP = {};
	const API = '/plugins/password-protect';
	const $root = () => $('#pp-content');
	const esc = s => (utils.escapeHTML ? utils.escapeHTML(String(s == null ? '' : s)) : $('<div>').text(String(s)).html());
	const T = (k, cb) => translator.translate(k, cb);
	const fmt = ts => (ts ? new Date(ts).toLocaleString() : '—');
	const rel = config.relative_path || '';
	const toast = (type, msg) => T(msg, m => alerts[type](m));
	const fail = e => toast('error', (e && (e.message || (e.status && e.status.message))) || '[[error:invalid-data]]');
	const local = ts => (ts ? new Date(ts - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16) : '');
	const parseDt = v => (v ? new Date(v).getTime() : 0);


	const PAGES = ['manage', 'categories', 'topics', 'settings', 'permissions', 'rules', 'access', 'log'];
	const NAV = [
		['protections', ['manage', 'categories', 'topics']],
		['configuration', ['settings', 'permissions', 'rules']],
		['monitoring', ['access', 'log']],
	];
	const STYLE = `#pp-acp .pp-header { border-bottom: 1px solid var(--bs-border-color); }
		#pp-acp .pp-nav { position: sticky; top: 1rem; }
		#pp-acp .pp-nav-title { font-size: .75rem; font-weight: 600; color: var(--bs-secondary-color); margin: 0 .75rem .5rem; }
		#pp-acp .pp-nav-group { font-size: .7rem; letter-spacing: .02em; color: var(--bs-secondary-color); margin: 1rem .75rem .25rem; text-transform: uppercase; }
		#pp-acp .pp-nav-link { display: block; padding: .4rem .75rem; border-radius: .375rem; font-size: .8rem; color: var(--bs-body-color); text-decoration: none; }
		#pp-acp .pp-nav-link:hover { background: var(--bs-tertiary-bg); }
		#pp-acp .pp-nav-link.active { background: var(--bs-secondary-bg); font-weight: 600; }`;

	function frameHtml() {
		const groups = NAV.map(([g, pages]) => `<div class="pp-nav-group">[[password-protect:acp.nav.${g}]]</div>${pages.map(p => `<a class="pp-nav-link" role="button" tabindex="0" data-pp-page="${p}" href="${rel}/admin/plugins/password-protect/${p}">[[password-protect:acp.tab.${p}]]</a>`).join('')}`).join('');
		return `<style>${STYLE}</style>
			<div class="pp-header d-flex align-items-center justify-content-between gap-2 pb-2 mb-4">
				<h4 class="mb-0 fw-semibold"><i class="fa fa-lock text-muted"></i> [[password-protect:acp.title]]</h4>
				<button type="submit" class="btn btn-primary btn-sm" id="pp-save" hidden>[[password-protect:form.save]]</button>
			</div>
			<div class="row">
				<div class="col-lg-9 order-2 order-lg-1"><div id="pp-content"></div></div>
				<div class="col-lg-3 order-1 order-lg-2 mb-4"><nav class="pp-nav" id="pp-tabs"><div class="pp-nav-title">[[password-protect:acp.nav.title]]</div>${groups}</nav></div>
			</div>`;
	}

	function currentPage() {
		const fromAttr = $('#pp-acp').attr('data-page');
		const fromUrl = window.location.pathname.split('/').filter(Boolean).pop();
		return [fromAttr, fromUrl].find(p => PAGES.includes(p)) || 'manage';
	}

	function render(html) {
		translator.translate(html, (out) => { $root().html(out); });
	}

	function table(head, rows) {
		return `<div class="table-responsive"><table class="table table-sm align-middle"><thead><tr>${head.map(h => `<th>${h}</th>`).join('')}</tr></thead><tbody>${rows.join('') || `<tr><td colspan="${head.length}" class="text-muted">[[password-protect:acp.empty]]</td></tr>`}</tbody></table></div>`;
	}

	// ---------- protections table (manage / categories / topics) ----------
	function protectionsPage(kind) {
		api.get(`${API}/admin/protections`).then((all) => {
			let rows = all;
			if (kind === 'categories') rows = all.filter(r => r.type === 'c');
			if (kind === 'topics') rows = all.filter(r => r.type === 't');
			const state = { q: '', type: 'all', status: 'all', sort: 'createdAt', dir: -1 };
			const draw = () => {
				let list = rows.filter(r => (!state.q || (`${r.title} ${r.categoryName} ${r.creatorName}`).toLowerCase().includes(state.q.toLowerCase()))
					&& (state.type === 'all' || r.type === state.type)
					&& (state.status === 'all' || (state.status === 'active') === r.active));
				list = list.slice().sort((a, b) => ((a[state.sort] > b[state.sort] ? 1 : -1) * state.dir));
				const body = list.map(r => `<tr>
					<td><a href="${rel}/${r.type === 'c' ? 'category' : 'topic'}/${r.id}/${esc(r.slug)}" target="_blank">${esc(r.title)}</a></td>
					<td>${r.type === 'c' ? '[[password-protect:acp.type.category]]' : '[[password-protect:acp.type.topic]]'}</td>
					<td>${esc(r.categoryName)}</td>
					<td>${r.active ? '<span class="badge bg-success">[[password-protect:acp.status.active]]</span>' : '<span class="badge bg-secondary">[[password-protect:acp.status.inactive]]</span>'}${r.hidden ? ' <span class="badge bg-warning text-dark">[[password-protect:acp.hidden]]</span>' : ''}${r.exempt ? ' <span class="badge bg-info text-dark">[[password-protect:acp.exempt]]</span>' : ''}</td>
					<td>${r.source === 'auto' ? `[[password-protect:acp.source.auto]] (${esc(r.ruleName)})` : '[[password-protect:acp.source.manual]]'}</td>
					<td>${esc(r.creatorName)}</td><td>${fmt(r.createdAt)}</td><td>${fmt(r.endAt)}</td>
					<td>${r.type === 't' ? (r.lockChange || r.lockRemove ? '[[password-protect:acp.yes]]' : '[[password-protect:acp.no]]') : '—'}</td>
					<td class="text-nowrap"><button class="btn btn-sm btn-outline-primary pp-edit" data-key="${r.key}">[[password-protect:acp.edit]]</button>
						<button class="btn btn-sm btn-outline-danger pp-del" data-key="${r.key}">[[password-protect:form.remove]]</button></td></tr>`);
				$('#pp-rows').html(table(['[[password-protect:acp.col.name]]', '[[password-protect:acp.col.type]]', '[[password-protect:acp.col.category]]', '[[password-protect:acp.col.status]]', '[[password-protect:acp.col.source]]', '[[password-protect:acp.col.creator]]', '[[password-protect:acp.col.created]]', '[[password-protect:acp.col.expires]]', '[[password-protect:acp.col.locked]]', ''], body));
				translator.translate($('#pp-rows').html(), h => $('#pp-rows').html(h));
			};
			render(`
				<div class="d-flex flex-wrap gap-2 mb-3">
					<input class="form-control w-auto" id="pp-q" placeholder="[[password-protect:acp.search]]">
					<select class="form-select w-auto" id="pp-type"><option value="all">[[password-protect:acp.all-types]]</option><option value="c">[[password-protect:acp.type.category]]</option><option value="t">[[password-protect:acp.type.topic]]</option></select>
					<select class="form-select w-auto" id="pp-status"><option value="all">[[password-protect:acp.all-status]]</option><option value="active">[[password-protect:acp.status.active]]</option><option value="inactive">[[password-protect:acp.status.inactive]]</option></select>
					<select class="form-select w-auto" id="pp-sort"><option value="createdAt">[[password-protect:acp.col.created]]</option><option value="title">[[password-protect:acp.col.name]]</option><option value="endAt">[[password-protect:acp.col.expires]]</option></select>
					${kind !== 'topics' ? '<button class="btn btn-primary" id="pp-add-cat">[[password-protect:acp.add-category]]</button>' : ''}
				</div><div id="pp-rows"></div>`);
			setTimeout(() => {
				draw();
				$('#pp-q').on('input', function () { state.q = this.value; draw(); });
				$('#pp-type').on('change', function () { state.type = this.value; draw(); });
				$('#pp-status').on('change', function () { state.status = this.value; draw(); });
				$('#pp-sort').on('change', function () { state.sort = this.value; state.dir = this.value === 'title' ? 1 : -1; draw(); });
				$('#pp-content').off('click.pp').on('click.pp', '.pp-edit', function () { editProtection($(this).data('key'), rows.find(r => r.key === $(this).data('key'))); })
					.on('click.pp', '.pp-del', function () {
						const key = $(this).data('key');
						const [t, id] = key.split(':');
						bootbox.confirm('[[password-protect:acp.confirm-remove]]', (yes) => {
							if (yes) api.del(`${API}/protection/${t}/${id}`, {}).then(() => { toast('success', '[[password-protect:form.removed]]'); ACP.load(kind); }).catch(fail);
						});
					});
				$('#pp-add-cat').on('click', () => {
					bootbox.prompt({ title: '[[password-protect:acp.category-id]]', inputType: 'number', callback: (v) => { if (v) editProtection(`c:${parseInt(v, 10)}`, null); } });
				});
			}, 0);
		}).catch(fail);
	}

	function editProtection(key, cur) {
		const [t, id] = key.split(':');
		const isCat = t === 'c';
		const p = cur || {};
		const html = `<form class="pp-edit-form">
			<div class="mb-2"><label class="form-label">[[password-protect:form.password]]</label><input type="password" class="form-control" name="password" autocomplete="new-password" placeholder="${cur ? '[[password-protect:form.keep-password]]' : ''}"></div>
			<div class="mb-2"><label class="form-label">[[password-protect:form.message]]</label><textarea class="form-control" name="message" rows="2" maxlength="1000">${esc(p.message || '')}</textarea></div>
			<div class="row g-2 mb-2"><div class="col"><label class="form-label">[[password-protect:form.start]]</label><input type="datetime-local" class="form-control" name="startAt" value="${local(p.startAt)}"></div>
			<div class="col"><label class="form-label">[[password-protect:form.end]]</label><input type="datetime-local" class="form-control" name="endAt" value="${local(p.endAt)}"></div></div>
			<div class="form-check"><input class="form-check-input" type="checkbox" name="enabled" id="pp-en" ${p.enabled === false ? '' : 'checked'}><label class="form-check-label" for="pp-en">[[password-protect:form.enabled]]</label></div>
			${isCat ? `<div class="form-check"><input class="form-check-input" type="checkbox" name="hidden" id="pp-hid" ${p.hidden ? 'checked' : ''}><label class="form-check-label" for="pp-hid">[[password-protect:form.hidden]]</label></div>` : `<div class="form-check"><input class="form-check-input" type="checkbox" name="exempt" id="pp-ex" ${p.exempt ? 'checked' : ''}><label class="form-check-label" for="pp-ex">[[password-protect:form.exempt]]</label></div>
			<div class="form-check"><input class="form-check-input" type="checkbox" name="lockChange" id="pp-lc" ${p.lockChange ? 'checked' : ''}><label class="form-check-label" for="pp-lc">[[password-protect:form.lock-change]]</label></div>
			<div class="form-check"><input class="form-check-input" type="checkbox" name="lockRemove" id="pp-lr" ${p.lockRemove ? 'checked' : ''}><label class="form-check-label" for="pp-lr">[[password-protect:form.lock-remove]]</label></div>`}
		</form>`;
		T(html, (out) => {
			const dlg = bootbox.dialog({
				title: esc(p.title || key),
				message: out,
				buttons: {
					cancel: { label: '[[password-protect:modal.cancel]]', className: 'btn-link' },
					save: {
						label: '[[password-protect:form.save]]',
						className: 'btn-primary',
						callback: () => {
							const f = dlg.find('form');
							const g = n => f.find(`[name=${n}]`);
							const body = {
								password: g('password').val() || undefined,
								message: g('message').val(),
								startAt: parseDt(g('startAt').val()),
								endAt: parseDt(g('endAt').val()),
								enabled: g('enabled').prop('checked'),
							};
							if (isCat) body.hidden = g('hidden').prop('checked'); else body.exempt = g('exempt').prop('checked');
							api.put(`${API}/protection/${t}/${id}`, body).then(() => {
								if (isCat) return null;
								const lock = {};
								if (g('lockChange').prop('checked') !== !!p.lockChange) lock.lockChange = g('lockChange').prop('checked');
								if (g('lockRemove').prop('checked') !== !!p.lockRemove) lock.lockRemove = g('lockRemove').prop('checked');
								return Object.keys(lock).length ? api.post(`${API}/protection/${t}/${id}/lock`, lock) : null;
							}).then(() => { toast('success', '[[password-protect:form.saved]]'); dlg.modal('hide'); ACP.load(ACP.page); }).catch(fail);
							return false;
						},
					},
				},
			});
		});
	}

	// ---------- settings ----------
	function settingsPage() {
		api.get(`${API}/admin/settings`).then(({ settings: s, engine }) => {
			const n = s.notifications;
			const chk = (name, v) => `<div class="form-check"><input class="form-check-input" type="checkbox" data-k="${name}" ${v ? 'checked' : ''}><label class="form-check-label">[[password-protect:set.${name}]]</label></div>`;
			render(`<form id="pp-set" class="col-lg-7">
				<p class="text-muted small">[[password-protect:set.engine]]: ${esc(engine)}</p>
				<div class="mb-3"><label class="form-label">[[password-protect:set.policy]]</label><select class="form-select" data-k="policy">
					<option value="topic" ${s.policy === 'topic' ? 'selected' : ''}>[[password-protect:set.policy.topic]]</option>
					<option value="category" ${s.policy === 'category' ? 'selected' : ''}>[[password-protect:set.policy.category]]</option>
					<option value="both" ${s.policy === 'both' ? 'selected' : ''}>[[password-protect:set.policy.both]]</option></select></div>
				<div class="mb-3"><label class="form-label">[[password-protect:set.messageWho]]</label><select class="form-select" data-k="messageWho">
					<option value="permitted" ${s.messageWho === 'permitted' ? 'selected' : ''}>[[password-protect:set.messageWho.permitted]]</option>
					<option value="creators" ${s.messageWho === 'creators' ? 'selected' : ''}>[[password-protect:set.messageWho.creators]]</option></select>
					<div class="form-text">[[password-protect:set.messageWho.hint]]</div></div>
				<div class="mb-3"><label class="form-label">[[password-protect:set.remember]]</label><select class="form-select" data-k="remember.mode">
					<option value="none" ${s.remember.mode === 'none' ? 'selected' : ''}>[[password-protect:set.remember.none]]</option>
					<option value="session" ${s.remember.mode === 'session' ? 'selected' : ''}>[[password-protect:set.remember.session]]</option>
					<option value="timed" ${s.remember.mode === 'timed' ? 'selected' : ''}>[[password-protect:set.remember.timed]]</option></select></div>
				<div class="row g-2 mb-3"><div class="col"><label class="form-label">[[password-protect:set.minutes]]</label><input type="number" min="1" class="form-control" data-k="remember.minutes" value="${s.remember.minutes}"></div>
					<div class="col"><label class="form-label">[[password-protect:set.sessionMaxHours]]</label><input type="number" min="1" class="form-control" data-k="sessionMaxHours" value="${s.sessionMaxHours}"></div></div>
				<div class="row g-2 mb-3"><div class="col"><label class="form-label">[[password-protect:set.maxAttempts]]</label><input type="number" min="1" class="form-control" data-k="limits.maxAttempts" value="${s.limits.maxAttempts}"></div>
					<div class="col"><label class="form-label">[[password-protect:set.blockMinutes]]</label><input type="number" min="1" class="form-control" data-k="limits.blockMinutes" value="${s.limits.blockMinutes}"></div></div>
				<div class="form-check mb-3"><input class="form-check-input" type="checkbox" data-k="limits.progressive" ${s.limits.progressive ? 'checked' : ''}><label class="form-check-label">[[password-protect:set.progressive]]</label></div>
				<h6>[[password-protect:set.notifications]]</h6>
				${['ownerAdded', 'ownerChanged', 'ownerRemoved', 'ownerLocked', 'adminAlerts', 'expiryReminder'].map(k => chk(`notifications.${k}`, n[k]).replace(`set.notifications.${k}`, `set.${k}`)).join('')}
				<div class="row g-2 my-2"><div class="col"><label class="form-label">[[password-protect:set.adminAlertThreshold]]</label><input type="number" min="1" class="form-control" data-k="notifications.adminAlertThreshold" value="${n.adminAlertThreshold}"></div>
					<div class="col"><label class="form-label">[[password-protect:set.reminderHours]]</label><input type="number" min="1" class="form-control" data-k="notifications.reminderHours" value="${n.reminderHours}"></div></div>
				<div class="mb-3"><label class="form-label">[[password-protect:set.replyContent]]</label><select class="form-select" data-k="notifications.replyContent">
					<option value="generic" ${n.replyContent === 'generic' ? 'selected' : ''}>[[password-protect:set.reply.generic]]</option>
					<option value="none" ${n.replyContent === 'none' ? 'selected' : ''}>[[password-protect:set.reply.none]]</option></select></div></form>`);
			setTimeout(() => $('#pp-set').on('submit', (e) => {
				e.preventDefault();
				const body = {};
				$('#pp-set [data-k]').each(function () {
					const path = $(this).data('k').split('.');
					const val = this.type === 'checkbox' ? this.checked : (this.type === 'number' ? parseInt(this.value, 10) : this.value);
					let o = body;
					path.slice(0, -1).forEach((p) => { o[p] = o[p] || {}; o = o[p]; });
					o[path[path.length - 1]] = val;
				});
				api.put(`${API}/admin/settings`, body).then(() => toast('success', '[[password-protect:form.saved]]')).catch(fail);
			}), 0);
		}).catch(fail);
	}

	// ---------- permissions ----------
	function permissionsPage() {
		Promise.all([api.get(`${API}/admin/settings`), api.get(`${API}/admin/groups`)]).then(([{ settings: s, permissions }, groups]) => {
			const all = ['guests'].concat(groups).filter((g, i, a) => a.indexOf(g) === i);
			render(`<p class="text-muted">[[password-protect:perm.note]]</p><form id="pp-perm">${table(['[[password-protect:perm.permission]]', '[[password-protect:perm.groups]]'], permissions.map(p => `<tr><td>[[password-protect:perm.${p}]]</td><td>
				<select multiple class="form-select" size="5" data-p="${p}">${all.map(g => `<option value="${esc(g)}" ${(s.permissions[p] || []).includes(g) ? 'selected' : ''}>${esc(g)}</option>`).join('')}</select></td></tr>`))}</form>`);
			setTimeout(() => $('#pp-perm').on('submit', (e) => {
				e.preventDefault();
				const body = { permissions: {} };
				$('#pp-perm select').each(function () { body.permissions[$(this).data('p')] = $(this).val() || []; });
				api.put(`${API}/admin/settings`, body).then(() => toast('success', '[[password-protect:form.saved]]')).catch(fail);
			}), 0);
		}).catch(fail);
	}

	// ---------- rules ----------
	function rulesPage() {
		api.get(`${API}/admin/rules`).then((rules) => {
			render(`<button class="btn btn-primary mb-3" id="pp-new-rule">[[password-protect:rule.new]]</button>${table(['[[password-protect:rule.name]]', '[[password-protect:rule.enabled]]', '[[password-protect:rule.conditions]]', '[[password-protect:rule.window]]', ''], rules.map(r => `<tr>
				<td>${esc(r.name)}</td><td><div class="form-check form-switch"><input class="form-check-input pp-toggle" type="checkbox" data-id="${r.id}" ${r.enabled ? 'checked' : ''}></div></td>
				<td class="small">cids: ${esc((r.conditions.cids || []).join(', ') || '—')}<br>uids: ${esc((r.conditions.uids || []).join(', ') || '—')}<br>groups: ${esc((r.conditions.groups || []).join(', ') || '—')}</td>
				<td class="small">${fmt(r.startAt)} → ${fmt(r.endAt)}${r.removeAt ? `<br>[[password-protect:rule.removeAt]]: ${fmt(r.removeAt)}` : ''}</td>
				<td class="text-nowrap"><button class="btn btn-sm btn-outline-primary pp-rule-edit" data-id="${r.id}">[[password-protect:acp.edit]]</button> <button class="btn btn-sm btn-outline-danger pp-rule-del" data-id="${r.id}">[[password-protect:form.remove]]</button></td></tr>`))}`);
			setTimeout(() => {
				$('#pp-new-rule').on('click', () => ruleDialog(null));
				$('.pp-rule-edit').on('click', function () { ruleDialog(rules.find(r => r.id === $(this).data('id'))); });
				$('.pp-rule-del').on('click', function () { const id = $(this).data('id'); bootbox.confirm('[[password-protect:acp.confirm-remove]]', (y) => { if (y) api.del(`${API}/admin/rules/${id}`, {}).then(() => ACP.load('rules')).catch(fail); }); });
				$('.pp-toggle').on('change', function () { api.post(`${API}/admin/rules/${$(this).data('id')}/toggle`, { enabled: this.checked }).catch(fail); });
			}, 0);
		}).catch(fail);
	}

	function ruleDialog(r) {
		const x = r || { conditions: {}, exceptions: {} };
		const list = a => esc((a || []).join(', '));
		T(`<form class="pp-rule-form">
			<div class="mb-2"><label class="form-label">[[password-protect:rule.name]]</label><input class="form-control" name="name" value="${esc(x.name || '')}"></div>
			<div class="mb-2"><label class="form-label">[[password-protect:form.password]]</label><input type="password" class="form-control" name="password" autocomplete="new-password" placeholder="${r ? '[[password-protect:form.keep-password]]' : ''}"></div>
			<div class="mb-2"><label class="form-label">[[password-protect:form.message]]</label><textarea class="form-control" name="message" rows="2">${esc(x.message || '')}</textarea></div>
			<div class="row g-2 mb-2"><div class="col"><label class="form-label">[[password-protect:rule.cids]]</label><input class="form-control" name="cids" value="${list(x.conditions.cids)}"></div>
			<div class="col"><label class="form-label">[[password-protect:rule.uids]]</label><input class="form-control" name="uids" value="${list(x.conditions.uids)}"></div>
			<div class="col"><label class="form-label">[[password-protect:rule.groups]]</label><input class="form-control" name="groups" value="${list(x.conditions.groups)}"></div></div>
			<div class="row g-2 mb-2"><div class="col"><label class="form-label">[[password-protect:rule.x-cids]]</label><input class="form-control" name="xcids" value="${list(x.exceptions.cids)}"></div>
			<div class="col"><label class="form-label">[[password-protect:rule.x-uids]]</label><input class="form-control" name="xuids" value="${list(x.exceptions.uids)}"></div>
			<div class="col"><label class="form-label">[[password-protect:rule.x-groups]]</label><input class="form-control" name="xgroups" value="${list(x.exceptions.groups)}"></div></div>
			<div class="row g-2 mb-2"><div class="col"><label class="form-label">[[password-protect:form.start]]</label><input type="datetime-local" class="form-control" name="startAt" value="${local(x.startAt)}"></div>
			<div class="col"><label class="form-label">[[password-protect:form.end]]</label><input type="datetime-local" class="form-control" name="endAt" value="${local(x.endAt)}"></div>
			<div class="col"><label class="form-label">[[password-protect:rule.removeAt]]</label><input type="datetime-local" class="form-control" name="removeAt" value="${local(x.removeAt)}"></div>
			<div class="col"><label class="form-label">[[password-protect:rule.duration]]</label><input type="number" min="0" class="form-control" name="durationHours" value="${x.durationHours || 0}"></div></div>
			<div class="form-check"><input class="form-check-input" type="checkbox" name="lockChange" id="rl1" ${x.lockChange ? 'checked' : ''}><label class="form-check-label" for="rl1">[[password-protect:form.lock-change]]</label></div>
			<div class="form-check"><input class="form-check-input" type="checkbox" name="lockRemove" id="rl2" ${x.lockRemove ? 'checked' : ''}><label class="form-check-label" for="rl2">[[password-protect:form.lock-remove]]</label></div>
			</form>`, (out) => {
			const dlg = bootbox.dialog({
				title: '[[password-protect:rule.new]]',
				message: out,
				size: 'large',
				buttons: {
					cancel: { label: '[[password-protect:modal.cancel]]', className: 'btn-link' },
					save: {
						label: '[[password-protect:form.save]]',
						className: 'btn-primary',
						callback: () => {
							const f = dlg.find('form');
							const g = n => f.find(`[name=${n}]`);
							const nums = n => g(n).val().split(',').map(s => parseInt(s, 10)).filter(Boolean);
							const strs = n => g(n).val().split(',').map(s => s.trim()).filter(Boolean);
							const body = {
								name: g('name').val(), password: g('password').val() || undefined, message: g('message').val(),
								conditions: { cids: nums('cids'), uids: nums('uids'), groups: strs('groups') },
								exceptions: { cids: nums('xcids'), uids: nums('xuids'), groups: strs('xgroups') },
								startAt: parseDt(g('startAt').val()), endAt: parseDt(g('endAt').val()), removeAt: parseDt(g('removeAt').val()),
								durationHours: parseInt(g('durationHours').val(), 10) || 0,
								lockChange: g('lockChange').prop('checked'), lockRemove: g('lockRemove').prop('checked'), enabled: r ? r.enabled : true,
							};
							(r ? api.put(`${API}/admin/rules/${r.id}`, body) : api.post(`${API}/admin/rules`, body))
								.then(() => { dlg.modal('hide'); ACP.load('rules'); }).catch(fail);
							return false;
						},
					},
				},
			});
		});
	}

	// ---------- personal access ----------
	function accessPage() {
		api.get(`${API}/admin/access`).then((rows) => {
			render(`<form id="pp-grant" class="row g-2 mb-3">
				<div class="col-auto"><input class="form-control" name="username" placeholder="[[password-protect:acc.username]]" required></div>
				<div class="col-auto"><select class="form-select" name="type"><option value="t">[[password-protect:acp.type.topic]]</option><option value="c">[[password-protect:acp.type.category]]</option></select></div>
				<div class="col-auto"><input class="form-control" type="number" min="1" name="id" placeholder="ID" required></div>
				<div class="col-auto"><input class="form-control" type="datetime-local" name="expiresAt" title="[[password-protect:acc.expires]]"></div>
				<div class="col-auto"><button class="btn btn-primary" type="submit">[[password-protect:acc.grant]]</button></div></form>
				${table(['[[password-protect:acc.user]]', '[[password-protect:acc.item]]', '[[password-protect:acc.granted]]', '[[password-protect:acc.expires]]', '[[password-protect:acp.col.status]]', ''], rows.map(a => `<tr><td>${esc(a.username)}</td><td>${esc(a.key)}</td><td>${fmt(a.grantedAt)}</td><td>${a.expiresAt ? fmt(a.expiresAt) : '[[password-protect:acc.permanent]]'}</td>
				<td>${a.active ? '<span class="badge bg-success">[[password-protect:acp.status.active]]</span>' : `<span class="badge bg-secondary">${a.revokedAt ? '[[password-protect:acc.revoked]]' : '[[password-protect:acc.expired]]'}</span>`}</td>
				<td>${a.active ? `<button class="btn btn-sm btn-outline-danger pp-revoke" data-id="${a.id}">[[password-protect:acc.revoke]]</button>` : ''}</td></tr>`))}`);
			setTimeout(() => {
				$('#pp-grant').on('submit', function (e) {
					e.preventDefault();
					const g = n => $(this).find(`[name=${n}]`).val();
					api.post(`${API}/admin/access`, { username: g('username'), key: `${g('type')}:${g('id')}`, expiresAt: parseDt(g('expiresAt')) || 0 }).then(() => ACP.load('access')).catch(fail);
				});
				$('.pp-revoke').on('click', function () { api.del(`${API}/admin/access/${$(this).data('id')}`, {}).then(() => ACP.load('access')).catch(fail); });
			}, 0);
		}).catch(fail);
	}

	// ---------- log ----------
	function logPage() {
		api.get(`${API}/admin/log`).then(({ rows, total }) => {
			render(`<p class="text-muted small">${total}</p>${table(['[[password-protect:log.time]]', '[[password-protect:log.user]]', '[[password-protect:log.action]]', '[[password-protect:log.item]]', '[[password-protect:log.result]]'], rows.map(r => `<tr><td>${fmt(r.ts)}</td><td>${esc(r.username)}</td><td>${esc(r.action)}</td><td>${esc(r.key)}</td><td>${esc(r.result)}</td></tr>`))}`);
		}).catch(fail);
	}

	ACP.load = function (page) {
		ACP.page = page;
		$('#pp-tabs .pp-nav-link').removeClass('active').filter(`[data-pp-page="${page}"]`).addClass('active');
		// the header "Save" button belongs to the two form pages
		const formId = { settings: 'pp-set', permissions: 'pp-perm' }[page];
		$('#pp-save').prop('hidden', !formId).attr('form', formId || null);
		if (page === 'settings') settingsPage();
		else if (page === 'permissions') permissionsPage();
		else if (page === 'rules') rulesPage();
		else if (page === 'access') accessPage();
		else if (page === 'log') logPage();
		else protectionsPage(page);
	};

	ACP.init = function () {
		const page = currentPage();
		translator.translate(frameHtml(), (out) => {
			$('#pp-acp').html(out);
			const go = (e) => {
				e.preventDefault();
				const target = $(e.currentTarget).attr('data-pp-page');
				if (window.history && history.replaceState) history.replaceState(null, '', `${rel}/admin/plugins/password-protect/${target}`);
				$('#pp-acp').attr('data-page', target);
				ACP.load(target);
			};
			$('#pp-tabs').on('click', '.pp-nav-link', go).on('keydown', '.pp-nav-link', (e) => { if (e.key === 'Enter' || e.key === ' ') go(e); });
			ACP.load(page);
		});
	};

	return ACP;
});
