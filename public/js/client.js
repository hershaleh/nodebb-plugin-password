'use strict';
/* global $, ajaxify, app, require, utils */

(function () {
	const API = '/plugins/password-protect';
	let modalOpen = false;

	function loadModules(cb) {
		require(['api', 'bootbox', 'translator', 'alerts'], cb, () => {
			// NodeBB 3.x without the alerts module: fall back to app.alert*
			require(['api', 'bootbox', 'translator'], (api, bootbox, translator) => cb(api, bootbox, translator, null));
		});
	}

	function notify(alerts, type, msg) {
		if (alerts && alerts[type]) return alerts[type](msg);
		return type === 'success' ? app.alertSuccess(msg) : app.alertError(msg);
	}

	function esc(s) {
		return utils && utils.escapeHTML ? utils.escapeHTML(String(s || '')) : $('<div>').text(String(s || '')).html();
	}

	function errMsg(err) {
		return (err && (err.message || (err.status && err.status.message))) || '[[error:invalid-data]]';
	}

	// ---- password prompt (one dialog per pending key, in order) ----
	function promptKey(mods, pendingList, done) {
		const [api, bootbox, translator, alerts] = mods;
		if (!pendingList.length) return done(true);
		const item = pendingList[0];
		translator.translateKeys(['[[password-protect:modal.title]]', '[[password-protect:modal.password]]', '[[password-protect:modal.submit]]', '[[password-protect:modal.cancel]]', '[[password-protect:modal.show]]', item.type === 'c' ? '[[password-protect:modal.auto.category]]' : '[[password-protect:modal.auto.topic]]'], (t) => {
			const body = `
				<form class="pp-form" autocomplete="off">
					<p class="fw-semibold mb-1">${esc(item.title)}</p>
					<p class="text-muted pp-message">${item.message ? esc(item.message) : t[5]}</p>
					<label class="form-label" for="pp-password">${t[1]}</label>
					<input id="pp-password" type="password" class="form-control" autocomplete="off" maxlength="256" required>
					<div class="text-danger small mt-2 pp-error" role="alert" hidden></div>
				</form>`;
			const dlg = bootbox.dialog({
				title: `<i class="fa fa-lock"></i> ${t[0]}`,
				message: body,
				onEscape: false,
				closeButton: false,
				backdrop: 'static',
				centered: true,
				className: 'pp-unlock-modal',
				buttons: {
					cancel: { label: t[3], className: 'btn-link', callback: () => { modalOpen = false; leaveLocked(); } },
					ok: {
						label: t[2],
						className: 'btn-primary',
						callback: function () {
							const pw = dlg.find('#pp-password').val();
							if (!pw) return false;
							const $err = dlg.find('.pp-error');
							api.post(`${API}/unlock`, { key: item.key, password: pw }).then(() => {
								dlg.modal('hide');
								notify(alerts, 'success', '[[password-protect:modal.success]]');
								promptKey(mods, pendingList.slice(1), done);
							}).catch((err) => {
								translator.translate(errMsg(err), (m) => {
									$err.text(m).prop('hidden', false);
									notify(alerts, 'error', m);
								});
								dlg.find('#pp-password').val('').trigger('focus');
							});
							return false; // keep the dialog open until unlock succeeds
						},
					},
				},
			});
			dlg.find('.modal-dialog').addClass('modal-dialog-centered');
			document.body.classList.add('pp-blur');
			dlg.on('shown.bs.modal', () => dlg.find('#pp-password').trigger('focus'));
			dlg.on('hidden.bs.modal', () => { if (!document.querySelector('.modal.show')) document.body.classList.remove('pp-blur'); });
			dlg.find('form').on('submit', (e) => { e.preventDefault(); dlg.find('.btn-primary').trigger('click'); });
		});
	}

	function injectStyle() {
		if (document.getElementById('pp-style')) return;
		const st = document.createElement('style');
		st.id = 'pp-style';
		st.textContent = 'body.pp-blur .modal-backdrop.show{opacity:1;background:rgba(0,0,0,.35);-webkit-backdrop-filter:blur(8px);backdrop-filter:blur(8px)}'
			+ '.pp-unlock-modal .modal-content{box-shadow:0 1rem 3rem rgba(0,0,0,.25)}';
		document.head.appendChild(st);
	}

	// cancelling the prompt leaves the protected page instead of leaving a dead 403 behind
	function leaveLocked() {
		if (window.history.length > 1) window.history.back(); else ajaxify.go('');
	}

	function isLockedPage() {
		const d = ajaxify.data;
		if (!d) return false;
		return !!d.passwordProtected || !!(d.template && (d.template.name === '403' || d.template['403']));
	}

	function handleLocked() {
		if (modalOpen || !isLockedPage()) return;
		injectStyle();
		modalOpen = true;
		loadModules((...mods) => {
			const [api] = mods;
			api.get(`${API}/status`, { path: window.location.pathname.replace(config.relative_path || '', '') }).then((s) => {
				if (!s || !s.protected) { modalOpen = false; return; }
				promptKey(mods, s.pending, (okAll) => {
					modalOpen = false;
					if (okAll) ajaxify.refresh();
				});
			}).catch(() => { modalOpen = false; });
		});
	}

	// ---- topic tools: protect / change / remove ----
	function openManage(type, id) {
		loadModules((api, bootbox, translator, alerts) => {
			const isTopic = type === 't';
			api.get(`${API}/protection/${type}/${id}`).then((p) => {
				translator.translateKeys([
					'[[password-protect:tools.protect]]', '[[password-protect:form.password]]', '[[password-protect:form.message]]',
					'[[password-protect:form.start]]', '[[password-protect:form.end]]', '[[password-protect:form.lock-change]]',
					'[[password-protect:form.lock-remove]]', '[[password-protect:form.save]]', '[[password-protect:form.remove]]',
					'[[password-protect:form.forgot]]', '[[password-protect:form.account-password]]', '[[password-protect:form.keep-password]]', '[[password-protect:form.message-hint]]', '[[password-protect:form.hidden]]',
					'[[password-protect:form.account-password-required]]', '[[password-protect:form.bypass-groups]]', '[[password-protect:form.bypass-groups-hint]]', '[[password-protect:form.optional]]',
				], (t) => {
					const iso = ts => (ts ? new Date(ts - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16) : '');
					const dlg = bootbox.dialog({
						title: `<i class="fa fa-lock"></i> ${t[0]}`,
						message: `
						<form class="pp-manage" autocomplete="off">
							<div class="mb-3"><label class="form-label">${t[1]}</label>
								<input type="password" name="password" class="form-control" autocomplete="new-password" maxlength="256" placeholder="${p.protected ? t[11] : ''}"></div>
							${p.protected && p.reauth ? `<div class="mb-3"><label class="form-label">${t[14]}</label><input type="password" name="accountPassword" class="form-control" autocomplete="current-password"></div>` : ''}
							${p.can.message ? `<div class="mb-3"><label class="form-label">${t[2]} ${t[17]}</label>
								<textarea name="message" class="form-control" rows="2" maxlength="1000">${esc(p.message || '')}</textarea>
								<div class="form-text">${t[12]}</div></div>` : ''}
							${p.can.bypassGroups ? `<div class="mb-3"><label class="form-label">${t[15]}</label><input name="bypassGroups" class="form-control" value="${esc((p.bypassGroups || []).join(', '))}"><div class="form-text">${t[16]}</div></div>` : ''}
							<div class="row g-2 mb-3">
								<div class="col"><label class="form-label">${t[3]}</label><input type="datetime-local" name="startAt" class="form-control" value="${iso(p.startAt)}"></div>
								<div class="col"><label class="form-label">${t[4]}</label><input type="datetime-local" name="endAt" class="form-control" value="${iso(p.endAt)}"></div>
							</div>
							${isTopic && p.protected && p.can.lockChange ? `<div class="form-check"><input class="form-check-input" type="checkbox" name="lockChange" id="pp-lc" ${p.lockChange ? 'checked' : ''}><label class="form-check-label" for="pp-lc">${t[5]}</label></div>` : ''}
							${isTopic && p.protected && p.can.lockRemove ? `<div class="form-check"><input class="form-check-input" type="checkbox" name="lockRemove" id="pp-lr" ${p.lockRemove ? 'checked' : ''}><label class="form-check-label" for="pp-lr">${t[6]}</label></div>` : ''}
							${!isTopic ? `<div class="form-check"><input class="form-check-input" type="checkbox" name="hidden" id="pp-hid" ${p.hidden ? 'checked' : ''}><label class="form-check-label" for="pp-hid">${t[13]}</label></div>` : ''}
							${isTopic && p.protected && p.can.change ? `<hr><details><summary>${t[9]}</summary>
								<div class="mt-2"><label class="form-label">${t[10]}</label><input type="password" name="accountPassword" class="form-control" autocomplete="current-password">
								<label class="form-label mt-2">${t[1]}</label><input type="password" name="resetPassword" class="form-control" autocomplete="new-password">
								<button type="button" class="btn btn-sm btn-outline-secondary mt-2 pp-reset">${t[9]}</button></div></details>` : ''}
						</form>`,
						buttons: {
							...(p.protected && p.can.remove ? {
								remove: { label: t[8], className: 'btn-danger', callback: () => {
									api.del(`${API}/protection/${type}/${id}`, {}).then(() => { notify(alerts, 'success', '[[password-protect:form.removed]]'); ajaxify.refresh(); }).catch(e => notify(alerts, 'error', errMsg(e)));
								} },
							} : {}),
							save: {
								label: t[7],
								className: 'btn-primary',
								callback: function () {
									const f = dlg.find('form.pp-manage');
									const val = n => f.find(`[name=${n}]`).val();
									const body = {
										password: val('password') || undefined,
										message: val('message'),
										startAt: val('startAt') ? new Date(val('startAt')).getTime() : 0,
										endAt: val('endAt') ? new Date(val('endAt')).getTime() : 0,
									};
									if (f.find('[name=accountPassword]').length) body.accountPassword = val('accountPassword');
									if (f.find('[name=bypassGroups]').length) body.bypassGroups = val('bypassGroups');
									if (!isTopic) body.hidden = f.find('[name=hidden]').prop('checked');
									const lockOps = [];
									if (isTopic && p.protected) {
										const lc = f.find('[name=lockChange]'); const lr = f.find('[name=lockRemove]');
										const lockBody = {};
										if (lc.length && lc.prop('checked') !== p.lockChange) lockBody.lockChange = lc.prop('checked');
										if (lr.length && lr.prop('checked') !== p.lockRemove) lockBody.lockRemove = lr.prop('checked');
										if (Object.keys(lockBody).length) lockOps.push(lockBody);
									}
									const doSave = (p.protected && !p.can.change) ? Promise.resolve() : api.put(`${API}/protection/${type}/${id}`, body);
									doSave.then(() => Promise.all(lockOps.map(b => api.post(`${API}/protection/t/${id}/lock`, b))))
										.then(() => { notify(alerts, 'success', '[[password-protect:form.saved]]'); dlg.modal('hide'); ajaxify.refresh(); })
										.catch(e => notify(alerts, 'error', errMsg(e)));
									return false;
								},
							},
						},
					});
					dlg.find('.pp-reset').on('click', () => {
						const f = dlg.find('form.pp-manage');
						api.post(`${API}/protection/t/${id}/reset`, { accountPassword: f.find('[name=accountPassword]').val(), newPassword: f.find('[name=resetPassword]').val() })
							.then(() => { notify(alerts, 'success', '[[password-protect:form.saved]]'); dlg.modal('hide'); })
							.catch(e => notify(alerts, 'error', errMsg(e)));
						f.find('[name=accountPassword],[name=resetPassword]').val('');
					});
				});
			}).catch(e => notify(alerts, 'error', errMsg(e)));
		});
	}

	// ---- category page: protect the category, and protect selected topics from "topic tools" ----
	function openBulk(tids) {
		loadModules((api, bootbox, translator, alerts) => {
			translator.translateKeys(['[[password-protect:tools.protect]]', '[[password-protect:form.password]]', '[[password-protect:form.message]]', '[[password-protect:form.save]]', '[[password-protect:modal.cancel]]'], (t) => {
				const dlg = bootbox.dialog({
					title: `<i class="fa fa-lock"></i> ${t[0]} (${tids.length})`,
					message: `<form class="pp-bulk" autocomplete="off"><div class="mb-3"><label class="form-label">${t[1]}</label><input type="password" name="password" class="form-control" autocomplete="new-password" maxlength="256" required></div>
						<div class="mb-3"><label class="form-label">${t[2]}</label><textarea name="message" class="form-control" rows="2" maxlength="1000"></textarea></div></form>`,
					buttons: {
						cancel: { label: t[4], className: 'btn-link' },
						save: {
							label: t[3],
							className: 'btn-primary',
							callback: () => {
								const f = dlg.find('form');
								const password = f.find('[name=password]').val();
								if (!password) return false;
								const message = f.find('[name=message]').val();
								Promise.allSettled(tids.map(tid => api.put(`${API}/protection/t/${tid}`, { password, message }))).then((res) => {
									const bad = res.filter(r => r.status === 'rejected');
									if (bad.length) notify(alerts, 'error', errMsg(bad[0].reason)); else notify(alerts, 'success', '[[password-protect:form.saved]]');
									dlg.modal('hide');
									ajaxify.refresh();
								});
								return false;
							},
						},
					},
				});
			});
		});
	}

	function enhanceCategory() {
		const d = ajaxify.data;
		if (!d || !d.template || d.template.name !== 'category' || !d.cid || isLockedPage()) return;
		loadModules((api, bootbox, translator) => {
			api.get(`${API}/me`).then((me) => {
				if (!me || !(me.category || me.topics)) return;
				translator.translateKeys(['[[password-protect:tools.protect]]'], ([label]) => {
					if (me.topics) {
						const $menu = $('.thread-tools .dropdown-menu').first();
						if ($menu.length && !$menu.find('.pp-bulk-protect').length) {
							const li = `<li><a class="dropdown-item rounded-1 d-flex align-items-center gap-2 pp-bulk-protect" href="#" role="menuitem"><i class="fa fa-fw fa-lock text-secondary"></i> <span>${esc(label)}</span></a></li>`;
							const anchor = $menu.find('[component="topic/lock"]').closest('li');
							if (anchor.length) anchor.first().before(li); else $menu.append(li);
						}
					}
					if (me.category && !$('.pp-cat-btn').length) {
						const btn = `<div class="btn-group pp-cat-btn"><button type="button" class="btn btn-ghost btn-sm ff-secondary d-flex gap-2 align-items-center pp-cat-protect"><i class="fa fa-fw fa-lock text-primary"></i><span class="d-none d-md-inline">${esc(label)}</span></button></div>`;
						const $tools = $('.thread-tools').first();
						if ($tools.length) $tools.before(btn);
						else if ($('.topic-list-header').length) $('.topic-list-header').first().prepend(btn);
						else $('[component="category"]').first().before(btn);
					}
				});
			}).catch(() => {});
		});
	}

	$(document).on('click', '.pp-cat-protect', function (e) {
		e.preventDefault();
		const cid = ajaxify.data && ajaxify.data.cid;
		if (cid) openManage('c', cid);
	});
	$(document).on('click', '.pp-bulk-protect', function (e) {
		e.preventDefault();
		require(['topicSelect', 'alerts'], (topicSelect, alerts) => {
			const tids = topicSelect.getSelectedTids();
			if (!tids || !tids.length) return alerts.error('[[error:no-topics-selected]]');
			if (tids.length === 1) return openManage('t', tids[0]);
			return openBulk(tids);
		});
	});

	function initManager() {
		if (!(ajaxify.data && ajaxify.data.template && ajaxify.data.template.name === 'password-protect/manager')) return;
		require(['admin/plugins/password-protect'], m => m.init());
	}

	$(window).on('action:ajaxify.end', initManager);
	$(window).on('action:ajaxify.end', handleLocked);
	$(window).on('action:ajaxify.end', enhanceCategory);
	$(document).on('click', '.pp-protect', function (e) {
		e.preventDefault();
		const tid = ajaxify.data && ajaxify.data.tid;
		if (tid) openManage('t', tid);
	});
	$(document).ready(() => { handleLocked(); enhanceCategory(); initManager(); });
}());
