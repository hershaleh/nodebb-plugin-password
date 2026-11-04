<div class="acp-page-container" id="pp-acp" data-page="{page}">
	<style>
		#pp-acp .pp-header { border-bottom: 1px solid var(--bs-border-color); }
		#pp-acp .pp-nav { position: sticky; top: 1rem; }
		#pp-acp .pp-nav-title { font-size: .75rem; font-weight: 600; color: var(--bs-secondary-color); margin: 0 .75rem .5rem; }
		#pp-acp .pp-nav-group { font-size: .7rem; letter-spacing: .02em; color: var(--bs-secondary-color); margin: 1rem .75rem .25rem; text-transform: uppercase; }
		#pp-acp .pp-nav a { display: block; padding: .4rem .75rem; border-radius: .375rem; font-size: .8rem; color: var(--bs-body-color); text-decoration: none; }
		#pp-acp .pp-nav a:hover { background: var(--bs-tertiary-bg); }
		#pp-acp .pp-nav a.active { background: var(--bs-secondary-bg); font-weight: 600; }
	</style>
	<div class="pp-header d-flex align-items-center justify-content-between gap-2 pb-2 mb-4">
		<h4 class="mb-0 fw-semibold"><i class="fa fa-lock text-muted"></i> [[password-protect:acp.title]]</h4>
		<button type="submit" class="btn btn-primary btn-sm" id="pp-save" hidden>[[password-protect:form.save]]</button>
	</div>
	<div class="row">
		<div class="col-lg-9 order-2 order-lg-1"><div id="pp-content"></div></div>
		<div class="col-lg-3 order-1 order-lg-2 mb-4">
			<nav class="pp-nav" id="pp-tabs" aria-label="[[password-protect:acp.nav.title]]">
				<div class="pp-nav-title">[[password-protect:acp.nav.title]]</div>
				<div class="pp-nav-group">[[password-protect:acp.nav.protections]]</div>
				<a class="nav-link" data-pp-page="manage" href="{config.relative_path}/admin/plugins/password-protect/manage">[[password-protect:acp.tab.manage]]</a>
				<a class="nav-link" data-pp-page="categories" href="{config.relative_path}/admin/plugins/password-protect/categories">[[password-protect:acp.tab.categories]]</a>
				<a class="nav-link" data-pp-page="topics" href="{config.relative_path}/admin/plugins/password-protect/topics">[[password-protect:acp.tab.topics]]</a>
				<div class="pp-nav-group">[[password-protect:acp.nav.configuration]]</div>
				<a class="nav-link" data-pp-page="settings" href="{config.relative_path}/admin/plugins/password-protect/settings">[[password-protect:acp.tab.settings]]</a>
				<a class="nav-link" data-pp-page="permissions" href="{config.relative_path}/admin/plugins/password-protect/permissions">[[password-protect:acp.tab.permissions]]</a>
				<a class="nav-link" data-pp-page="rules" href="{config.relative_path}/admin/plugins/password-protect/rules">[[password-protect:acp.tab.rules]]</a>
				<div class="pp-nav-group">[[password-protect:acp.nav.monitoring]]</div>
				<a class="nav-link" data-pp-page="access" href="{config.relative_path}/admin/plugins/password-protect/access">[[password-protect:acp.tab.access]]</a>
				<a class="nav-link" data-pp-page="log" href="{config.relative_path}/admin/plugins/password-protect/log">[[password-protect:acp.tab.log]]</a>
			</nav>
		</div>
	</div>
</div>
