'use strict';

// Self-contained "password required" page for full page loads of protected URLs.
// It does not depend on NodeBB's theme rendering, so the unlock dialog always
// appears (centred, page behind it blurred) and the content stays closed until
// the password is accepted. Strings are rendered server-side in the user's language.

const fs = require('fs');
const path = require('path');
const nconf = require.main.require('nconf');
const meta = require.main.require('./src/meta');
const user = require.main.require('./src/user');

const cache = {};
function strings(lang) {
	const l = ['he', 'en-GB', 'en-US'].includes(lang) ? lang : (String(lang).startsWith('he') ? 'he' : 'en-GB');
	if (!cache[l]) {
		try { cache[l] = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'languages', l, 'password-protect.json'), 'utf8')); } catch (e) { cache[l] = {}; }
	}
	return { l, s: cache[l] };
}

const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', '\'': '&#39;' }[c]));

exports.render = async (req, uid) => {
	let lang = meta.config.defaultLang || 'en-GB';
	try {
		if (uid > 0) {
			const st = await user.getSettings(uid);
			if (st && st.userLang) lang = st.userLang;
		} else {
			const al = String(req.headers['accept-language'] || '').toLowerCase();
			if (al.startsWith('he')) lang = 'he';
		}
	} catch (e) { /* default language */ }
	const { l, s } = strings(lang);
	const rtl = l === 'he';
	const rel = nconf.get('relative_path') || '';
	const t = k => s[k] || '';
	const errors = {};
	Object.keys(s).filter(k => k.startsWith('error.')).forEach((k) => { errors[k.slice(6)] = s[k]; });
	const cfg = JSON.stringify({
		rel, errors, auto: { c: t('modal.auto.category'), t: t('modal.auto.topic') }, ok: t('modal.success'),
		generic: t('error.locked'), wrong: t('error.wrong-password') || t('error.locked'),
	}).replace(/</g, '\\u003c');
	const siteTitle = esc(meta.config.title || '');
	return `<!DOCTYPE html>
<html lang="${esc(l)}" dir="${rtl ? 'rtl' : 'ltr'}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>${esc(t('modal.title'))} | ${siteTitle}</title>
<style>
*{box-sizing:border-box}html,body{height:100%;margin:0}
body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;background:linear-gradient(135deg,#e9eef7,#f7f3ea);color:#212529}
.site{padding:1.5rem 2rem;font-weight:700;font-size:1.1rem;opacity:.7}
.ghost{max-width:900px;margin:2rem auto;padding:0 2rem}
.ghost i{display:block;height:1rem;border-radius:.5rem;background:#cfd6e2;margin:1rem 0}
.backdrop{position:fixed;inset:0;background:rgba(0,0,0,.35);-webkit-backdrop-filter:blur(8px);backdrop-filter:blur(8px);display:flex;align-items:center;justify-content:center;padding:1rem}
.dlg{background:#fff;border-radius:.6rem;width:100%;max-width:440px;box-shadow:0 1rem 3rem rgba(0,0,0,.3);overflow:hidden}
.dlg h1{font-size:1.1rem;margin:0;padding:1rem 1.25rem;border-bottom:1px solid #dee2e6;display:flex;gap:.5rem;align-items:center}
.body{padding:1.25rem}.item{font-weight:600;margin:0 0 .25rem;word-break:break-word}.msg{color:#6c757d;margin:0 0 1rem;white-space:pre-wrap;word-break:break-word}
label{display:block;margin-bottom:.35rem;font-size:.9rem}
input{width:100%;padding:.55rem .75rem;border:1px solid #ced4da;border-radius:.4rem;font-size:1rem}
input:focus{outline:2px solid #0d6efd55;border-color:#0d6efd}
.err{color:#dc3545;font-size:.85rem;margin-top:.5rem;min-height:1.2em}
.row{display:flex;gap:.5rem;justify-content:flex-end;padding:0 1.25rem 1.25rem}
button{font:inherit;padding:.5rem 1rem;border-radius:.4rem;border:1px solid transparent;cursor:pointer}
.ok{background:#0d6efd;color:#fff}.ok:disabled{opacity:.6}.cancel{background:none;color:#0d6efd}
</style></head><body>
<div class="site">${siteTitle}</div><div class="ghost" aria-hidden="true"><i style="width:60%"></i><i></i><i></i><i style="width:80%"></i><i></i></div>
<div class="backdrop"><form class="dlg" role="dialog" aria-modal="true" aria-labelledby="ttl" autocomplete="off">
<h1 id="ttl">🔒 ${esc(t('modal.title'))}</h1>
<div class="body"><p class="item" id="item"></p><p class="msg" id="msg"></p>
<label for="pw">${esc(t('modal.password'))}</label><input id="pw" type="password" maxlength="256" autocomplete="off" required autofocus>
<div class="err" id="err" role="alert"></div></div>
<div class="row"><button type="button" class="cancel" id="cancel">${esc(t('modal.cancel'))}</button><button type="submit" class="ok" id="go">${esc(t('modal.submit'))}</button></div>
</form></div>
<script>
(function(){
var C=${cfg},API=C.rel+'/api/v3/plugins/password-protect',path=location.pathname.replace(C.rel,''),csrf='',pending=[],cur=null;
var $=function(i){return document.getElementById(i)};
function msgOf(j){var m=j&&j.status&&j.status.message||'';var k=/error\\.([\\w.-]+)/.exec(m);return (k&&C.errors[k[1]])||(j&&j.status&&j.status.code==='too-many-requests'?C.errors['too-many-attempts']:'')||C.wrong}
function show(){cur=pending[0];if(!cur){location.reload();return}$('item').textContent=cur.title||'';$('msg').textContent=cur.message||C.auto[cur.type]||C.generic;$('pw').value='';$('err').textContent='';$('pw').focus()}
fetch(C.rel+'/api/config',{credentials:'same-origin'}).then(function(r){return r.json()}).then(function(c){csrf=c.csrf_token;
return fetch(API+'/status?path='+encodeURIComponent(path),{credentials:'same-origin'})}).then(function(r){return r.json()}).then(function(j){
var s=j.response||j;pending=(s&&s.pending)||[];if(!pending.length){$('msg').textContent=C.generic;$('go').disabled=true}else show()}).catch(function(){$('err').textContent=C.generic});
$('cancel').onclick=function(){if(history.length>1)history.back();else location.href=C.rel+'/'};
document.querySelector('form').onsubmit=function(e){e.preventDefault();if(!cur||!$('pw').value)return;$('go').disabled=true;
fetch(API+'/unlock',{method:'POST',credentials:'same-origin',headers:{'content-type':'application/json','x-csrf-token':csrf},body:JSON.stringify({key:cur.key,password:$('pw').value})})
.then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j}})}).then(function(x){$('go').disabled=false;
if(x.ok){pending.shift();show()}else{$('err').textContent=msgOf(x.j);$('pw').value='';$('pw').focus()}}).catch(function(){$('go').disabled=false;$('err').textContent=C.generic})};
})();
</script></body></html>`;
};
