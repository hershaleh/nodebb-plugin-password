'use strict';

// Pure policy logic (no NodeBB dependency): which protection keys must be
// unlocked to view an item. Keys look like "c:5" (category) or "t:12" (topic).

/**
 * @param {{cat?:string|null, topic?:string|null, exempt?:boolean, mode:'topic'|'category'|'both'}} p
 *  cat    - key of the nearest active category protection (or null)
 *  topic  - key of the topic's own active protection (or null)
 *  exempt - topic is exempted from inherited category protection
 *  mode   - collision policy when both apply
 * @returns {string[]} keys that must all be satisfied
 */
exports.requiredKeys = function ({ cat, topic, exempt, mode }) {
	const c = cat && !exempt ? cat : null;
	const t = topic || null;
	if (c && t) {
		if (mode === 'category') return [c];
		if (mode === 'both') return [c, t];
		return [t]; // 'topic' is the default
	}
	if (c) return [c];
	if (t) return [t];
	return [];
};

exports.isActive = function (prot, now) {
	if (!prot || !prot.enabled || !prot.hash) return false;
	if (prot.startAt && now < prot.startAt) return false;
	if (prot.endAt && now >= prot.endAt) return false;
	return true;
};

/** A session grant is "v:exp" and is valid only for the current password version. */
exports.grantValid = function (grant, prot, now) {
	if (!grant || !prot) return false;
	const [v, exp] = String(grant).split(':');
	return Number(v) === prot.version && Number(exp) > now;
};

exports.parseKey = function (key) {
	const m = /^([tc]):(\d+)$/.exec(String(key));
	return m ? { type: m[1], id: parseInt(m[2], 10) } : null;
};
