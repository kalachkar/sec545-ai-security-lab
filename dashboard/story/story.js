/* SEC545 story: 9 pages, one idea each. Big visuals, few words; the talk track lives in speaker notes.
   Reads window.BENCH (aggregates only, see export_data.py), LOGOS/SHOTS (embedded images), and for
   pages 1-3 the scanner rows the main dashboard embeds (scannerRows, counts, badge, sev, esc, num). */
const B = (typeof BENCH === 'object' && BENCH) || {};
const BR = B.runs || [];
const L = (typeof LOGOS === 'object' && LOGOS) || {};
const SH = (typeof SHOTS === 'object' && SHOTS) || {};
const MAIN = '02';     // pages 6-7: the harness as first built (page 8 shows the fix, round 03)
const FIX = '03';
const PLANTED = 21;

const run = (app, model, mode = 'harness', repeat = 1, round = MAIN) =>
  BR.find(r => r.app === app && r.model === model && r.mode === mode && r.repeat === repeat && r.round === round);
const val = (x, d = '—') => (x === null || x === undefined ? d : x);
const fmtTok = n => (n >= 1e6 ? (n / 1e6).toFixed(1) + 'M' : n >= 1e3 ? Math.round(n / 1e3) + 'K' : String(n || 0));
const chip = (kind, icon, text) => `<span class="chip ${kind}">${icon} ${text}</span>`;
const refusedIn = r => (r ? (B.refusals || []).filter(x => x.run_id === r.run_id && x.app === r.app).map(x => x.phase) : []);
const spagStats = (app, rid) => (B.spaghetti || []).find(s => s.app === app && s.run_id === rid) || {};
const head = (step, title) => `<div class="step">${step}</div><h1 class="hero">${title}</h1>`;
const logo = (k, alt) => (L[k] ? `<img class="biglogo" src="${L[k]}" alt="${alt} logo">` : '');
const usdFmt = x => (x === null || x === undefined ? '—' : x < 0.995 ? '$' + x.toFixed(2) : '$' + x.toFixed(x < 10 ? 2 : 0));

const PRINCIPLES = {
  1: ['⚙️', 'Use AI where it matters.', 'If deterministic rules do the job, they win.', 'Repeatable beats clever.'],
  2: ['🧰', 'Invest in the harness.', 'Process, context and checks turn a model into a security tool.', 'Then pick the model that fits.'],
  3: ['🧑‍⚖️', 'AI accelerates. Humans stay in the loop.', 'A human makes the final call.', ''],
};
const principle = n => { const [icon, title, line, sub] = PRINCIPLES[n];
  return `<div class="pcard"><div class="pshine"></div><div class="pnum">PRINCIPLE ${n}</div><div class="picon">${icon}</div>
    <div class="ptitle">${title}</div><div class="pline">${line}</div>${sub ? `<div class="psub">${sub}</div>` : ''}</div>`; };
const bridge = t => `<div class="bridge">${t} <span>➜</span></div>`;
const big = (value, label, kind = '') => `<div class="bignum ${kind}"><b>${value}</b><span>${label}</span></div>`;
const ba = (label, before, after, good) => `<div class="ba"><div class="bl">${label}</div><div class="bv"><span class="before">${before}</span><span class="arrow">→</span><span class="after ${good ? 'good' : ''}">${after}</span></div></div>`;
const scanRows = () => (typeof scannerRows !== 'undefined' ? scannerRows : []);
const toolOf = f => (f.tool.startsWith('trivy') ? 'trivy' : f.tool);

/* ============ 1 · The pipeline ============ */
function p1() {
  const sc = (k, name, kind, what) => `<div class="scan"><div class="slogo">${logo(k, name)}</div><b>${name}</b><span class="skind">${kind}</span><small>${what}</small></div>`;
  return `${head('1 · The pipeline', 'How we secure an app <em>today</em>')}
  <div class="pipe">
    <a class="pnode applink" href="#apps" title="Meet the apps"><div class="pi bob">🧱</div><b>Application</b><small class="apps">🍔 SnackOverflow<br>🤖 RAGnarok (GenAI)</small><small class="meet">meet the apps ↗</small></a>
    <div class="arrow flowing"><span></span></div>
    <div class="scanners3">
      ${sc('trivy', 'Trivy', 'SCA', 'vulnerable dependencies')}
      ${sc('semgrep', 'Semgrep', 'SAST', 'risky code patterns')}
      ${sc('trufflesecurity', 'TruffleHog', 'Secrets', 'leaked credentials')}
    </div>
    <div class="arrow flowing"><span></span></div>
    <div class="pnode"><div class="pi">📊</div><b>Findings</b></div>
    <div class="arrow flowing"><span></span></div>
    <div class="pnode"><div class="pi bob">🕵️</div><b>Analyst</b></div>
    <div class="arrow flowing"><span></span></div>
    <div class="pnode"><div class="pi">🛠️</div><b>Fix</b></div>
  </div>
  ${bridge('Before we fix anything: what comes out of the scanners?')}`;
}

/* ============ 2 · The findings ============ */
function p2() {
  const R = scanRows(), sevs = ['critical', 'high', 'medium', 'low', 'info'];
  const tools = [['trivy', 'Trivy', 'trivy'], ['semgrep', 'Semgrep', 'semgrep'], ['trufflesecurity', 'TruffleHog', 'trufflehog']];
  const cell = (n, s) => `<td class="sv ${n ? s : 'zero'}">${n ? num(n) : '·'}</td>`;
  const row = (k, name, t) => { const x = R.filter(f => toolOf(f) === t), c = counts(x);
    return `<tr><td class="tn">${logo(k, name)}<b>${name}</b></td>${sevs.map(s => cell(c[s], s)).join('')}<td class="tt">${num(x.length)}</td></tr>`; };
  const all = counts(R);
  const found = ['snackoverflow', 'ragnarok'].map(a => (BR.find(r => r.app === a && r.scanner_found !== undefined) || {}).scanner_found || 0);
  const claims = ['snackoverflow', 'ragnarok'].map(a => (BR.find(r => r.app === a && r.triage_items) || {}).triage_items || 0).reduce((a, b) => a + b, 0);
  const hours = Math.round((R.length * 5) / 60);
  return `${head('2 · The findings', 'Three problems: <em>noise, accuracy, time.</em>')}
  <table class="sevmatrix"><thead><tr><th></th>${sevs.map(s => `<th class="${s}">${s}</th>`).join('')}<th>total</th></tr></thead>
    <tbody>${tools.map(t => row(...t)).join('')}</tbody>
    <tfoot><tr><td class="tn"><b>All scanners</b></td>${sevs.map(s => `<td class="sv ${s}">${num(all[s])}</td>`).join('')}<td class="tt">${num(R.length)}</td></tr></tfoot></table>
  <div class="threads">
    <div class="thr noise"><div class="tk">📢 Noise</div><b>${num(R.length)} → ${claims}</b><span>alerts → distinct claims</span></div>
    <div class="thr acc"><div class="tk">🎯 Accuracy</div><b>${found[0] + found[1]} of 42</b><span>planted bugs found · 5 of 13 safe decoys flagged</span></div>
    <div class="thr time"><div class="tk">⏱️ Time</div><b>≈${hours} h</b><span>at 5 min per alert (assumed)</span></div>
  </div>
  ${bridge('Can AI help with noise, accuracy and time?')}`;
}

/* ============ 3 · Where AI fits ============ */
function p3() {
  const found = ['snackoverflow', 'ragnarok'].map(a => (BR.find(r => r.app === a && r.scanner_found !== undefined) || {}).scanner_found || 0);
  const missed = PLANTED * 2 - found[0] - found[1];
  const cells = Array.from({ length: PLANTED * 2 }, (_, k) => `<i class="${k < found[0] + found[1] ? 'hit' : 'miss'}"></i>`).join('');
  return `${head('3 · So what does that mean?', 'AI helps <em>here</em>. Not <em>there</em>.')}
  <div class="fit">
    <div class="fitcol yes"><div class="fittag">✅ Good use of AI</div>
      <div class="fitcard"><div class="fi">⚖️</div><div><b>Triage</b><span>📢 Noise: is this finding real? reachable?</span></div></div>
      <div class="fitcard"><div class="fi">🔍</div><div><b>Discover</b><span>🎯 Accuracy: what did rule-based scanners miss?</span></div></div>
      <div class="waffle2"><div class="cells">${cells}</div><small><i class="lg hit"></i><b>${42 - missed}</b> caught by scanners <i class="lg miss"></i><b>${missed}</b> missed by every scanner · 42 planted bugs (21 per app)</small></div>
    </div>
    <div class="fitcol no"><div class="fittag">🚫 No AI needed</div>
      <div class="th">${logo('trufflesecurity', 'TruffleHog')}<b>TruffleHog</b></div>
      <div class="thrules"><span>🧬 800+ secret types</span><span>🔣 signatures &amp; regex</span><span>✅ live check for many secret types</span></div>
      <div class="thverdict">Rules win. Keep them.</div>
    </div>
  </div>
  ${principle(1)}
  ${bridge('Let’s try the shiniest model first.')}`;
}

/* ============ 4 · The shiny model ============ */
function spaghettiSvg() {
  const noodles = Array.from({ length: 22 }, (_, i) => {
    const y = 60 + (i * 13) % 180, a = 40 + (i * 37) % 120, b = 220 - (i * 23) % 150;
    return `<path d="M${20 + (i * 17) % 60} ${y} C ${120 + (i * 31) % 200} ${a}, ${260 + (i * 13) % 180} ${b}, ${560 - (i * 19) % 80} ${80 + (i * 29) % 160}" />`;
  }).join('');
  const tags = [['CRITICAL', 90, 92], ['CVE-2021-25289', 320, 70], ['HIGH', 450, 190], ['FP?', 200, 210], ['TP?', 380, 130], ['.env:7', 130, 160]]
    .map(([t, x, y]) => `<g transform="translate(${x} ${y}) rotate(${(x % 7) - 3})"><rect x="-4" y="-15" width="${t.length * 9 + 12}" height="22" rx="5" fill="${t === 'CRITICAL' || t === 'HIGH' ? '#d03b3b' : '#1f2a3f'}"/><text x="${t.length * 4.5 + 2}" y="1" text-anchor="middle" font-size="12" font-weight="800" fill="#fff">${t}</text></g>`).join('');
  return `<svg class="spag" viewBox="0 0 600 280" role="img" aria-label="A plate of tangled spaghetti mixed with security alerts">
    <ellipse cx="300" cy="160" rx="290" ry="115" fill="#f3f1ea"/><ellipse cx="300" cy="160" rx="245" ry="92" fill="#e9e4d6"/>
    <g fill="none" stroke="#f4c542" stroke-width="7" stroke-linecap="round" opacity=".95">${noodles}</g>
    <g fill="#b5431f"><circle cx="230" cy="140" r="16"/><circle cx="350" cy="175" r="18"/><circle cx="290" cy="110" r="14"/></g>${tags}</svg>`;
}
function p4() {
  const s1 = run('snackoverflow', 'opus-5-5', 'spaghetti', 1), s2 = run('snackoverflow', 'opus-5-5', 'spaghetti', 2);
  if (!s1 || !s2) return `${head('4', 'Spaghetti')}<p class="pending">No data yet.</p>`;
  const st1 = spagStats('snackoverflow', s1.run_id), st2 = spagStats('snackoverflow', s2.run_id);
  const g = run('ragnarok', 'opus-5-5', 'spaghetti', 1);
  return `${head('4 · Grab the best model', 'One prompt. Two runs. <em>Two answers.</em>')}
  <div class="p4top">
    <div class="p4left">
      <div class="search">🔍 <span>best AI model for security…</span><b>✨ Opus 5.5</b></div>
      <div class="shovelrow"><div class="sin">📁<b>all the code</b></div><div class="plus">+</div><div class="sin">🚨<b>490 findings</b></div>
        <div class="arrow flowing"><span></span></div><div class="sin model">🧠<b>Opus 5.5</b><small>one prompt</small></div></div>
      <div class="twoRuns"><div class="tr"><span>Run 1</span><b>${val(st1.tp)}</b><small>findings called “real”</small></div><div class="neq">≠</div>
        <div class="tr"><span>Run 2</span><b>${val(st2.tp)}</b><small>same prompt, same model</small></div></div>
    </div>
    <div class="wrongs"><div class="wt">🚩 What went wrong</div>
      <div class="w"><i>🔀</i><span><b>Same rule, both verdicts:</b> pickle and raw SQL <code>text()</code> called real <u>and</u> false</span></div>
      <div class="w"><i>🧩</i><span><b>${val(st1.inconsistent)} groups</b> of identical findings got mixed labels</span></div>
      <div class="w"><i>👻</i><span><b>${s1.ai_unplanted} “new bugs”</b> not in the answer key</span></div>
      <div class="w"><i>🪤</i><span>Run 2 flagged a <b>safe decoy</b> as a bug</span></div>
      <div class="w"><i>🧾</i><span><b>No evidence:</b> no file:line, no source → sink</span></div>
      <div class="w"><i>🛑</i><span>RAGnarok: <b>blocked</b> by the safety filter, 2 of 2 runs</span></div>
    </div>
  </div>
  <div class="p4bottom">
    <div class="spagbig">${spaghettiSvg()}</div>
    <div class="p4right"><div class="spagcap">This isn’t AI-assisted security.<br><b>It’s spaghetti. 🍝</b></div>
      <div class="pivot"><div class="pv1">🍝 → 📖</div><div><b>You don’t fix spaghetti with a better fork.</b><span>You need a <em>recipe</em>. In AppSec, the recipe is called a <em>harness</em>.</span></div><div class="pv2">➜</div></div></div>
  </div>`;
}

/* ============ 5 · The harness ============ */
let storyStage = 'triage';
const CX = 'https://github.com/openai/codex-security/tree/main/plugins/codex-security/skills/';
const STAGES = [
  { id: 'normalize', icon: '🧹', name: 'Normalize', kind: 'code', skill: null, codex: 'publish-findings',
    in: 'Raw scanner output', does: ['One schema, deduplicated, grouped by root cause'], out: r => `${num(r.raw_scanner_findings)} → <b>${r.triage_items}</b> claims` },
  { id: 'triage', icon: '⚖️', name: 'Triage', kind: 'ai', skill: 'triage', codex: 'triage-finding',
    in: 'Scanner claims + repo map', does: ['Open the code at file:line', 'Trace source → control → sink', 'confirmed · not actionable · needs review'], out: r => `<b>${r.triage_confirmed}</b> confirmed · <b>${r.triage_not_actionable}</b> dismissed · <b>${r.triage_needs_review}</b> unsure` },
  { id: 'discovery', icon: '🔍', name: 'Discover', kind: 'ai', skill: 'discovery', codex: 'finding-discovery',
    in: 'Repo map + what scanners already found', does: ['Hunt where scanners are blind: authZ, logic, LLM abuse'], out: r => `<b>+${r.ai_candidates}</b> new` },
  { id: 'validation-static', icon: '✅', name: 'Validate', kind: 'ai', skill: 'validation-static', codex: 'validation',
    in: 'Every claim', does: ['Re-read the code, don’t trust the claim', 'Evidence + proof level'], out: () => 'evidence for every claim' },
  { id: 'attack-path', icon: '🧭', name: 'Severity', kind: 'ai', skill: 'attack-path', codex: 'attack-path-analysis',
    in: 'Validated findings', does: ['Attacker position, reachability, impact → P0-P3'], out: () => 'contextual severity' },
  { id: 'score', icon: '🎯', name: 'Score', kind: 'code', skill: null, codex: null,
    in: 'Hidden answer key', does: ['Deterministic scoring'], out: r => `<b>${r.found}/21</b>` },
];
function p5() {
  const h = run('snackoverflow', 'opus-5-5');
  if (!h) return `${head('5', 'Harness')}<p class="pending">No data yet.</p>`;
  const st = STAGES.find(x => x.id === storyStage) || STAGES[1];
  const skills = (typeof DATA === 'object' && DATA.skills) || {};
  return `${head('5 · The recipe: the harness', 'Write down <em>the analyst’s workflow</em>.')}
  <div class="contract">🧪 Experimentation ≠ AppSec. 🧾 A <b>contract</b> for what an analyst does, borrowed from <a href="${CX}" target="_blank" rel="noopener"><b>OpenAI Codex Security skills</b> ↗</a></div>
  <div class="hflow">${STAGES.map((x, i) => `<button class="hnode ${x.kind} ${x.id === st.id ? 'on' : ''}" data-stage="${x.id}">
      <span class="hn">${i + 1}</span><span class="hi">${x.icon}</span><b>${x.name}</b><small>${x.kind === 'ai' ? '🤖 AI' : '⚙️ rules'}</small><code class="cx">${x.codex || 'ours'}</code></button>${i < STAGES.length - 1 ? '<span class="harrow">➜</span>' : ''}`).join('')}</div>
  <div class="hline ${st.kind}"><b>${st.icon} ${st.name}</b><span>${st.does.join(' · ')}</span><em>→ ${st.out(h)}</em>
    ${st.skill && skills[st.skill] ? `<details class="skillsrc"><summary>📄 SKILL.md</summary><pre>${esc(skills[st.skill])}</pre></details>` : ''}</div>
  <div class="decides"><div class="q">The harness decides</div>
    <span>🎚️ severity</span><span>✅❎ true vs false positive</span><span>🆕 missed by scanners</span><span>🧑 when a human must re-score</span><span>🗺️ severity in <i>your</i> environment</span></div>
  <div class="envscore"><div class="es-from"><span class="sevbig crit">CRITICAL 9.8</span><small>RCE in a package</small></div>
    <div class="es-why"><span>🔌 service is isolated, no internet</span><span>🧩 needs a config we don’t have</span></div>
    <div class="es-to"><span class="sevbig low">LOW</span><small>after environmental scoring</small></div>
    <div class="es-note">illustrative · production adds a threat-model step</div></div>
  ${principle(2)}
  ${bridge('Now run the same model through it.')}`;
}
document.addEventListener('click', e => {
  const b = e.target.closest && e.target.closest('[data-stage]');
  if (b) { storyStage = b.dataset.stage; render(); }
});

/* ============ 6 · Same model + harness ============ */
function p6() {
  const s = run('snackoverflow', 'opus-5-5', 'spaghetti', 1), h = run('snackoverflow', 'opus-5-5'), h2 = run('snackoverflow', 'opus-5-5', 'harness', 2);
  const hg = run('ragnarok', 'opus-5-5');
  if (!s || !h) return `${head('6', 'Harness')}<p class="pending">No data yet.</p>`;
  return `${head('6 · Same Opus, now with the harness', 'Same model. <em>Different outcome.</em>')}
  <div class="bas huge three-threads">
    <div class="ba acc"><div class="bl">🎯 Accuracy · planted bugs found</div><div class="bv"><span class="before">${s.found}/21</span><span class="arrow">→</span><span class="after good">${h.found}/21</span></div><small>“bugs” not in the key: ${s.ai_unplanted} → ${h.ai_unplanted} · decoys flagged: ${h.decoys_flagged + (hg ? hg.decoys_flagged : 0)} of 13</small></div>
    <div class="ba noise"><div class="bl">📢 Noise · items left for an analyst</div><div class="bv"><span class="before">${s.review_queue}</span><span class="arrow">→</span><span class="after good">${h.review_queue}</span></div><small>${h.triage_not_actionable} of ${h.triage_items} scanner claims dismissed with code evidence</small></div>
    <div class="ba time"><div class="bl">⏱️ Time · machine time per app</div><div class="bv"><span class="after good">≈${Math.round(h.mins)} min</span></div><small>vs ≈149 h of reading (assumed) · second run: ${h2 ? h2.found : '—'}/21 again</small></div>
  </div>
  <div class="bigline center">The harness is the analyst’s workflow, <b>written down</b>. <span class="muted">SnackOverflow · Opus 5.5</span></div>
  ${bridge('Is it just the powerful model? Let’s test 15.')}`;
}

/* ============ 7 · Is it the model? ============ */
const TIERS = [[21, 21, 't1', 'Top tier'], [15, 20, 't2', 'Close behind'], [9, 14, 't3', 'Mid'], [0, 8, 't4', 'Struggled']];
function p7() {
  const R = BR.filter(r => r.mode === 'harness' && r.repeat === 1 && (r.round === MAIN || r.round === FIX));
  const blockedRun = r => refusedIn(r).length > 0;
  const ms = Object.keys(B.names || {}).map(m => {
    const rs = R.filter(r => r.model === m), f = rs.map(r => r.found);
    if (!f.length) return null;
    const cost = rs.reduce((a, r) => a + (r.cost_usd || 0), 0) / 2;              // avg list price of one full 2-app run
    return { m, name: B.names[m], vendor: (B.vendors || {})[m], open: rs.some(r => r.open_weight), avg: f.reduce((a, b) => a + b, 0) / f.length,
      lo: Math.min(...f), hi: Math.max(...f), cost, blocked: rs.filter(blockedRun).length, broke: rs.some(r => r.triage_needs_review > 60 && r.found < 4), n: f.length };
  }).filter(Boolean).sort((a, b) => b.avg - a.avg || a.cost - b.cost);
  const tier = a => a >= 19 ? ['t1', 'Top tier'] : a >= 15 ? ['t2', 'Close behind'] : a >= 10 ? ['t3', 'Mid'] : ['t4', 'Struggled'];
  const X = v => (100 * v) / 21;
  let last = '';
  const rowsHtml = ms.map(x => {
    const t = tier(x.avg), sep = t[1] !== last ? `<div class="tierlab ${t[0]}">${t[1]}</div>` : ''; last = t[1];
    return sep + `<div class="mrow ${t[0]}"><div class="mn"><b>${esc(x.name)}</b> <span class="tag ${x.open ? 'open' : 'closed'}">${x.open ? 'open' : 'closed'}</span>${x.blocked ? ' <span class="blk" title="vendor safety filter blocked part of the work">🛑</span>' : ''}${x.broke ? ' <span class="blk" title="tool loop failed">⚠</span>' : ''}</div>
      <div class="mb"><span class="rng" style="left:${X(x.lo)}%;width:${X(x.hi - x.lo)}%"></span><span class="avg" style="width:${X(x.avg)}%"></span></div>
      <div class="mv"><b>${x.avg.toFixed(1)}</b><small>${x.lo}–${x.hi}</small></div><div class="mc">${usdFmt(x.cost)}</div></div>`;
  }).join('');
  const hk = ms.find(x => x.m === 'haiku-5-5'), op = ms.find(x => x.m === 'opus-5-5');
  const pct = hk && op ? Math.round((100 * hk.cost) / op.cost) : null;
  const jev = B.jev || [], jp = jev.find(j => j.model.includes('typesafe') && j.kind === 'planted') || {}, jo = jev.find(j => j.model.includes('typesafe') && j.kind === 'other') || {};
  return `${head('7 · Is it the model?', `The cheapest Claude tied the top. <em>At ${pct ?? '—'}% of Opus’s price.</em>`)}
  <div class="mhead"><span>Model · same harness</span><span>Planted bugs found per app · avg of 4 runs <i class="key avg"></i>avg <i class="key rng"></i>range</span><span>avg · range</span><span>$ / full run</span></div>
  <div class="mlist">${rowsHtml}</div>
  <div class="scope">4 runs per model: 2 apps × 2 harness versions. 🛑 a vendor safety filter blocked part of the work (Opus and Gemini 4 Argon on RAGnarok, GPT-6.2 Sol everywhere). $ = published list price per token × logged tokens (within 3% of the actual bill for 10 of 15 models; the rest also paid for unlogged retries and blocked calls).</div>
  <div class="jevcard"><div class="jtag">🧪 Fun experiment · #16</div>
    <div class="jgrid"><div class="jwhat"><b>Jev</b>, a “System One” decision model: no text, no tools, just a probability.
      We gave it every scanner claim with <b>±15 lines of code</b> and asked one question: <i>“is this finding real?”</i></div>
      <div class="jnum"><b>${val(jp.avg_latency_s)}s</b><span>per decision</span></div>
      <div class="jnum"><b>${val(jp.avg_p)}</b><span>P(real) on planted bugs</span></div>
      <div class="jnum dim"><b>${val(jo.avg_p)}</b><span>P(real) on everything else</span></div>
      <div class="jverdict">⚡ Blazing fast and cheap<br>≈ Barely tells real from noise<br>➜ A pre-filter, not a judge</div></div></div>
  ${bridge('So which model should you pick?')}`;
}

/* ============ 8 · Production ============ */
function mdash() {
  return `<div class="mdash"><div class="mtitle">What a mature harness looks like · <b>Microsoft MDASH</b>, a multi-model agentic scanning harness
      <a href="https://www.microsoft.com/en-us/security/blog/2026/05/12/defense-at-ai-speed-microsofts-new-multi-model-agentic-security-system-tops-leading-industry-benchmark/" target="_blank" rel="noopener">↗</a></div>
    <div class="morch">🧠 A <b>frontier model</b> orchestrates <b>100+ specialized agents</b></div>
    <div class="mstages">${[['📚', 'Prepare', 'index code · threat model'], ['🔎', 'Scan', 'auditor agents'], ['⚔️', 'Validate', 'distilled “debaters”'],
      ['🧬', 'Dedupe', 'merge equivalents'], ['💥', 'Prove', 'build a trigger']].map(([i, n, d], k) => `<div class="ms"><span>${i}</span><b>${n}</b><small>${d}</small></div>${k < 4 ? '<div class="marrow">➜</div>' : ''}`).join('')}</div>
    <div class="mside"><span>🧑‍⚖️ a second, independent frontier model as counterpoint</span><span>⚡ “disagreement between models is itself a signal”</span><span>🙈 even MDASH: 10 of 52 misses were false suppressions</span></div></div>`;
}
function p8() {
  const supp = B.suppressions || [], byTitle = {};
  supp.filter(x => x.run_id.includes('-' + MAIN)).forEach(x => { (byTitle[x.title] = byTitle[x.title] || { ...x, runs: [] }).runs.push(x.run_id); });
  const rank = s => ({ critical: 0, high: 1, medium: 2, low: 3 }[s] ?? 4);
  const ex = Object.values(byTitle).sort((a, b) => rank(a.gt_severity) - rank(b.gt_severity) || b.runs.length - a.runs.length)[0];
  const r2 = BR.filter(r => r.round === MAIN && r.mode === 'harness' && r.repeat === 1), r3 = BR.filter(r => r.round === FIX && r.mode === 'harness');
  const sum = (rs, k) => rs.reduce((a, r) => a + (r[k] || 0), 0);
  const fixedCount = ex ? supp.filter(x => x.title === ex.title && x.run_id.includes('-' + FIX)).length : 0;
  const s1 = spagStats('snackoverflow', (run('snackoverflow', 'opus-5-5', 'spaghetti', 1) || {}).run_id), s2 = spagStats('snackoverflow', (run('snackoverflow', 'opus-5-5', 'spaghetti', 2) || {}).run_id);
  const h1 = run('snackoverflow', 'opus-5-5'), h2 = run('snackoverflow', 'opus-5-5', 'harness', 2);
  return `${head('9 · Ready for production?', 'Yes, once you solve <em>two problems</em>.')}
  <div class="probs">
    <div class="prob"><div class="ptag">Problem 1</div><h2>🙈 False suppression</h2>
      ${ex ? `<div class="ticket mini"><div class="thead"><span class="tid">${esc(ex.vuln_id)}</span>${badge(ex.gt_severity)}<span class="tstat">AUTO-CLOSED</span></div>
        <div class="ttitle">${esc(ex.title)}</div><div class="trow"><span>🤖 AI</span><b class="badtext">“not actionable” · ${ex.runs.length} of 15 models</b></div>
        <div class="trow"><span>🎯 Truth</span><b class="badtext">REAL ${esc(String(ex.gt_severity).toUpperCase())} BUG</b></div><div class="stampbig">FALSE SUPPRESSION</div></div>` : ''}
      ${r3.length ? `<div class="fixrow">🔧 One rule fix in the harness: <b>${sum(r2, 'false_suppressions')} → ${sum(r3, 'false_suppressions')}</b> false suppressions${ex ? `, ${esc(ex.vuln_id)} dismissed by <b>${fixedCount}</b>` : ''}<br><span class="muted">cost: “needs review” ${sum(r2, 'triage_needs_review')} → ${sum(r3, 'triage_needs_review')}</span></div>` : ''}
      <div class="howfix">Mature the harness · review closely early on · measure against ground truth</div></div>
    <div class="prob"><div class="ptag">Problem 2</div><h2>🎲 Reproducibility</h2>
      <div class="rep"><div class="repline good"><span>${logo('trivy', 'Trivy')} Trivy · same version + DB</span><b>same output, by design</b></div>
        <div class="repline bad"><span>🍝 AI · one prompt, twice</span><b>${val(s1.tp)} ≠ ${val(s2.tp)}</b></div>
        <div class="repline good"><span>🧰 Opus + harness, 2 runs</span><b>${h1 ? h1.found : '—'}/21 both times</b></div>
        <div class="repline bad"><span>🧰 Kimi K3.1 · RAGnarok · next harness run</span><b>21 → 11</b></div></div>
      <div class="howfix">Top models stayed within ±1. Others swung ±10. Measure variance before you trust a model.</div></div>
  </div>
  ${mdash()}
  ${principle(3)}
  ${bridge('So what did we learn, and what did it cost?')}`;
}

/* ============ 9 · Who is the best model? ============ */
const BOARDS = [
  { k: 'cybench', org: 'Stanford', name: 'Cybench', q: 'Can it hack?', url: 'https://cybench.github.io/', note: 'professional CTF challenges' },
  { k: 'cybergym', org: 'UC Berkeley', name: 'CyberGym', q: 'Can it reproduce real vulns?', url: 'https://www.cybergym.io/cybergym/', note: '1,507 real vulnerabilities · MDASH reports 88.45% here' },
  { k: 'vals', org: 'Vals AI', name: 'CyberBench', q: 'Can it find &amp; fix?', url: 'https://www.vals.ai/benchmarks/cyber', note: 'find + patch memory bugs, with cost per test' },
];
function p9() {
  const shot = b => `<a class="shot" href="${b.url}" target="_blank" rel="noopener">
    ${SH[b.k] ? `<img src="${SH[b.k]}" alt="${b.name} leaderboard screenshot">` : '<div class="noshot">screenshot missing</div>'}
    <div class="meta"><div class="sq">${b.q}</div><div class="sm"><b>${b.name}</b><span>${b.org}</span></div><small>${b.note}</small></div></a>`;
  return `${head('8 · The question everyone asks', 'Who’s the <em>best model</em>? 🏆')}
  <div class="answer top"><div class="a1">The best model is the one that <b>fits your needs</b> and <b>your compliance</b>.</div>
    <div class="a2">Open weights are close: <b>DeepSeek V4.1 Flash</b> is #3 overall on page 7 at a fraction of frontier prices. Pick a model that is <b>capable, stable and allowed to do the work</b>.</div>
    <div class="a3">You don’t need the best model. <b>You need the best harness.</b></div></div>
  <div class="shots three">${BOARDS.map(shot).join('')}</div>
  <div class="shotdate">Three leaderboards, three different questions. Screenshots taken 2026-11-25. CyberGym’s own caveat: <i>“agent runs are stochastic… modest score differences may not reflect meaningful capability gaps.”</i></div>
  ${bridge('Pick a model, keep the harness. Can we ship it?')}`;
}

/* ============ 10 · Wrap-up ============ */
const SESSION_USD = 60;   // AI pair-programming session that built the lab (presenter's figure)
function p10() {
  const sp = B.spend || {}, models = sp.models || 0, compute = sp.compute || 0, total = models + compute + SESSION_USD;
  const fun = (icon, unit, price, label) => `<div class="fun"><span class="fi">${icon}</span><b>${Math.round(total / price)}</b><small>${label} (@ $${price})</small></div>`;
  const analystRate = 75, analystH = Math.round((scanRows().length * 5) / 60);
  const takeaways = [
    ['⚙️', PRINCIPLES[1][1], 'TruffleHog doesn’t need a chatbot. Let rules be rules.'],
    ['🧰', PRINCIPLES[2][1], 'Same Opus: spaghetti 🍝 → 21/21 with a recipe 📖.'],
    ['🧑‍⚖️', PRINCIPLES[3][1], '5 models dismissed a critical secret. A reviewer would have caught it.'],
  ];
  return `${head('10 · Wrap-up', 'Three rules and <em>one receipt</em>. 🧾')}
  <div class="tk3">${takeaways.map(([i, t, d], k) => `<div class="tkc"><div class="tkn">${k + 1}</div><div class="tki">${i}</div><b>${t}</b><span>${d}</span></div>`).join('')}</div>
  <div class="receipt-row">
    <div class="receipt"><div class="rh">🧾 SEC545 AI SECURITY LAB · RECEIPT</div>
      <div class="rl"><span>15 models · 3 harness rounds + spaghetti · 2 apps · every retry</span><b>$${models.toFixed(2)}</b></div>
      <div class="rl"><span>Compute (jobs, SQL, storage)</span><b>$${compute.toFixed(2)}</b></div>
      <div class="rl"><span>AI pair-programmer that built all this</span><b>≈ $${SESSION_USD.toFixed(2)}</b></div>
      <div class="rl tot"><span>TOTAL</span><b>≈ $${Math.round(total)}</b></div>
      <div class="rfoot">Cheapest full run: Haiku, <b>$0.29</b>. Less than a chocolate bar. 🍫</div></div>
    <div class="funs">${fun('🍕', 'pizzas', 18, 'pizzas')}${fun('🍫', 'bars', 2, 'chocolate bars')}${fun('☕', 'lattes', 5, 'lattes')}
      <div class="fun vs"><span class="fi">🕵️</span><div><b>≈ ${Math.round(total / analystRate)} h</b><small>of one analyst (@ $${analystRate}/h, assumed). Reading the alerts by hand: ≈ ${analystH} h.</small></div></div></div>
  </div>
  <div class="finale"><div class="fq">Let rules do what rules can do, let AI do the reading, and let a human make the call.</div></div>`;
}

/* ============ Deep dive (detail views; safe data only: no code, no responses, no secret values) ============ */
const DD = { q: '', app: 'all', tool: 'all', sev: 'all', page: 0, round: MAIN, skill: 'triage', runRound: 'all' };
const ddSel = (id, opts, cur) => `<select data-dd="${id}">${opts.map(([v, t]) => `<option value="${v}" ${v === cur ? 'selected' : ''}>${t}</option>`).join('')}</select>`;
function ddFindingsRows() {
  const q = DD.q.toLowerCase();
  return scanRows().filter(f => (DD.app === 'all' || f.app === DD.app) && (DD.tool === 'all' || toolOf(f) === DD.tool) && (DD.sev === 'all' || sev(f.severity) === DD.sev)
    && (!q || [f.rule_id, f.title, f.file, f.package && (f.package.name || f.package)].join(' ').toLowerCase().includes(q)));
}
function ddFindingsTable() {
  const R = ddFindingsRows(), per = 25, pages = Math.max(1, Math.ceil(R.length / per)); DD.page = Math.min(DD.page, pages - 1);
  const where = f => f.package ? (typeof f.package === 'object' ? `${f.package.name || ''} ${f.package.installed || ''}` : f.package) : `${f.file || ''}${f.line ? ':' + f.line : ''}`;
  return `<div class="ddcount"><b>${num(R.length)}</b> of ${num(scanRows().length)} findings</div>
    <div class="tablebox"><table class="mtable ddt"><thead><tr><th>Severity</th><th>Rule / CVE</th><th>Title</th><th>Where</th><th>Tool</th><th>App</th></tr></thead><tbody>
    ${R.slice(DD.page * per, DD.page * per + per).map(f => `<tr><td>${badge(f.severity)}</td><td><code>${esc(f.rule_id)}</code></td><td>${esc((f.title || '').slice(0, 90))}</td><td><code>${esc(where(f))}</code></td><td>${esc(f.tool)}</td><td>${f.app === 'snackoverflow' ? 'SnackOverflow' : 'RAGnarok'}</td></tr>`).join('')}
    </tbody></table></div>
    <div class="ddpager"><button data-ddpage="-1" ${DD.page ? '' : 'disabled'}>‹ Prev</button><span>page ${DD.page + 1} / ${pages}</span><button data-ddpage="1" ${DD.page < pages - 1 ? '' : 'disabled'}>Next ›</button></div>`;
}
function d0() {
  const bugs = B.bugs || [];
  const APPS = [
    { k: 'snackoverflow', icon: '🍔', name: 'SnackOverflow', stack: 'Python · FastAPI · Postgres', what: 'Food delivery for developers. Customers order, restaurant owners manage menus, drivers deliver, admins see sales.',
      roles: ['customer', 'restaurant owner', 'driver', 'admin'], decoys: 7 },
    { k: 'ragnarok', icon: '🤖', name: 'RAGnarok', stack: 'Node · TypeScript · Express · simulated LLM', what: 'A GenAI knowledge assistant: upload documents, ask questions over them (RAG), and let an agent use tools. Two tenants share one deployment.',
      roles: ['workspace user', 'two tenants'], decoys: 6 },
  ];
  const cls = [['scanner', 'Scanner-detectable', 'a classic scanner rule can see it'], ['hybrid', 'Hybrid', 'scanner sees a symptom, code reading proves it'], ['ai_only', 'AI-only', 'logic, authorization, LLM abuse: no rule exists']];
  const card = a => { const bs = bugs.filter(b => b.app === a.k);
    return `<div class="appcard"><div class="aph"><span class="api">${a.icon}</span><div><b>${a.name}</b><small>${a.stack}</small></div></div>
      <p class="apw">${a.what}</p><div class="aproles">${a.roles.map(r => `<span>${r}</span>`).join('')}<span class="dec">🪤 ${a.decoys} safe decoys</span></div>
      <div class="apcls">${cls.map(([c, n, d]) => { const xs = bs.filter(b => b.class === c);
        return `<div class="apc ${c}"><div class="apch"><b>${xs.length}</b> ${n}<small>${d}</small></div><ul>${xs.map(b => `<li>${badge(b.severity)} ${esc(b.title)}</li>`).join('')}</ul></div>`; }).join('')}</div></div>`; };
  return `${head('Deep dive · Meet the apps', 'Two apps. <em>42 planted bugs.</em> 13 decoys.')}
  <div class="bigline">Deliberately vulnerable, built for this lab; every secret in them is fake. Source and answer key stay private so the lab stays fresh for students.</div>
  <div class="appgrid">${APPS.map(card).join('')}</div>`;
}
function d1() {
  return `${head('Deep dive · Findings explorer', 'Every scanner finding, <em>searchable</em>.')}
  <div class="ddbar"><input data-dd="q" placeholder="Search rule, CVE, package, file…" value="${esc(DD.q)}">
    ${ddSel('app', [['all', 'Both apps'], ['snackoverflow', 'SnackOverflow'], ['ragnarok', 'RAGnarok']], DD.app)}
    ${ddSel('tool', [['all', 'All scanners'], ['trivy', 'Trivy'], ['semgrep', 'Semgrep'], ['trufflehog', 'TruffleHog']], DD.tool)}
    ${ddSel('sev', [['all', 'All severities'], ...levels.map(l => [l, l])], DD.sev)}</div>
  <div id="ddtable">${ddFindingsTable()}</div>`;
}
function d2() {
  const bugs = B.bugs || [], models = Object.keys(B.names || {});
  const rid = m => DD.round === 'spag' ? null : `bench-${m}-${DD.round}`;
  const cols = DD.round === 'spag' ? [['spaghetti', 'Opus 5.5 · no harness']] : models.map(m => [m, B.names[m]]);
  const cell = (b, m) => { const st = DD.round === 'spag' ? b.runs['spaghetti-opus-5-5-02-r1'] : b.runs[rid(m)];
    return `<td class="bm ${st || 'na'}" title="${esc(b.title)} · ${esc(m)}: ${st || 'no run'}">${st === 'found' ? '●' : st === 'dismissed' ? '✕' : st === 'missed' ? '○' : '·'}</td>`; };
  const rowsHtml = ['snackoverflow', 'ragnarok'].map(app => `<tr class="bmapp"><td colspan="${cols.length + 2}">${app === 'snackoverflow' ? '🍔 SnackOverflow' : '🤖 RAGnarok'}</td></tr>` +
    bugs.filter(b => b.app === app).map(b => { const hits = cols.filter(([m]) => (DD.round === 'spag' ? b.runs['spaghetti-opus-5-5-02-r1'] : b.runs[rid(m)]) === 'found').length;
      return `<tr><td class="bt">${badge(b.severity)} <b>${esc(b.title)}</b> <span class="bc ${esc(b.class)}">${b.class === 'ai_only' ? 'AI-only' : b.class === 'hybrid' ? 'hybrid' : 'scanner'}</span></td>${cols.map(([m]) => cell(b, m)).join('')}<td class="bsum">${hits}/${cols.length}</td></tr>`; }).join('')).join('');
  return `${head('Deep dive · Bug matrix', 'Which model found <em>which bug</em>?')}
  <div class="ddbar">${ddSel('round', [['02', 'Harness v1 (round 02)'], ['03', 'Harness v2 · rule fix (round 03)'], ['spag', 'Spaghetti (no harness)']], DD.round)}
    <span class="legend"><span><b class="lg f">●</b> found</span><span><b class="lg d">✕</b> dismissed (false suppression)</span><span><b class="lg m">○</b> missed</span><span>class: scanner-detectable · hybrid · AI-only</span></span></div>
  <div class="tablebox bmwrap"><table class="bmt"><thead><tr><th>Planted bug</th>${cols.map(([, n]) => `<th class="vh"><span>${esc(n.replace('Claude ', ''))}</span></th>`).join('')}<th>found</th></tr></thead><tbody>${rowsHtml}</tbody></table></div>`;
}
function d3() {
  const R = BR.filter(r => DD.runRound === 'all' || r.round === DD.runRound || (DD.runRound === 'spag' && r.mode === 'spaghetti'))
    .filter(r => !(DD.runRound === 'spag') || r.mode === 'spaghetti')
    .slice().sort((a, b) => a.app.localeCompare(b.app) || (b.found ?? -1) - (a.found ?? -1));
  const label = r => r.mode === 'spaghetti' ? `spaghetti #${r.repeat}` : r.round === '01' ? 'harness v0 (round 01)' : `harness ${r.round === '02' ? 'v1' : 'v2'}${r.repeat > 1 ? ' · repeat' : ''}`;
  return `${head('Deep dive · All runs', 'Every run, <em>every number</em>.')}
  <div class="ddbar">${ddSel('runRound', [['all', 'All runs'], ['02', 'Harness v1 (round 02)'], ['03', 'Harness v2 (round 03)'], ['01', 'Round 01 (before fixes)'], ['spag', 'Spaghetti']], DD.runRound)}
    <span class="muted">${R.length} runs · round 01 is kept as the “before the harness fixes” evidence</span></div>
  <div class="tablebox"><table class="mtable ddt"><thead><tr><th>Model</th><th>App</th><th>Run</th><th>Found /21</th><th>Not in key</th><th>False supp.</th><th>Needs review</th><th>Analyst queue</th><th>Tokens</th><th>$ list</th><th>Min</th><th></th></tr></thead><tbody>
  ${R.map(r => `<tr><td><b>${esc(r.name || r.model)}</b></td><td>${r.app === 'snackoverflow' ? 'SnackOverflow' : 'RAGnarok'}</td><td>${label(r)}</td><td class="n"><b>${val(r.found)}</b></td><td class="n">${val(r.ai_unplanted)}</td>
    <td class="n">${val(r.false_suppressions)}</td><td class="n">${val(r.triage_needs_review)}</td><td class="n">${val(r.review_queue)}</td><td class="n">${fmtTok((r.tin || 0) + (r.tout || 0))}</td>
    <td class="n">${r.cost_usd ? usdFmt(r.cost_usd) : '—'}</td><td class="n">${val(r.mins)}</td><td>${refusedIn(r).length ? chip('bad', '🛑', refusedIn(r).join(', ')) : ''}</td></tr>`).join('')}</tbody></table></div>`;
}
function d4() {
  const skills = (typeof DATA === 'object' && DATA.skills) || {}, names = Object.keys(skills).sort();
  const cur = skills[DD.skill] ? DD.skill : names[0];
  return `${head('Deep dive · Harness skills', 'What each AI step is <em>actually told</em>.')}
  <div class="ddbar">${names.map(n => `<button class="skbtn ${n === cur ? 'on' : ''}" data-ddskill="${n}">${n}</button>`).join('')}
    <a class="cxlink" href="https://github.com/openai/codex-security/tree/main/plugins/codex-security/skills" target="_blank" rel="noopener">adapted from OpenAI Codex Security skills ↗</a></div>
  <pre class="skillfull">${esc(skills[cur] || '')}</pre>`;
}
document.addEventListener('input', e => {
  const k = e.target.dataset && e.target.dataset.dd;
  if (k === 'q') { DD.q = e.target.value; DD.page = 0; const t = document.getElementById('ddtable'); if (t) t.innerHTML = ddFindingsTable(); }
});
document.addEventListener('change', e => {
  const k = e.target.dataset && e.target.dataset.dd;
  if (k && k !== 'q') { DD[k] = e.target.value; DD.page = 0; render(); }
});
document.addEventListener('click', e => {
  const pg = e.target.closest && e.target.closest('[data-ddpage]');
  if (pg) { DD.page += +pg.dataset.ddpage; const t = document.getElementById('ddtable'); if (t) t.innerHTML = ddFindingsTable(); }
  const sk = e.target.closest && e.target.closest('[data-ddskill]');
  if (sk) { DD.skill = sk.dataset.ddskill; render(); }
});

const STORY = {
  chapters: ['Pipeline', 'Findings', 'Where AI fits', 'Shiny model', 'Harness', 'With harness', '15 models', 'Best model?', 'Production', 'Wrap-up'],
  hashes: ['p1', 'p2', 'p3', 'p4', 'p5', 'p6', 'p7', 'p8', 'p9', 'p10'],
  views: [p1, p2, p3, p4, p5, p6, p7, p9, p8, p10],
  deep: { chapters: ['Meet the apps', 'Findings explorer', 'Bug matrix', 'All runs', 'Harness skills'], hashes: ['apps', 'findings', 'bugs', 'runs', 'skills'], views: [d0, d1, d2, d3, d4] },
  notes: [
    "This is how most of us secure an app today. Two deliberately vulnerable apps: SnackOverflow, and RAGnarok, a GenAI app. Trivy checks dependencies, Semgrep checks code patterns, TruffleHog checks for leaked secrets. Everything lands in one findings list, an analyst works through it, and we fix. We planted 42 real bugs and 13 safe decoys, so we can grade everything against an answer key.",
    "Here is everything the scanners produced, by severity. Three problems. Noise: 1,791 alerts that collapse to 165 distinct claims; one package alone produced 384. Accuracy: they found 18 of our 42 planted bugs, and flagged 5 of 13 safe decoys. Time: at an assumed five minutes per alert, about 149 analyst hours. We will answer all three.",
    "AI helps here, not there. Triage answers noise: is this finding real, and reachable? Discovery answers accuracy: what did rule-based scanners miss? They caught 18 of 42; 24 slipped past in authorization, business logic and LLM abuse. TruffleHog stays rules-only: 800-plus secret types, signatures, live checks for many. Principle 1: use AI where it matters.",
    "So I grab the best model, Opus 5.5, and put all the SnackOverflow code and its 490 scanner findings into one prompt. It calls 168 real; run it again and it says 158. It labels the same rule both real and false, gives identical findings different verdicts, invents five bugs, flags a safe decoy, and shows no evidence. On RAGnarok it was blocked. You don't fix spaghetti with a better fork. You need a recipe, and in AppSec the recipe is called a harness.",
    "What we just saw is experimentation, not application security. The fix is a harness: a written contract for what an analyst does, borrowed from OpenAI Codex Security skills. Rules run where rules work; AI does only the judgment. It decides severity, true versus false positive, what scanners missed, and when a human re-scores. The critical-to-low example is illustrative; production adds a threat-model step. Principle 2.",
    "Same Opus, same code, same scanner output, now inside the harness. Accuracy: 21 of 21 planted bugs, zero bugs outside the key, no decoys flagged. Noise: the analyst is left with 58 items instead of 84, with 37 claims dismissed with code evidence. Time: about ten minutes of machine time per app, and the second run gave 21 of 21 again.",
    "You might think: a harness plus the most powerful model wins. So I ran 15 models through the same harness, four runs each. Grok and the cheapest Claude, Haiku, top the list, both stable within one bug. Opus was blocked by its own vendor filter on RAGnarok, so it averages lower. The best open-weight model, DeepSeek, is third. Haiku cost about 3 percent of Opus per full run. And a fun one: Jev, a yes-or-no decision model. We gave it every scanner claim with fifteen lines of code around it and asked: is this real? A fifth of a second per answer, but it barely separates real bugs from noise. A pre-filter, not a judge.",
    "Everyone asks which model is best. My answer first: the one that fits your needs and your compliance, and that is capable, stable and allowed to do the work. Open weights are close: DeepSeek is third on our list. You do not need the best model; you need the best harness. Here are three leaderboards asking three different questions, and CyberGym itself warns small score gaps may not mean much.",
    "Can we take this to production? Yes, once we solve two problems. One: false suppression. Five of 15 models dismissed a critical hardcoded JWT secret. One rule fix cut false suppressions from 20 to 7, but needs review rose from 571 to 841: more analyst time. Two: reproducibility. Trivy is repeatable by design. Opus with the harness gave 21 twice, but Kimi swung from 21 to 11. Microsoft's MDASH shows what a mature harness looks like, and it still reports false suppression. Principle 3: AI accelerates, humans stay in the loop. A human makes the final call.",
    "Three rules to take home: use AI where it matters, invest in the harness, AI accelerates, humans stay in the loop. And the receipt: every model run, retry and test, plus compute, plus the AI pair-programmer that built this, came to about two hundred thirty-five dollars. That is about thirteen pizzas, or roughly three hours of one analyst, versus about 149 hours to read the alerts by hand."
  ],
};

/* Fit each story page to the screen: no scrolling while presenting. */
function fitStage() {
  const st = document.getElementById('stage');
  if (!st) return;
  if (document.body.dataset.mode !== 'story' || document.body.dataset.deep) { st.style.zoom = ''; return; }
  st.style.zoom = 1;
  const header = document.querySelector('header');
  const avail = window.innerHeight - (header ? header.offsetHeight : 0) - 8;
  const need = st.scrollHeight;
  st.style.zoom = need > avail ? Math.max(0.5, avail / need).toFixed(3) : 1;
}
window.fitStage = fitStage;
window.addEventListener('resize', () => fitStage());
document.addEventListener('fullscreenchange', () => setTimeout(fitStage, 150));

(function () {
  const tip = document.createElement('div');
  tip.className = 'tip';
  document.addEventListener('DOMContentLoaded', () => document.body.appendChild(tip));
  document.addEventListener('mouseover', e => {
    const g = e.target.closest && e.target.closest('[data-tip]');
    if (!g) { tip.style.display = 'none'; return; }
    tip.innerHTML = g.dataset.tip; tip.style.display = 'block';
  });
  document.addEventListener('mousemove', e => { tip.style.left = e.clientX + 14 + 'px'; tip.style.top = e.clientY + 14 + 'px'; });
})();
