/*
 * Moteur de la démo web : portage fidèle de yara_rag (tokenisation, BM25 Okapi de
 * rank_bm25, assemblage extractif). Vérifié contre la version Python par
 * tests/test_web_engine.py (mêmes règles retrouvées, même règle produite).
 */
(function (root) {
  "use strict";

  const STOPWORDS = new Set(`a an the and or of to in on for with by from that this these those is are be been
using use uses used which who what when where how detect detects detection identify find rule rules
yara file files le la les un une des du de et ou pour avec par qui que dans sur est`.split(/\s+/));
  const RESERVED = new Set(("all and any ascii at base64 base64wide condition contains endswith entrypoint false " +
    "filesize for fullword global import icontains iendswith iequals in include int16 int16be int32 int32be int8 " +
    "int8be istartswith matches meta nocase none not of or private rule startswith strings them true uint16 " +
    "uint16be uint32 uint32be uint8 uint8be wide xor defined").split(" "));
  const CAMEL = /(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])/;
  const MAX_STRINGS = 8;

  function tokenize(text) {
    const out = [];
    const toks = String(text).match(/[A-Za-z0-9_.\\\/-]+/g) || [];
    for (const tok of toks) {
      const parts = tok.split(/[_.\\\/-]+/).filter(Boolean);
      const pieces = new Set([tok.toLowerCase()]);
      for (const p of parts) {
        pieces.add(p.toLowerCase());
        for (const x of p.split(CAMEL)) if (x) pieces.add(x.toLowerCase());
      }
      for (const p of [...pieces].sort()) if (p.length > 1 && !STOPWORDS.has(p)) out.push(p);
    }
    return out;
  }

  /* BM25 Okapi, mêmes formules et paramètres que rank_bm25 (k1 = 1.5, b = 0.75, epsilon = 0.25) */
  class BM25 {
    constructor(docs, k1 = 1.5, b = 0.75, epsilon = 0.25) {
      this.k1 = k1; this.b = b;
      this.N = docs.length;
      this.len = new Float64Array(this.N);
      this.post = new Map();                       // mot -> [[doc, tf], ...]
      let total = 0;
      docs.forEach((toks, i) => {
        this.len[i] = toks.length; total += toks.length;
        const tf = new Map();
        for (const t of toks) tf.set(t, (tf.get(t) || 0) + 1);
        for (const [t, f] of tf) {
          if (!this.post.has(t)) this.post.set(t, []);
          this.post.get(t).push([i, f]);
        }
      });
      this.avgdl = total / Math.max(1, this.N);
      this.idf = new Map();
      let sum = 0; const neg = [];
      for (const [t, plist] of this.post) {
        const n = plist.length;
        const v = Math.log(this.N - n + 0.5) - Math.log(n + 0.5);
        this.idf.set(t, v); sum += v;
        if (v < 0) neg.push(t);
      }
      const eps = epsilon * sum / Math.max(1, this.idf.size);
      for (const t of neg) this.idf.set(t, eps);
    }
    scores(query) {
      const s = new Float64Array(this.N);
      for (const q of query) {
        const plist = this.post.get(q);
        if (!plist) continue;
        const idf = this.idf.get(q);
        for (const [i, f] of plist) {
          s[i] += idf * ((f * (this.k1 + 1)) / (f + this.k1 * (1 - this.b + this.b * this.len[i] / this.avgdl)));
        }
      }
      return s;
    }
    top(query, k) {
      const s = this.scores(query);
      const idx = [];
      for (let i = 0; i < s.length; i++) if (s[i] > 0) idx.push(i);
      idx.sort((a, b) => s[b] - s[a] || a - b);
      return idx.slice(0, k).map(i => ({ index: i, score: s[i] }));
    }
  }

  function searchText(r) {
    const embed = `${r.name.replaceAll("_", " ")} ${r.type} ${r.description}`.trim();
    return `${embed} ${embed} ${r.tags} ${r.literals}`;
  }

  function sanitizeName(name, def = "Generated_Rule") {
    name = (name || "").replace(/[^A-Za-z0-9_]/g, "_").replace(/^_+|_+$/g, "").replace(/_+/g, "_");
    if (!name) name = def;
    if (/^[0-9]/.test(name)) name = "Rule_" + name;
    if (RESERVED.has(name.toLowerCase())) name = "Rule_" + name;
    return name.slice(0, 128);
  }

  function ruleNameFromQuery(q) {
    const words = (q.match(/[A-Za-z][A-Za-z0-9]+/g) || [])
      .filter(w => w.length > 2 && !STOPWORDS.has(w.toLowerCase())).slice(0, 4)
      .map(w => w[0].toUpperCase() + w.slice(1));
    return sanitizeName(words.length ? "Gen_" + words.join("_") : "Generated_Rule");
  }

  function metaEscape(v) {
    return String(v).replace(/\s+/g, " ").trim().replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  }

  function assemble(query, docs, today) {
    const terms = new Set(tokenize(query));
    const pool = [], seen = new Set();
    docs.forEach((d, rank) => {
      for (const def of d.strings) {
        const lit = def.match(/^"(?:\\.|[^"\\])*"/);
        const key = lit ? lit[0] : def.startsWith("/") ? def.split(" ")[0] : def;
        if (seen.has(key)) continue;
        seen.add(key);
        let score = 0;
        for (const t of new Set(tokenize(def))) if (terms.has(t)) score++;
        pool.push({ score, rank, def, from: d.name });
      }
    });
    pool.sort((a, b) => b.score - a.score || a.rank - b.rank);
    const chosen = pool.slice(0, MAX_STRINGS);
    const n = chosen.length;
    const need = n <= 2 ? 1 : n <= 5 ? 2 : 3;
    const mz = docs.filter(d => d.mz).length > docs.length / 2;
    let cond = n ? `${need} of them` : "false";
    if (mz && n) cond = `uint16(0) == 0x5A4D and ${cond}`;
    const ref = docs.length ? docs[0].url : "";
    const lines = [`rule ${ruleNameFromQuery(query)} {`, "    meta:",
      `        description = "${metaEscape(query.slice(0, 200))}"`,
      '        author = "yara-rag (assemblage extractif)"',
      `        date = "${today || new Date().toISOString().slice(0, 10)}"`];
    if (ref) lines.push(`        reference = "${metaEscape(ref)}"`);
    if (n) { lines.push("    strings:"); chosen.forEach((c, i) => lines.push(`        $s${i + 1} = ${c.def}`)); }
    lines.push("    condition:", `        ${cond}`, "}");
    return { rule: lines.join("\n"), sources: chosen.map(c => c.from) };
  }

  class Engine {
    constructor(payload) {
      const F = payload.fields;
      this.rules = payload.rules.map(row => Object.fromEntries(F.map((f, i) => [f, row[i]])));
      this.bm25 = new BM25(this.rules.map(r => tokenize(searchText(r))));
    }
    search(query, k = 5, type = "") {
      const hits = this.bm25.top(tokenize(query), type ? 400 : k);
      return hits.filter(h => !type || this.rules[h.index].type === type).slice(0, k)
        .map(h => Object.assign({ score: h.score, index: h.index }, this.rules[h.index]));
    }
    generate(query, k = 5, type = "", today) {
      const docs = this.search(query, k, type);
      return Object.assign({ docs }, assemble(query, docs, today));
    }
  }

  const api = { tokenize, BM25, Engine, assemble, ruleNameFromQuery };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.YaraEngine = api;
})(typeof self !== "undefined" ? self : this);
