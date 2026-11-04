/* 晨读 · 检阅站外壳。无任何外部依赖。
 * enc 模式：PBKDF2-SHA256 → AES-256-GCM（WebCrypto），数据文件为 i/*.bin、d/*.bin。
 *   派生出的密钥以「不可导出」的 CryptoKey 存进 IndexedDB——不存密码本身。
 * plain 模式：本地工作视图（python -m http.server），数据文件为 i/*.json、d/*.html，带外审状态。
 */
(() => {
  "use strict";
  const $ = (s, r = document) => r.querySelector(s);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const UNK = "未知";
  let CFG, KEY = null, MAN, ITEMS = [], BYID = new Map(), rendered = null, inApp = false;
  const state = { tab: "all", q: "", f: {}, shown: 60 };

  // ───────── 存储：IndexedDB 里放不可导出的 CryptoKey ─────────
  const DB = "chendu", STORE = "k";
  function idb() {
    return new Promise((res, rej) => {
      const r = indexedDB.open(DB, 1);
      r.onupgradeneeded = () => r.result.createObjectStore(STORE);
      r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
    });
  }
  async function kvGet(k) { try { const d = await idb(); return await new Promise((res) => { const t = d.transaction(STORE).objectStore(STORE).get(k); t.onsuccess = () => res(t.result); t.onerror = () => res(null); }); } catch { return null; } }
  async function kvSet(k, v) { try { const d = await idb(); await new Promise((res) => { const t = d.transaction(STORE, "readwrite"); t.objectStore(STORE).put(v, k); t.oncomplete = res; t.onerror = res; }); } catch {} }
  async function kvDel(k) { try { const d = await idb(); await new Promise((res) => { const t = d.transaction(STORE, "readwrite"); t.objectStore(STORE).delete(k); t.oncomplete = res; t.onerror = res; }); } catch {} }

  // ───────── 解密 ─────────
  const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  async function deriveKey(pw) {
    const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pw), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt: b64(CFG.salt), iterations: CFG.iter },
      base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  }
  async function gunzip(buf) {
    const ds = new DecompressionStream("gzip");
    return new Response(new Blob([buf]).stream().pipeThrough(ds)).arrayBuffer();
  }
  async function fetchBytes(path, fresh) {
    const r = await fetch(path, { cache: fresh ? "no-cache" : "default" });
    if (!r.ok) throw new Error(`HTTP ${r.status} ${path}`);
    return new Uint8Array(await r.arrayBuffer());
  }
  async function openBlob(path, key, fresh) {
    const b = await fetchBytes(path, fresh);
    if (b[0] !== 67 || b[1] !== 68 || b[2] !== 49) throw new Error("格式不对");
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b.slice(3, 15), additionalData: new TextEncoder().encode(path) }, key, b.slice(15));
    return new TextDecoder().decode(await gunzip(plain));
  }
  async function load(kind, name, fresh) {          // kind: i | d
    if (CFG.mode === "plain") {
      const r = await fetch(`${kind}/${name}.${kind === "i" ? "json" : "html"}`, { cache: "no-cache" });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return r.text();
    }
    return openBlob(`${kind}/${name}.bin`, KEY, fresh);
  }

  // ───────── 启动 ─────────
  async function boot() {
    try { CFG = await (await fetch("config.json", { cache: "no-cache" })).json(); }
    catch { document.body.innerHTML = '<p class="err">配置读取失败</p>'; return; }
    if (CFG.mode !== "plain" && !(window.crypto && crypto.subtle && window.DecompressionStream)) {
      document.body.innerHTML = '<p class="err">这个浏览器太旧，打不开本站。请用较新的 Safari / Chrome / 微信内置浏览器（iOS 16.4+）。</p>'; return;
    }
    if (CFG.mode === "plain") return enter();
    const saved = await kvGet("key:" + CFG.salt);
    if (saved) {
      KEY = saved;
      try { return await enter(); } catch { KEY = null; await kvDel("key:" + CFG.salt); }
    }
    showLock("");
  }
  function showLock(msg) { $("#app").hidden = true; $("#lock").hidden = false; $("#lockMsg").textContent = msg; $("#pw").focus(); }
  $("#lockForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = $("#unlockBtn"); btn.disabled = true; $("#lockMsg").textContent = "正在解锁…（首次约 1 秒）";
    try {
      KEY = await deriveKey($("#pw").value);
      await load("i", "m", true);                  // 能解开清单 = 密码正确
      if ($("#remember").checked) await kvSet("key:" + CFG.salt, KEY);
      $("#pw").value = "";
      await enter();
    } catch (err) {
      KEY = null; $("#lockMsg").textContent = String(err).includes("HTTP") ? "网络错误，稍后再试" : "密码不对";
    } finally { btn.disabled = false; }
  });
  $("#forget").addEventListener("click", async () => {
    if (CFG.mode === "plain") return;
    await kvDel("key:" + CFG.salt); KEY = null; location.hash = "#/"; location.reload();
  });

  async function enter() {
    MAN = JSON.parse(await load("i", "m", true));
    const shards = await Promise.all(MAN.shards.map((s) => load("i", s, false).then(JSON.parse)));
    ITEMS = shards.flat().sort((a, b) => (b.d + b.id).localeCompare(a.d + a.id));
    BYID = new Map(ITEMS.map((x) => [x.id, x]));
    $("#lock").hidden = true; $("#app").hidden = false;
    $("#updated").textContent = `最后更新：${MAN.updated}` + (CFG.mode === "plain" ? " · 本地工作视图（含外审）" : "");
    route();
  }

  // ───────── 路由 ─────────
  window.addEventListener("hashchange", route);
  function route() {
    if (!MAN) return;
    const h = location.hash.replace(/^#\/?/, "");
    const [page, arg] = h.split("/");
    document.querySelectorAll("[data-nav]").forEach((a) => a.classList.toggle("on", a.dataset.nav === (page || "home")));
    if (page === "r" && arg) return openReader(decodeURIComponent(arg));
    const wasReading = !$("#reader").hidden;
    closeReader();
    if (wasReading && rendered === (page || "home")) return;     // 从阅读器回来：保留列表与滚动位置
    rendered = page || "home";
    if (page === "shelf") return renderShelf();
    if (page === "poets") return renderPoets();
    renderHome();
  }

  // ───────── 首页 ─────────
  const kindName = { p: "古诗", c: "经典" };
  const fmtD = (d) => d.slice(5).replace("-", "·");
  function todayStr() { const t = new Date(); return `${t.getFullYear()}-${String(t.getMonth() + 1).padStart(2, "0")}-${String(t.getDate()).padStart(2, "0")}`; }
  function latest(k) { return ITEMS.find((x) => x.k === k); }
  function card(x) {
    if (!x) return `<div class="card"><div class="kind">暂无</div></div>`;
    const stale = x.d !== todayStr() ? `<div class="stale">今天还没更新 · 这是 ${fmtD(x.d)} 的</div>` : "";
    if (x.k === "p") {
      const verse = (x.poem || "").split("\n").slice(0, 4).join("\n");
      return `<a class="card p" href="#/r/${x.id}"><div class="kind">古诗 · ${esc(x.d)}</div>
        <div class="ttl">${esc(x.t)}</div><div class="by">${esc(x.a)} · ${esc(x.dy)} · ${esc(x.th)}</div>
        <div class="verse">${esc(verse)}</div>${stale}</a>`;
    }
    return `<a class="card c" href="#/r/${x.id}"><div class="kind">经典 · ${esc(x.d)}</div>
      <div class="ttl">《${esc(x.b)}》</div><div class="by">${esc(x.a)} · ${esc(x.cat)}</div>
      <div class="verse">${esc(x.ch)}</div>${stale}</a>`;
  }
  function renderHome() {
    const v = $("#view");
    const now = new Date(), wk = "日一二三四五六"[now.getDay()];
    v.innerHTML = `<header class="mast"><h1>晨读</h1><div class="motto">每日古诗词 · 每日经典精读</div>
        <div class="dateline"><span>${now.getFullYear()}年${now.getMonth() + 1}月${now.getDate()}日 星期${wk}</span>
        <span>古诗 ${MAN.counts.p} · 经典 ${MAN.counts.c}</span></div></header>
      <section class="today">${card(latest("p"))}${card(latest("c"))}</section>
      <h2 class="sec">日历<small>每格一天</small></h2><div class="heat" id="heat"></div><div class="legend" id="legend"></div>
      <h2 class="sec">往期目录</h2>
      <div class="tabs" id="tabs">${["all", "p", "c"].map((t) => `<button data-t="${t}" class="${state.tab === t ? "on" : ""}">${{ all: "全部", p: "古诗", c: "经典" }[t]}</button>`).join("")}</div>
      <input class="search" id="q" type="search" placeholder="搜标题、作者、诗句、书名、主题…" value="${esc(state.q)}">
      <div class="filters" id="filters"></div>
      <div class="count" id="count"></div><ul class="list" id="list"></ul><button class="more" id="more" hidden>加载更多</button>`;
    renderHeat();
    $("#tabs").addEventListener("click", (e) => { const t = e.target.dataset.t; if (!t) return; state.tab = t; state.f = {}; state.shown = 60; renderHome(); });
    let tm; $("#q").addEventListener("input", (e) => { clearTimeout(tm); tm = setTimeout(() => { state.q = e.target.value.trim(); state.shown = 60; renderList(); }, 150); });
    $("#more").addEventListener("click", () => { state.shown += 60; renderList(); });
    renderFilters(); renderList();
  }

  const FACETS = { p: [["dy", "朝代"], ["th", "主题"], ["a", "作者"], ["fm", "体裁"]], c: [["b", "书名"], ["cat", "类别"], ["a", "作者"]] };
  function pool() { return ITEMS.filter((x) => state.tab === "all" || x.k === state.tab); }
  function renderFilters() {
    const box = $("#filters"); const facets = FACETS[state.tab] || [];
    box.innerHTML = facets.map(([k, label]) => {
      const cnt = new Map(); pool().forEach((x) => { const v = x[k] || UNK; cnt.set(v, (cnt.get(v) || 0) + 1); });
      const opts = [...cnt].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0], "zh"));
      return `<select data-k="${k}"><option value="">${label}（全部）</option>${opts.map(([v, n]) => `<option value="${esc(v)}" ${state.f[k] === v ? "selected" : ""}>${esc(v)} · ${n}</option>`).join("")}</select>`;
    }).join("");
    box.onchange = (e) => { const k = e.target.dataset.k; state.f[k] = e.target.value || undefined; state.shown = 60; renderList(); };
  }
  function hay(x) { return [x.t, x.a, x.dy, x.th, x.fm, x.poem, x.b, x.ch, x.cat, (x.tp || []).join(" "), x.d].join("\n"); }
  function filtered() {
    const q = state.q.toLowerCase();
    return pool().filter((x) => Object.entries(state.f).every(([k, v]) => !v || (x[k] || UNK) === v) && (!q || hay(x).toLowerCase().includes(q)));
  }
  function hl(s) { s = esc(s); if (!state.q) return s; const q = esc(state.q).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); return s.replace(new RegExp(q, "gi"), (m) => `<mark>${m}</mark>`); }
  function snippet(x) {
    if (!state.q || !x.poem) return "";
    const line = x.poem.split("\n").find((l) => l.toLowerCase().includes(state.q.toLowerCase()));
    return line ? `<div class="s">${hl(line)}</div>` : "";
  }
  function renderList() {
    const xs = filtered(); window.__LIST = xs.map((x) => x.id);
    $("#count").textContent = `${xs.length} 篇`;
    $("#list").innerHTML = xs.slice(0, state.shown).map((x) => {
      const sub = x.k === "p" ? `${x.a} · ${x.dy} · ${x.th} · ${x.fm}` : `${x.a} · ${x.cat}`;
      const ttl = x.k === "p" ? x.t : `《${x.b}》${x.ch}`;
      const rv = x.rv ? `<div class="rv">外审：${esc(x.rv)}</div>` : "";
      return `<li><a href="#/r/${x.id}"><span class="dt">${fmtD(x.d)}<br>${x.d.slice(0, 4)}</span>
        <span><span class="tag ${x.k}">${kindName[x.k]}</span><span class="t">${hl(ttl)}</span><div class="s">${hl(sub)}</div>${snippet(x)}${rv}</span></a></li>`;
    }).join("");
    $("#more").hidden = xs.length <= state.shown;
  }

  // ───────── 日历热力图（纯 SVG）─────────
  function renderHeat() {
    const cnt = new Map(); ITEMS.forEach((x) => cnt.set(x.d, (cnt.get(x.d) || 0) + 1));
    const dates = ITEMS.map((x) => x.d).sort(); if (!dates.length) return;
    const start = new Date(dates[0] + "T00:00:00"); start.setDate(start.getDate() - start.getDay());
    const end = new Date(todayStr() + "T00:00:00");
    const cs = 12, gap = 2, cells = []; let col = 0; const months = [];
    for (let d = new Date(start); d <= end; d.setDate(d.getDate() + 1)) {
      const ds = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
      const n = cnt.get(ds) || 0, row = d.getDay();
      if (d.getDate() === 1) months.push([col, d.getMonth() + 1]);
      cells.push(`<rect x="${col * (cs + gap)}" y="${16 + row * (cs + gap)}" width="${cs}" height="${cs}" rx="2" fill="var(--h${Math.min(n, 3)})"><title>${ds} · ${n} 篇</title></rect>`);
      if (row === 6) col++;
    }
    const w = (col + 1) * (cs + gap), h = 16 + 7 * (cs + gap);
    const ml = months.map(([c, m]) => `<text x="${c * (cs + gap)}" y="11" font-size="10" fill="var(--mut)">${m}月</text>`).join("");
    $("#heat").innerHTML = `<svg width="${w}" height="${h}" role="img" aria-label="每日发布日历">${ml}${cells.join("")}</svg>`;
    $("#legend").innerHTML = `少 <i style="background:var(--h0)"></i><i style="background:var(--h1)"></i><i style="background:var(--h2)"></i><i style="background:var(--h3)"></i> 多 · 断更的日子留白`;
    $("#heat").scrollLeft = 1e6;
  }

  // ───────── 聚合 ─────────
  function groupView(title, k, key, label) {
    const g = new Map(); ITEMS.filter((x) => x.k === k).forEach((x) => { const v = x[key] || UNK; if (!g.has(v)) g.set(v, []); g.get(v).push(x); });
    const arr = [...g].sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0], "zh"));
    $("#view").innerHTML = `<h2 class="sec">${title}（${arr.length}）</h2>` + arr.map(([name, xs]) =>
      `<details class="grp"><summary><span>${esc(name)}</span><span class="n">${xs.length} 篇</span></summary><ol>${
        xs.slice().sort((a, b) => a.d.localeCompare(b.d)).map((x) => `<li><a href="#/r/${x.id}">${esc(label(x))}</a> <span class="mut">${x.d}</span></li>`).join("")}</ol></details>`).join("");
  }
  const renderShelf = () => groupView("书架", "c", "b", (x) => x.ch);
  const renderPoets = () => groupView("诗人", "p", "a", (x) => x.t);

  // ───────── 阅读器 ─────────
  let curId = null;
  async function openReader(id) {
    const x = BYID.get(id);
    $("#reader").hidden = false; document.body.style.overflow = "hidden";
    if (!x) { $("#rTitle").textContent = "找不到这一篇"; $("#rFrame").srcdoc = ""; return; }
    curId = id;
    $("#rTitle").textContent = x.k === "p" ? x.t : `《${x.b}》`;
    const seq = ITEMS.filter((y) => y.k === x.k), i = seq.findIndex((y) => y.id === id);
    const prev = seq[i + 1], next = seq[i - 1];      // ITEMS 倒序：i+1 是更早的
    $("#rPrev").disabled = !prev; $("#rNext").disabled = !next;
    $("#rPrev").onclick = () => prev && location.replace(`#/r/${prev.id}`);
    $("#rNext").onclick = () => next && location.replace(`#/r/${next.id}`);
    $("#rFrame").srcdoc = `<p style="font:15px sans-serif;color:#888;padding:24px">加载中…</p>`;
    if (!x.has) { $("#rFrame").srcdoc = `<p style="font:15px sans-serif;padding:24px">这一篇的详情页本次没有发布（构建时没通过检查）。</p>`; return; }
    try {
      const html = await load("d", id, false);
      if (curId === id) $("#rFrame").srcdoc = html;
    } catch (e) { $("#rFrame").srcdoc = `<p style="font:15px sans-serif;padding:24px">加载失败：${esc(e.message)}</p>`; }
  }
  function closeReader() { $("#reader").hidden = true; document.body.style.overflow = ""; curId = null; $("#rFrame").srcdoc = ""; }
  $("#rBack").addEventListener("click", () => { if (inApp) history.back(); else location.hash = "#/"; });
  window.addEventListener("hashchange", (e) => { if (!/#\/r\//.test(e.oldURL)) inApp = true; });
  $("#rShare").addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(location.href); toast("链接已复制（打开仍需密码）"); } catch { toast(location.href); }
  });
  function toast(s) { const t = $("#toast"); t.textContent = s; t.hidden = false; clearTimeout(t._t); t._t = setTimeout(() => (t.hidden = true), 2200); }

  boot();
})();
