/**
 * ============================================================
 * QUASAR API MAPPER v2 — SPA Endpoint Discovery Engine
 * ============================================================
 * Paste into DevTools Console on the target SPA.
 *
 * Coverage:
 *   [RUNTIME]  fetch + XHR hooks (passive capture while you browse)
 *   [STATIC]   JS chunk mining: axios, fetch, /api/ strings, GraphQL
 *   [ROUTER]   React Router / Vue Router / SvelteKit route extraction
 *   [CRAWL]    HTML link + form discovery from current DOM
 *   [SITEMAP]  /sitemap.xml + /robots.txt endpoint harvesting
 *   [NAV]      Auto-navigation: visits discovered routes, captures
 *              the API calls each route fires (active spider)
 *
 * Globals exposed:
 *   showAPI()      — render current API map
 *   crawlRoutes()  — auto-navigate all discovered SPA routes
 *   exportAPI()    — copy JSON to clipboard
 *   __API_MAP__    — array of discovered endpoints
 *   __API_RAW__    — Map of raw entries
 * ============================================================
 */
(async () => {
  console.clear();

  const APIs = new Map();
  const ROUTES = new Set();
  const CHUNKS = new Set();
  const MAX_DEPTH = 6;

  const clean = v => {
    if (v === undefined || v === null) return "";
    if (typeof v === "string") return v;
    try { return JSON.stringify(v, null, 2); } catch { return String(v); }
  };

  const add = ({ method = "UNKNOWN", url = "", input = "", query = "", source = "runtime" }) => {
    try { url = new URL(url, location.href).href; } catch { return; }

    // API-looking filter (keep loose — router mining adds non-/api too)
    const isApi =
      /\/api\b/i.test(url) ||
      /graphql/i.test(url) ||
      /\.(json|php|aspx)(\?|$)/i.test(url) ||
      /\/_(next|nuxt|remix|sveltekit)\//.test(url) ||
      /\/(v\d+|rest|rpc|gql|query|mutate)\b/i.test(url);

    if (!isApi) return;

    const key = `${method}|${url}|${clean(input).slice(0, 200)}|${query}`;
    if (!APIs.has(key)) {
      APIs.set(key, {
        METHOD: method.toUpperCase(),
        ENDPOINT: url,
        INPUT: clean(input),
        QUERY: query,
        SOURCE: source
      });
    }
  };

  const addRoute = r => {
    if (!r || typeof r !== "string") return;
    if (!r.startsWith("/")) return;
    if (r.startsWith("//")) return;
    if (/\.(js|css|png|jpg|svg|woff2?|ico|map)$/i.test(r)) return;
    if (r.length > 200) return;
    ROUTES.add(r);
  };

  // ============================================================
  // 1. RUNTIME HOOKS — fetch + XHR
  // ============================================================

  const originalFetch = window.fetch;
  window.fetch = async function (input, options = {}) {
    let url = typeof input === "string" ? input : input?.url;
    let method = options?.method || input?.method || "GET";
    let body = options?.body || input?.body || "";
    let query = "";
    try { query = new URL(url, location.href).search; } catch {}

    add({ method, url, input: body, query, source: "FETCH-LIVE" });
    return originalFetch.apply(this, arguments);
  };

  const originalOpen = XMLHttpRequest.prototype.open;
  const originalSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function (method, url) {
    this.__apiMethod = method;
    this.__apiUrl = url;
    return originalOpen.apply(this, arguments);
  };

  XMLHttpRequest.prototype.send = function (body) {
    if (this.__apiUrl) {
      let query = "";
      try { query = new URL(this.__apiUrl, location.href).search; } catch {}
      add({ method: this.__apiMethod, url: this.__apiUrl, input: body, query, source: "XHR-LIVE" });
    }
    return originalSend.apply(this, arguments);
  };

  // ============================================================
  // 2. STATIC JS MINING
  // ============================================================

  const scanned = new Set();

  async function scanScript(url, depth = 0) {
    if (!url || scanned.has(url) || depth > MAX_DEPTH) return;
    scanned.add(url);
    CHUNKS.add(url);

    let code;
    try {
      code = await originalFetch(url).then(r => r.text());
    } catch { return; }

    // ---- axios.get/post/etc ----
    const axiosRegex = /\baxios\s*\.\s*(get|post|put|patch|delete|head|options)\s*\(\s*([`'"])(.*?)\2([\s\S]{0,3000}?)\)/gi;
    let m;
    while ((m = axiosRegex.exec(code))) {
      const method = m[1].toUpperCase();
      const u = m[3];
      const rest = m[4] || "";
      let input = "";
      if (["POST", "PUT", "PATCH"].includes(method)) {
        const comma = rest.match(/^\s*,\s*([\s\S]{0,2000})/);
        if (comma) input = comma[1].replace(/\)\s*;?\s*$/, "").trim();
      }
      add({ method, url: u, input, source: "AXIOS" });
    }

    // ---- axios({ method, url, data }) ----
    const axiosObject = /\baxios\s*\.\s*(?:request\s*)?\(\s*\{([\s\S]{0,5000}?)\}\s*\)/gi;
    while ((m = axiosObject.exec(code))) {
      const block = m[1];
      const method = block.match(/\bmethod\s*:\s*["'`]([^"'`]+)["'`]/)?.[1] || "UNKNOWN";
      const u = block.match(/\burl\s*:\s*["'`]([^"'`]+)["'`]/)?.[1];
      const input = block.match(/\b(?:data|body)\s*:\s*([\s\S]{0,2000}?)(?:,\s*\w+\s*:|$)/)?.[1] || "";
      if (u) add({ method, url: u, input, source: "AXIOS-OBJ" });
    }

    // ---- fetch('/api/...') ----
    const fetchRegex = /\bfetch\s*\(\s*([`'"])(.*?)\1([\s\S]{0,3000}?)\)/gi;
    while ((m = fetchRegex.exec(code))) {
      const u = m[2];
      const rest = m[3] || "";
      const method = rest.match(/\bmethod\s*:\s*["'`]([^"'`]+)["'`]/)?.[1] || "GET";
      const body = rest.match(/\bbody\s*:\s*([\s\S]{0,2000}?)(?:,\s*\w+\s*:|\})/)?.[1] || "";
      add({ method, url: u, input: body, source: "FETCH-STATIC" });
    }

    // ---- generic /api/ strings with context ----
    const apiRegex = /([`'"])(\/(?:api|v\d+|graphql|rest|rpc|gql)\/[^`'"]+)\1/gi;
    while ((m = apiRegex.exec(code))) {
      const u = m[2];
      const context = code.slice(Math.max(0, m.index - 500), Math.min(code.length, m.index + 2500));
      let method = "UNKNOWN";
      if (/axios\.post|method\s*:\s*["'`]POST/i.test(context)) method = "POST";
      else if (/axios\.get/i.test(context)) method = "GET";
      else if (/axios\.put|method\s*:\s*["'`]PUT/i.test(context)) method = "PUT";
      else if (/axios\.patch|method\s*:\s*["'`]PATCH/i.test(context)) method = "PATCH";
      else if (/axios\.delete|method\s*:\s*["'`]DELETE/i.test(context)) method = "DELETE";
      else if (/fetch/i.test(context)) method = "GET";
      const dataMatch = context.match(/\b(?:data|body)\s*:\s*([\s\S]{0,1000})/);
      const input = dataMatch ? dataMatch[1].slice(0, 1000) : "";
      add({ method, url: u, input, source: "STRING" });
    }

    // ---- GraphQL operations (query/mutation/subscription names) ----
    const gqlRegex = /\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)/g;
    while ((m = gqlRegex.exec(code))) {
      const opName = m[2];
      // Only record if a graphql endpoint is referenced anywhere in chunk
      if (/graphql/i.test(code)) {
        add({
          method: m[1] === "query" ? "QUERY" : m[1].toUpperCase(),
          url: "/graphql",
          input: `${m[1]} ${opName}`,
          source: "GRAPHQL"
        });
      }
    }

    // ---- ROUTER MINING ----
    scanRouterPatterns(code);

    // ---- follow imports (static + dynamic) ----
    const imports = [
      ...code.matchAll(/\bimport\s*(?:[^"'`]*?\sfrom\s*)?["'`]([^"'`]+)["'`]/g),
      ...code.matchAll(/\bimport\s*\(\s*["'`]([^"'`]+)["'`]\s*\)/g),
      ...code.matchAll(/\brequire\s*\(\s*["'`]([^"'`]+)["'`]\s*\)/g)
    ];
    for (const im of imports) {
      const imp = im[1];
      if (!imp.startsWith(".")) continue;
      try {
        let child = new URL(imp, url).href;
        // Vite/webpack extensionless imports → try .js
        if (!/\.(js|mjs|cjs|ts|jsx|tsx)(\?|$)/.test(child)) child += ".js";
        await scanScript(child, depth + 1);
      } catch {}
    }

    // ---- webpack chunk manifest: "123" → "chunk-123.js" style maps ----
    const chunkMap = code.match(/\{([\s\S]{0,5000}?)\}\s*\[\s*e\s*\]\s*\+\s*["'`]\.js/);
    if (chunkMap) {
      const ids = [...chunkMap[1].matchAll(/["'`](\d+)["'`]\s*:/g)].map(x => x[1]);
      const base = new URL("./", url).href;
      for (const id of ids.slice(0, 200)) {
        // Common patterns; failures are silently skipped
        for (const pat of [`${id}.js`, `chunk-${id}.js`]) {
          try { await scanScript(new URL(pat, base).href, depth + 1); } catch {}
        }
      }
    }
  }

  // ============================================================
  // 3. ROUTER PATTERN MINING
  // ============================================================

  function scanRouterPatterns(code) {
    // React Router: <Route path="/users" ...> or path: "/users"
    for (const m of code.matchAll(/\bpath\s*[:=]\s*["'`](\/[^"'`]*)["'`]/g)) addRoute(m[1]);
    // React Router v6: createBrowserRouter([{ path: "..." }])
    for (const m of code.matchAll(/\bcreateBrowserRouter\s*\(/g)) {
      // handled by generic path: mining above
    }
    // Vue Router: { path: '/x', component: ... } — covered above
    // SvelteKit/Nuxt file-based: extract from chunk URLs instead
    // Angular: loadChildren / redirectTo
    for (const m of code.matchAll(/\bredirectTo\s*:\s*["'`](\/[^"'`]*)["'`]/g)) addRoute(m[1]);
    // Next.js app router chunks: /_next/static/chunks/app/<route>/page-*.js
    for (const m of code.matchAll(/["'`]((?:\/?_next)?\/(?:app\/)?[\w\-./]*page[\w\-./]*)["'`]/g)) {
      // too noisy — skip
    }
    // history.push / navigate('/x')
    for (const m of code.matchAll(/\b(?:navigate|push|replace)\s*\(\s*["'`](\/[^"'`]*)["'`]/g)) addRoute(m[1]);
    // <a href="/x"> in inline templates
    for (const m of code.matchAll(/\bhref\s*=\s*["'`](\/[^"'`]*)["'`]/g)) addRoute(m[1]);
    // to="/x" (React Router Link)
    for (const m of code.matchAll(/\bto\s*=\s*["'`](\/[^"'`]*)["'`]/g)) addRoute(m[1]);
  }

  // ============================================================
  // 4. DOM CRAWL — links + forms from current page
  // ============================================================

  function crawlDom() {
    document.querySelectorAll('a[href]').forEach(a => {
      try {
        const u = new URL(a.href, location.href);
        if (u.origin === location.origin) addRoute(u.pathname + u.search);
      } catch {}
    });
    document.querySelectorAll("form[action]").forEach(f => {
      try {
        const u = new URL(f.getAttribute("action") || location.href, location.href);
        const method = (f.method || "GET").toUpperCase();
        const fields = [...f.querySelectorAll("input,select,textarea")]
          .map(i => i.name).filter(Boolean).join(", ");
        add({ method, url: u.href, input: fields ? `FORM: ${fields}` : "", source: "FORM" });
      } catch {}
    });
  }

  // ============================================================
  // 5. SITEMAP + ROBOTS
  // ============================================================

  async function scanSitemap() {
    for (const path of ["/sitemap.xml", "/robots.txt"]) {
      try {
        const txt = await originalFetch(path).then(r => (r.ok ? r.text() : null));
        if (!txt) continue;
        for (const m of txt.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)) {
          try {
            const u = new URL(m[1], location.href);
            if (u.origin === location.origin) addRoute(u.pathname + u.search);
          } catch {}
        }
        for (const m of txt.matchAll(/^(?:Allow|Disallow):\s*(\/\S*)/gim)) {
          if (m[1] !== "/") addRoute(m[1]);
        }
      } catch {}
    }
  }

  // ============================================================
  // 6. AUTO-NAVIGATION (active spider)
  // ============================================================

  async function crawlRoutes({ max = 30, delay = 800 } = {}) {
    const targets = [...ROUTES]
      .filter(r => r !== location.pathname)
      .slice(0, max);

    console.log(`%c[crawl] Visiting ${targets.length} routes...`, "font-weight:bold");

    for (const route of targets) {
      const before = APIs.size;
      try {
        history.pushState({}, "", route);
        window.dispatchEvent(new PopStateEvent("popstate"));
      } catch {}
      await new Promise(r => setTimeout(r, delay));
      crawlDom();
      const fired = APIs.size - before;
      console.log(`[crawl] ${route} → ${fired} new API calls`);
    }

    // return to start
    try {
      history.pushState({}, "", START_PATH);
      window.dispatchEvent(new PopStateEvent("popstate"));
    } catch {}

    return show();
  }

  const START_PATH = location.pathname + location.search;

  // ============================================================
  // 7. EXECUTION PIPELINE
  // ============================================================

  crawlDom();
  await scanSitemap();

  const scripts = [
    ...document.querySelectorAll('script[src], link[rel="modulepreload"], link[rel="preload"][as="script"]')
  ].map(x => x.src || x.href).filter(Boolean);

  console.log(`%cScanning ${scripts.length} loaded JS chunks + router patterns...`, "font-weight:bold");

  for (const script of scripts) await scanScript(script);

  // Also scan inline scripts for router config
  document.querySelectorAll("script:not([src])").forEach(s => {
    try { scanRouterPatterns(s.textContent); } catch {}
  });

  // ============================================================
  // 8. DISPLAY + GLOBALS
  // ============================================================

  function show() {
    const list = [...APIs.values()].map((x, i) => ({
      "#": i + 1,
      METHOD: x.METHOD,
      ENDPOINT: x.ENDPOINT,
      INPUT: x.INPUT ? x.INPUT.replace(/\s+/g, " ").slice(0, 500) : "-",
      QUERY: x.QUERY || "-",
      SOURCE: x.SOURCE
    }));

    console.clear();
    console.log(`%cAPI MAP — ${list.length} endpoints | ${ROUTES.size} routes | ${CHUNKS.size} chunks scanned`, "font-size:18px;font-weight:bold");
    console.table(list);
    console.log("%cRoutes discovered:", "font-weight:bold");
    console.table([...ROUTES]);
    console.log("%cFull objects:", "font-weight:bold");
    console.log(list);

    window.__API_MAP__ = list;
    window.__API_RAW__ = APIs;
    window.__ROUTES__ = [...ROUTES];
    window.__CHUNKS__ = [...CHUNKS];

    return list;
  }

  function exportAPI() {
    const data = JSON.stringify({ endpoints: [...APIs.values()], routes: [...ROUTES] }, null, 2);
    navigator.clipboard.writeText(data).then(
      () => console.log("%cCopied to clipboard ✓", "color:green;font-weight:bold"),
      () => console.log(data)
    );
    return data;
  }

  show();

  console.log("%cAPI capture ACTIVE. Commands:", "font-size:15px;font-weight:bold");
  console.log("  showAPI()     — re-render map");
  console.log("  crawlRoutes() — auto-visit discovered routes, capture their API calls");
  console.log("  exportAPI()   — copy JSON to clipboard");

  window.showAPI = show;
  window.crawlRoutes = crawlRoutes;
  window.exportAPI = exportAPI;
})();
