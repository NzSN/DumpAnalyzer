# Operator dashboard

The Rust daemon serves an optional loopback operator dashboard at `/` on
`DUMP_ANALYZER_HTTP_ADDR` (default `127.0.0.1:4180`; empty disables it). It is a
static single-page shell baked into the binary; every value comes from the
existing `/api/*` JSON endpoints. It never embeds server data, dump bytes, or
the analyzer token.

Since the 2026-10-30 redesign the dashboard is built on the
[Gentelella v4 admin template](https://github.com/ColorlibHQ/gentelella). The
DumpLedger operator UI uses the same template, so both surfaces share one design
language: a grouped sidebar, a fixed topbar, Gentelella cards/tables/status
pills, and light/dark tokens.

## Files and provenance

| Path | Purpose |
| --- | --- |
| [`src/ui/dashboard.html`](../src/ui/dashboard.html) | Static shell: skip link, sidebar, topbar, four panels, footer. No inline CSS or script. |
| [`src/ui/app.css`](../src/ui/app.css) | DumpAnalyzer app layer on top of Gentelella (tokens, shell fixes, dashboard components, responsive rules). |
| [`src/ui/dashboard.js`](../src/ui/dashboard.js) | All dashboard behaviour: routing, polling, explorer, reports, report detail, action forms, theme and sidebar behaviour. |
| [`src/ui/gentelella.css`](../src/ui/gentelella.css) | Vendored Gentelella design system (159,792 bytes; full `main.scss`, v4.2.0). Do not edit by hand. |
| [`src/ui/GENTELELLA-LICENSE.txt`](../src/ui/GENTELELLA-LICENSE.txt) | MIT license for the vendored template. |
| [`tools/vendor-gentelella.sh`](../tools/vendor-gentelella.sh) | Reproducible regeneration of the vendored CSS at a pinned commit. |
| [`src/http.rs`](../src/http.rs) | Serves the shell and assets, runs the strict CSP header, and renders the Gentelella form-result pages. |

The template is pinned to commit `02936f9003baa8473aa39dadd4ce23b679961d53`
(v4.2.0); the vendored files are committed, so builds and tests need no
network access. To intentionally upgrade the template:

```sh
tools/vendor-gentelella.sh          # rewrites gentelella.css + license
git diff src/ui/gentelella.css     # review the template delta
# then re-check the shell in src/ui/dashboard.html and src/ui/app.css
```

`app.css` owns every DumpAnalyzer-specific component; the vendored file must
stay byte-identical to the script's output.

## Serving and Content-Security-Policy

| Route | Content type | Body |
| --- | --- | --- |
| `GET /` | `text/html; charset=utf-8` | `src/ui/dashboard.html` |
| `GET /assets/gentelella.css` | `text/css; charset=utf-8` | vendored template |
| `GET /assets/app.css` | `text/css; charset=utf-8` | app layer |
| `GET /assets/dashboard.js` | `text/javascript; charset=utf-8` | behaviour |

Every HTML response (the dashboard and the form-result pages) carries:

```text
content-security-policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'
x-content-type-options: nosniff
cache-control: no-store
```

The policy forbids inline `<style>`, inline `<script>`, `style="…"` attributes
and inline event handlers. Presentation lives in the two stylesheets; inline
SVG and CSS `data:` URIs are allowed. No external fonts or assets are loaded,
so the template's Inter webfont is replaced by the system UI font stack. This
is an intentional trade-off for an offline, loopback-only surface: glyph
metrics differ slightly from upstream Gentelella screenshots.

## Layout and behaviour

- **Sidebar** (`#sidebar`): brand, three grouped navigation sections
  (`Operations` → Queue; `Evidence` → Dumps, Reports; `System` → Settings),
  and a local-daemon footer. Above 768 px the topbar toggle collapses it to a
  64 px icon rail (`body.sidebar-rail`, persisted in
  `localStorage["dump-analyzer.sidebar-rail"]`); below 769 px the same toggle
  opens a drawer (`body.sidebar-open` + `.sidebar.open`) that closes on
  Escape, on the backdrop, or after following a link.
- **Topbar**: breadcrumb, daemon status chip (connection dot, version, last
  successful update), ledger URL, and the theme select (`System`, `Light`,
  `Dark`; stored as `dump-analyzer-theme`, applied as `html[data-theme]`). The
  `meta[name=theme-color]` and browser theme follow the resolved theme.
- **Queue**: stat tiles (jobs in queue, pending reports, local reports), an
  SVG queue-pipeline bar, phase filter chips, a filterable active-jobs table,
  and explicit empty states.
- **Dumps explorer**: customer → case → dump navigation with breadcrumbs,
  bounded search, pagination, per-scope analysis buttons, and the Gentelella
  table/status vocabulary for dumps.
- **Reports**: search plus outcome/delivery filters, a paged report table, and
  lazy rich-report detail (exception, context/registers, native stack,
  JavaScript/optimized frames, symbols, evidence, provenance). Legacy reports
  remain explicitly labelled. The detail view loads only the selected
  `GET /api/reports/:reportId`.
- **Settings**: analyzer-token card (the token is probed against the ledger
  before it is stored), one actions card (analyze dump/case/customer, rescan)
  enabled per `/api/capabilities`, and daemon diagnostics.

Hash routing (`#queue`, `#dumps`, `#reports`, `#settings` with their query
parameters) preserves scope, filters, and page selection across Back/Forward.
The queue polls every 5 seconds and the selected list/detail every 15 seconds;
hidden panels make no list requests. The dashboard is a static shell: it embeds
no catalog, report, or credential data.

## Accessibility and responsive behaviour

- Skip link is the first focusable element and targets `#content`.
- One `<h1>` per panel (focused after keyboard/hash navigation), labelled
  navigation landmarks, real table headers, and polite/assertive live regions
  for status and action feedback.
- Buttons are real buttons with a visible focus ring; disabled actions expose
  `disabled` plus a distinct disabled affordance.
- Color tokens in `app.css` keep WCAG-AA contrast on the Gentelella surfaces
  (including the lighter teal primary fill and muted text); status pills and
  warnings use darker inks.
- The layout is exercised at 1440×900 (light, dark, rail) and 390×844 (drawer).

## Tests and verification

- `tests/http.rs` asserts the shell structure, required ids, asset links, the
  exact CSP header, `nosniff`/`no-store`, absence of inline style/script/
  handlers, asset content types and markers, and result-page assets/no inline
  CSS.
- `tests/dashboard_javascript.mjs` executes the real DOM-free rendering helpers
  (`statusLabel`, `javascriptStackMarkup`, escaping) from
  `src/ui/dashboard.js` under `node --test`.
- Browser verification for the redesign (Playwright/Chromium under the real CSP,
  11+ scenarios, contrast samples, keyboard and drawer checks) is recorded in
  `dashboard-verify/` alongside the workspace's before/after screenshots; see
  `dashboard-verify/report.md` when that evidence is present (it is a workspace
  artifact, not part of the crate).
