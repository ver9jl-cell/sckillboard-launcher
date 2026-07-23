// Security regression tests for the audit fixes. No framework — run with `npm test`.
// Covers: httpGet redirect pinning, RSI URL handle encoding, openExternal https-pin.
const fs = require('fs')
const path = require('path')
const http = require('http')
const https = require('https')

const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'main.js'), 'utf8')
let pass = 0, fail = 0
const ok = (c, n) => { if (c) { pass++; console.log('PASS:', n) } else { fail++; console.log('FAIL:', n) } }

// ── httpGet redirect pin (real sockets, function extracted verbatim from main.js) ──
const fnMatch = src.match(/function httpGet\(urlStr\) \{[\s\S]*?\n\}/)
if (!fnMatch) { console.error('FAIL: could not extract httpGet from main.js'); process.exit(1) }
let testPort = 0
const httpWrapped = { get: (opts, cb) => http.get({ ...opts, port: testPort }, cb) }
const httpGet = new Function('http', 'https', 'return ' + fnMatch[0])(httpWrapped, https)

const srv = http.createServer((req, res) => {
  if (req.url === '/evil-absolute')      { res.writeHead(302, { Location: 'http://127.0.0.1:' + testPort + '/payload' }); res.end() }
  else if (req.url === '/evil-external') { res.writeHead(302, { Location: 'https://attacker.example.com/x' }); res.end() }
  else if (req.url === '/evil-relative') { res.writeHead(302, { Location: '/payload' }); res.end() }
  else if (req.url === '/payload')       { res.end('SECRET-PAYLOAD') }
  else res.end('root')
})

srv.listen(0, '127.0.0.1', async () => {
  testPort = srv.address().port
  const base = 'http://127.0.0.1:' + testPort
  try {
    const r1 = await httpGet(base + '/evil-absolute')
    ok(r1.body === '' && r1.status === 302, 'off-domain absolute redirect dropped (empty body)')
    const r2 = await httpGet(base + '/evil-external')
    ok(r2.body === '', 'attacker-domain redirect dropped')
    const r3 = await httpGet(base + '/evil-relative')
    ok(r3.body === '', 'relative redirect resolved against request URL, then pinned (no crash)')
    const pin = /^https?:\/\/(www\.)?robertsspaceindustries\.com\//i
    ok(pin.test('https://robertsspaceindustries.com/en/citizens/foo'), 'pin accepts RSI')
    ok(!pin.test('https://robertsspaceindustries.com.evil.com/'), 'pin rejects suffix-spoof domain')
    srv.close()

    // ── RSI URL handle encoding (Game.log-derived handle interpolated into scrape URL) ──
    const handle = 'evil/../../admin?x=<script>'
    const url = `https://robertsspaceindustries.com/en/citizens/${encodeURIComponent(handle)}`
    ok(!url.includes('/../') && !url.includes('<script>'), 'hostile handle: traversal + html neutralized')
    const rsiSites = (src.match(/robertsspaceindustries\.com\/[^`]*\$\{encodeURIComponent\(handle\)\}/g) || []).length
    ok(rsiSites >= 3, 'main.js encodeURIComponent(handle) at 3+ RSI sites (found ' + rsiSites + ')')

    // ── openExternal download_url https-pin (server-supplied URL) ──
    ok(/shell\.openExternal\(\/\^https:.*info\.download_url.*DEFAULT_RELEASES_URL\)/.test(src), 'forced-update path https-pins download_url')
    ok(/res\.download_url && \/\^https:.*\.test\(res\.download_url\)/.test(src), 'soft-update path https-pins download_url')
    const httpsPin = u => /^https:\/\//i.test(u || '')
    ok(httpsPin('https://good') && !httpsPin('file:///etc/passwd') && !httpsPin('javascript:alert(1)') && !httpsPin('steam://run/1'),
       'https-pin: accepts https, rejects file/javascript/custom-scheme')

    console.log(`\n=== ${pass} passed, ${fail} failed ===`)
    process.exit(fail ? 1 : 0)
  } catch (e) { console.error('ERROR:', e.message); process.exit(1) }
})
