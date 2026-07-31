/**
 * scKillboard - Main Process v1.4.8
 * Handles window creation, IPC, Game.log watching, API calls + RSI profile sync.
 */

const { app, BrowserWindow, ipcMain, dialog, shell, safeStorage } = require('electron')
const path   = require('path')
const fs     = require('fs')
const https  = require('https')
const http   = require('http')
const os     = require('os')
const crypto = require('crypto')
const { exec } = require('child_process')
const IS_LINUX = process.platform === 'linux'
const USERAGENT = IS_LINUX ?
  'Mozilla/5.0 (X11; Linux x86_64; rv:153.0) Gecko/20100101 Firefox/153.0' :
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36'


// ── Star Citizen process check ────────────────────────────────────────────────
function isScRunning() {
  return new Promise(resolve => {
    if (IS_LINUX) {
      // Linux: SC runs under Wine/Proton, but the process name is usually still StarCitizen.exe
      exec('pgrep -fi StarCitizen.exe', (err, stdout) => {
        resolve(!err && stdout.trim().length > 0)
      })
    } else {
      exec('tasklist /FI "IMAGENAME eq StarCitizen.exe" /NH', (err, stdout) => {
        resolve(!err && stdout.toLowerCase().includes('starcitizen.exe'))
      })
    }
  })
}

let scPollTimer = null
function startScPoll(win) {
  stopScPoll()
  const send = async () => {
    const running = await isScRunning()
    if (win && !win.isDestroyed()) win.webContents.send('sc-status', running)
  }
  send() // immediate check
  scPollTimer = setInterval(send, 2000)
}
function stopScPoll() {
  if (scPollTimer) { clearInterval(scPollTimer); scPollTimer = null }
}

// ── Config ─────────────────────────────────────────────────────────────────────
const API_BASE   = 'https://www.sckillboard.com'
// API_SECRET is loaded from config at runtime — never hardcoded
function getApiSecret() { return loadConfig().api_secret || '' }
function getSessionToken() { return loadConfig().session_token || '' }

const CONFIG_DIR = IS_LINUX ? path.join(os.homedir(), ".config", "sckillboard") : path.join(os.homedir(), 'AppData', 'Roaming', 'vKillboard')
const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json')
const DEFAULT_LOG = IS_LINUX ? 
  path.join(os.homedir(), 'Games', 'star-citizen', 'drive_c', 'Program Files', 'Roberts Space Industries', 'StarCitizen', 'LIVE', 'Game.log') :
  'C:\\Program\ Files\\Roberts\ Space\ Industries\\StarCitizen\\LIVE\\Game.log'
const KILL_CRIMES = new Set([
  'Negligent Homicide', 'Murder', 'Manslaughter',
  'Aggravated Assault', 'Destruction of Vehicle', 'Grievous Bodily Harm',
  'Homicide', 'Incapacitated'
])

const QUOTES = [
  'The quarry never sees the last step.',
  'Some hunt for food. Others hunt for sport.',
  'Another trophy for the wall.',
  'Death is just the end of the chase.',
  'It is not the prey that chooses the hunt.',
  'The forest remembers who ran.',
]

// ── Config helpers ──────────────────────────────────────────────────────────────
const SECRET_FIELDS = ['session_token', 'personal_webhook'];

function _protectSecrets(cfg) {
  for (const k of SECRET_FIELDS) {
    if (cfg[k] != null && !String(cfg[k]).startsWith('enc:')) {
      cfg[k] = 'enc:' + safeStorage.encryptString(String(cfg[k])).toString('base64');
    }
  }
  return cfg;
}

function _unprotectSecrets(cfg) {
  for (const k of SECRET_FIELDS) {
    if (cfg[k] != null && String(cfg[k]).startsWith('enc:')) {
      try { cfg[k] = safeStorage.decryptString(Buffer.from(String(cfg[k]).slice(4), 'base64')); } catch (e) {}
    }
  }
  return cfg;
}

function loadConfig() {
  try {
    if (fs.existsSync(CONFIG_FILE)) {
      const cfg = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
      if (safeStorage.isEncryptionAvailable()) _unprotectSecrets(cfg);
      return cfg;
    }
  } catch(e) {}
  return { log_path: DEFAULT_LOG, attacker_handle: '', personal_webhook: '', personal_enabled: false, api_secret: '', volume: 0.067, muted: false }
}

function saveConfig(cfg) {
  try {
    fs.mkdirSync(CONFIG_DIR, { recursive: true })
    const out = safeStorage.isEncryptionAvailable() ? _protectSecrets(JSON.parse(JSON.stringify(cfg))) : cfg;
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(out, null, 2))
  } catch(e) {}
}

// ── HTTP helpers ────────────────────────────────────────────────────────────────
function apiRequest(method, urlPath, body) {
  return new Promise((resolve, reject) => {
    const bodyStr = body ? JSON.stringify(body) : ''
    const sig = body
      ? crypto.createHmac('sha256', getApiSecret()).update(bodyStr).digest('hex')
      : ''
    const url = new URL(API_BASE + urlPath)
    const opts = {
      hostname: url.hostname,
      path:     url.pathname + url.search,
      method,
      headers: {
        'Content-Type':   'application/json',
        'Content-Length': Buffer.byteLength(bodyStr),
        'X-Client-Version': app.getVersion(),
        ...(getSessionToken() ? { 'Cookie': 'vkb_session=' + getSessionToken() } : (sig ? { 'X-Signature': sig } : {}))
      }
    }
    const req = (url.protocol === 'https:' ? https : http).request(opts, res => {
      let data = ''
      res.on('data', c => data += c)
      res.on('end', () => {
        let parsed
        try {
          parsed = JSON.parse(data)
        } catch(e) {
          resolve({ ok: false, error: `Parse error (${res.statusCode}): ${data.slice(0,200)}` })
          return
        }
        // Server says this launcher is too old (HTTP 426). Trigger the blocking
        // update flow, and still resolve so the caller doesn't hang.
        if (res.statusCode === 426 || parsed.update_required) {
          handleUpdateRequired(parsed)
          resolve({ ok: false, error: parsed.message || 'Update required', update_required: true })
          return
        }
        resolve(parsed)
      })
    })
    req.on('error', reject)
    if (bodyStr) req.write(bodyStr)
    req.end()
  })
}

function httpGet(urlStr) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlStr)
    const opts = {
      hostname: url.hostname,
      path: url.pathname + url.search,
      method: 'GET',
      headers: {
        'User-Agent': USERAGENT,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Referer': 'https://robertsspaceindustries.com/',
      }
    }
    const mod = url.protocol === 'https:' ? https : http
    const req = mod.get(opts, res => {
      // Follow redirects
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        const loc = new URL(res.headers.location, urlStr).href
        if (/^https?:\/\/(www\.)?robertsspaceindustries\.com\//i.test(loc)) {
          return httpGet(loc).then(resolve).catch(reject)
        }
        return resolve({ status: res.statusCode, body: '' })
      }
      let data = ''
      res.on('data', c => data += c)
      res.on('end', () => resolve({ status: res.statusCode, body: data }))
    })
    req.on('error', reject)
    req.setTimeout(12000, () => { req.destroy(); reject(new Error('timeout')) })
  })
}

// ── RSI Profile scraping ────────────────────────────────────────────────────────
async function fetchRsiProfile(handle) {
  const profile = {
    handle, display: handle,
    avatar_url: '', org_logo: '', org_name: '', org_sid: '', org_rank: '',
    enlisted: '', location: '',
    found: false,        // true only when a real RSI citizen page was loaded
    lookup: 'error',     // 'found' | 'notfound' (clean 404) | 'error' (couldn't tell)
    profile_url: `https://robertsspaceindustries.com/en/citizens/${encodeURIComponent(handle)}`
  }
  let sawNotFound = false
  for (const url of [
    `https://robertsspaceindustries.com/en/citizens/${encodeURIComponent(handle)}`,
    `https://robertsspaceindustries.com/citizens/${encodeURIComponent(handle)}`,
  ]) {
    try {
      const res = await httpGet(url)
      // A clean 404 means RSI has no such citizen — the strongest "not a real
      // player" signal we get. Anything else non-200 is treated as uncertain.
      if (res.status === 404) { sawNotFound = true; continue }
      if (res.status !== 200 || res.body.length < 500) continue
      const html = res.body

      // Avatar — theverse CDN first (always portrait, never org logo)
      const theverse = html.match(/https:\/\/theverse\.robertsspaceindustries\.com\/[^"']+\/heap_infobox[^"']+/)
      if (theverse) profile.avatar_url = theverse[0]

      if (!profile.avatar_url) {
        const avatarM = html.match(/class="profile[^"]*"[^>]*>[\s\S]*?<img[^>]+src="([^"]+)"/)
        if (avatarM) profile.avatar_url = avatarM[1].startsWith('/') ? 'https://robertsspaceindustries.com' + avatarM[1] : avatarM[1]
      }

      // Org logo
      const orgLogoM = html.match(/class="main-org[\s\S]*?<img[^>]+src="([^"]+)"/)
      if (orgLogoM) profile.org_logo = orgLogoM[1].startsWith('/') ? 'https://robertsspaceindustries.com' + orgLogoM[1] : orgLogoM[1]

      // Org name
      const orgNameM = html.match(/class="main-org[\s\S]*?<a[^>]*>([^<]+)<\/a>/)
      if (orgNameM) profile.org_name = orgNameM[1].replace(/&nbsp;/g,'').replace(/&amp;/g,'&').replace(/&[a-z]+;/g,'').trim()

      // Label/value pairs
      const pairs = [...html.matchAll(/<p class="label">([^<]+)<\/p>\s*<p class="value[^"]*">([^<]+)<\/p>/g)]
      for (const [, label, value] of pairs) {
        const l = label.toLowerCase()
        const v = value.trim()
        if (l.includes('handle'))   profile.display  = v
        if (l.includes('enlist'))   profile.enlisted = v
        if (l.includes('locat'))    profile.location = v
        if (l.includes('spectrum') || l.includes('sid')) profile.org_sid  = v
        if (l.includes('rank'))     profile.org_rank = v
      }

      // Org name fallback from link
      if (!profile.org_name) {
        const orgLinkM = html.match(/href="\/orgs\/([A-Z0-9]+)"[^>]*>([^<]+)</)
        if (orgLinkM) { profile.org_sid = orgLinkM[1]; profile.org_name = orgLinkM[2].trim() }
      }

      profile.profile_url = url
      profile.found  = true
      profile.lookup = 'found'
      break
    } catch(e) {
      console.log(`RSI fetch failed for ${handle}: ${e.message}`)
    }
  }
  // Distinguish a confirmed "no such citizen" (clean 404 → NPC) from a lookup we
  // simply couldn't complete (network/timeout/rate-limit → uncertain, don't drop).
  if (!profile.found) profile.lookup = sawNotFound ? 'notfound' : 'error'
  return profile
}

const EXCLUDED_ORG_SIDS = new Set(['AVOCADO', 'TEST', 'COALPVP'])

async function fetchRsiAffiliations(handle) {
  const affiliations = []
  try {
    const res = await httpGet(`https://robertsspaceindustries.com/en/citizens/${encodeURIComponent(handle)}/organizations`)
    if (res.status !== 200 || res.body.length < 500) return affiliations
    const html = res.body

    // Extract org logo SIDs and logos
    const logoMatches = [...html.matchAll(/heap_infobox\/([A-Z0-9]+)-Logo[^"']*/g)]
    const logoUrls    = [...html.matchAll(/src="([^"]+heap_infobox[^"]+)"/g)]
    const nameMatches = [...html.matchAll(/class="[^"]*(?:info|title)[^"]*"[^>]*>[\s\S]*?<(?:a|h2|h3|strong)[^>]*>([^<]{2,60})<\/(?:a|h2|h3|strong)>/g)]
    const rankMatches = [...html.matchAll(/class="[^"]*rank[^"]*"[^>]*>([^<]{2,60})<\//g)]
    const sidLinks    = [...html.matchAll(/\/orgs\/([A-Z0-9]{2,12})"/g)]

    const uniqueSids = [...new Set(logoMatches.map(m => m[1]))]
    uniqueSids.forEach((sid, i) => {
      if (EXCLUDED_ORG_SIDS.has(sid)) return
      let logo = logoUrls[i] ? logoUrls[i][1] : ''
      if (logo && logo.startsWith('/')) logo = 'https://robertsspaceindustries.com' + logo
      const name = nameMatches[i] ? nameMatches[i][1].replace(/&nbsp;/g,'').replace(/&[a-z]+;/g,'').trim() : sid
      const rank = rankMatches[i] ? rankMatches[i][1].trim() : ''
      affiliations.push({ org_sid: sid, org_name: name, org_logo: logo, org_rank: rank, is_primary: i === 0 })
    })

    // Fallback to /orgs/ links if logo parsing failed
    if (!affiliations.length) {
      const seen = new Set()
      sidLinks.forEach(m => {
        const sid = m[1]
        if (seen.has(sid) || EXCLUDED_ORG_SIDS.has(sid)) return
        seen.add(sid)
        affiliations.push({ org_sid: sid, org_name: sid, org_logo: '', org_rank: '', is_primary: affiliations.length === 0 })
      })
    }
  } catch(e) {
    console.log(`Affiliations fetch failed for ${handle}: ${e.message}`)
  }
  return affiliations
}

async function pushProfile(profile) {
  try {
    // Use the exact handle casing from RSI profile page
    if (profile.display && profile.display !== profile.handle) {
      profile.handle = profile.display
    }
    await apiRequest('POST', '/api/player/profile-sync', profile)
  } catch(e) {}
}

async function pushAffiliations(handle, affiliations) {
  if (!affiliations || !affiliations.length) return
  try {
    const path = '/api/player/' + handle + '/affiliations'
    const result = await apiRequest('POST', path, { affiliations })
    console.log('pushAffiliations result for', handle, ':', JSON.stringify(result))
    return result
  } catch(e) {
    console.error('pushAffiliations failed for', handle, ':', e.message)
  }
}

async function syncAllProfiles(handles, win) {
  if (win) win.webContents.send('log', 'info', `Syncing ${handles.length} profiles from RSI…`)
  let synced = 0
  for (const handle of handles) {
    try {
      const p = await fetchRsiProfile(handle)
      // Use canonical casing from RSI
      const canonicalHandle = p.display || handle
      p.handle = canonicalHandle
      await pushProfile(p)
      // Also fetch and push org affiliations using canonical handle
      const affiliations = await fetchRsiAffiliations(canonicalHandle)
      if (affiliations.length) {
        await pushAffiliations(canonicalHandle, affiliations)
        if (win) win.webContents.send('log', 'ok', `  ✓ ${canonicalHandle} (${p.org_name || 'no org'}) + ${affiliations.length} org(s)`)
      } else {
        if (win) win.webContents.send('log', 'ok', `  ✓ ${canonicalHandle} (${p.org_name || 'no org'})`)
      }
      synced++
    } catch(e) {
      if (win) win.webContents.send('log', 'error', `  ✗ ${handle}: ${e.message}`)
    }
    await new Promise(r => setTimeout(r, 1200)) // Rate limit RSI
  }
  if (win) win.webContents.send('log', 'ok', `Profile sync complete — ${synced}/${handles.length} updated`)
  return synced
}

// ── Game.log watcher ────────────────────────────────────────────────────────────
let watcherInterval = null
let logPosition     = 0
let pendingCrime    = null
// victim(lowercased) -> pending kill entry, each with its OWN 35s timer. Keyed by
// victim so rapid kills on DIFFERENT victims within the window can't overwrite one
// another — the old single-slot design silently dropped the earlier victim's kill.
const pendingKills  = new Map()
let killCount       = 0

// ── Ship + bounty state ───────────────────────────────────────────────────────
let currentShip        = null   // ship name we're currently piloting (null once out of the seat)
let lastShip           = null   // last ship we were confirmed in — survives leaving the seat
let inShip             = false  // true when seated/piloting
let weaponInHand       = null   // personal weapon CURRENTLY in the player's hands (null once holstered)
let activeBounty       = null   // { target, missionId, missionType }
let bountyCompleted    = false
let pendingVehicleDestroy = null // { victim, ts } — vehicle destroy just before homicide

let detectedHandle = null    // auto-detected from CIG login line
let detectedGeid   = null    // auto-detected from CIG login line

// ── NPC filter ──────────────────────────────────────────────────────────────
// Real scKillboard/SC player handles never contain spaces (e.g. "Vergil_One").
// NPCs are always given "First Last" style names (e.g. "Hunter Pryor",
// "Ted Bundy") by CIG. Any name containing whitespace is an NPC, not a
// player, and should never be recorded as a kill.
function isNpcName(name) {
  return !name || /\s/.test(name.trim())
}

// ── Location tracking ──────────────────────────────────────────────────────
// Pyro's lawless zones broadcast "Entered <name> Jurisdiction" SHUD
// notifications (e.g. "Entered Rough & Ready Jurisdiction" at Ruin Station).
// Generalized so any jurisdiction gets captured, not just Ruin Station.
let currentLocation = null   // last-entered jurisdiction name, attached to fallback kills
const LOCATION_ENTER_RE = /Added notification "Entered (.+?) Jurisdiction/

// More granular than the jurisdiction name — fires on RequestLocationInventory
// (spawn/inventory access at a specific pad/landing zone), e.g. "RR_P6_LEO".
// Doesn't fire continuously, so it's a "best known" value, not live tracking —
// still meaningfully more precise than the jurisdiction alone when present.
let currentLocationCode = null
const LOCATION_CODE_RE = /RequestLocationInventory> Player\[[^\]]+\] requested inventory for Location\[([A-Za-z0-9_]+)\]/

function fmtZone() {
  if (currentLocation && currentLocationCode) return `${currentLocation} [${currentLocationCode}]`
  return currentLocation || currentLocationCode || ''
}

const CRIME_RE  = /^<(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)>.*<SHUDEvent_OnNotification> Added notification "Crime Committed:\s*(.+)/
const VICTIM_RE = /against\s+(.+?):\s*"/
const CORPSE_RE = /CSCActorCorpseUtils::PopulateItemPortForItemRecoveryEntitlement.*Item '(.+?)_\d+ - Class.*Port Name '(wep_stocked_\d+|wep_sidearm)'/

// Ship tracking
const SHIP_RE           = /SHUDEvent_OnNotification.*"You have joined channel '(.+?) : /
const SHIP_EXIT_RE      = /CVehicleMovementBase::ClearDriver: Local client node \[(\d+)\] releasing control token for '(.+?)'/

// Weapon in hand — Star Citizen logs inventory moves as:
//   <AttachmentReceived> Player[handle] Attachment[id, class, guid] Status[..] Port[..]
// Drawn  = Port[weapon_attach_hand_right];  stowed/holstered = Port[wep_stocked_N].
// NOTE: the field order is Attachment BEFORE Port, and the tag carries a '>'. An
// earlier game log-format change broke the old patterns (they looked for Port
// before Attachment, and no '>'), which is why FPS weapons stopped tracking.
// Group 1 = player handle, Group 2 = clean weapon class (e.g. gmni_smg_ballistic_01).
const WEAPON_HAND_RE    = /<AttachmentReceived> Player\[(.+?)\] Attachment\[[^,]+,\s*([^,\]]+).*?Port\[weapon_attach_hand_right\]/
const WEAPON_HOLSTER_RE = /<AttachmentReceived> Player\[(.+?)\] Attachment\[[^,]+,\s*([^,\]]+).*?Port\[wep_stocked_/

// Vehicle destruction — attacker POV (crime notification)
const VEH_DESTROY_CRIME_RE = /SHUDEvent.*"Crime Committed: Destruction of Vehicle[\s\r\n]+against (.+?):/
// Vehicle destruction — victim POV ("X committed Destruction of Vehicle against you")
const VEH_DESTROY_VICTIM_RE = /SHUDEvent.*"(.+?) committed Destruction of Vehicle against you/
// Death detection — victim POV ("X committed Murder/Homicide/etc against you")
const DEATH_RE = /SHUDEvent.*"(.+?) committed (.+?) against you/
// Actor ejected from destroyed ship (victim POV)
const ACTOR_EJECTED_RE  = /\[ActorState\] Dead.*ejected from zone '(.+?)' .+ due to previous zone being in a destroyed vehicle/

// Bounty missions — both known types, same Neutralize pattern
// MissionId comes from CommsNotifications line (most reliable)
const BOUNTY_COMMS_RE    = /CommsNotifications.*MissionType\.Bounty.*Mission: \[([^\]]+)\]/
const BOUNTY_TARGET_RE   = /SHUDEvent.*"New Objective: Neutralize ([^:]+):/
const BOUNTY_COMPLETE_RE = /MissionEnded.*mission_id ([a-f0-9\-]+).*MISSION_STATE_COMPLETED/
const BOUNTY_ENDMISSION_RE = /EndMission.*MissionId\[([^\]]+)\].*CompletionType\[Complete\]/

// Lawful vs unlawful crime types
const UNLAWFUL_CRIMES = new Set([
  'Murder', 'Homicide', 'Manslaughter', 'Assault', 'Grand Theft', 'Piracy',
  'Destruction of Property', 'Trespassing',
])
const BOUNTY_MISSION_TYPES = [
  'Pro Tem Suspect Apprehension',
  'Suspect Apprehension Certification',
]

// Login line — CIG writes this on every game start, contains handle + GEID + accountId
const LOGIN_RE       = /AccountLoginCharacterStatus_Character.*?geid\s+(\d+).*?accountId\s+(\d+).*?name\s+([A-Za-z0-9_\-]+)/i
// AccountLoginCharacterStatus_Character's "name" field can be a stale/cached
// account record that doesn't match the actual live character (e.g. after a
// handle rename that hasn't fully propagated through all CIG services). The
// "Legacy login response" line gives the real live handle that actually
// shows up in ProcessHit lines — always trust this one over the above when
// both are present.
const LEGACY_LOGIN_RE = /<Legacy login response>.*?Handle\[([^\]]+)\]/

function startWatcher(logPath, win) {
  stopWatcher()
  if (!fs.existsSync(logPath)) {
    win.webContents.send('log', 'error', `Game.log not found: ${logPath}`)
    win.webContents.send('status', 'error', 'Game.log not found — check the path in Settings')
    return false
  }
  logPosition  = fs.statSync(logPath).size
  pendingCrime = null
  currentShip  = null
  lastShip     = null
  inShip       = false
  weaponInHand = null
  activeBounty = null
  bountyCompleted      = false
  pendingVehicleDestroy = null
  detectedHandle = null
  detectedGeid   = null
  currentLocation = null
  currentLocationCode = null

  win.webContents.send('log',    'ok', 'Watching Game.log…')
  win.webContents.send('status', 'ok', 'Tracking active')

  watcherInterval = setInterval(() => {
    try {
      if (!fs.existsSync(logPath)) return
      const stat = fs.statSync(logPath)
      if (stat.size < logPosition) { logPosition = 0; pendingCrime = null }
      if (stat.size === logPosition) return
      const fd  = fs.openSync(logPath, 'r')
      const len = stat.size - logPosition
      const buf = Buffer.alloc(len)
      fs.readSync(fd, buf, 0, len, logPosition)
      fs.closeSync(fd)
      logPosition = stat.size
      const lines = buf.toString('utf8').split('\n')
      for (const line of lines) {
          // ── CIG login line — auto-detect player identity ──────────────
          const lm = LOGIN_RE.exec(line)
          if (lm && !detectedGeid) {
            detectedGeid   = lm[1]
            detectedHandle = lm[3]
            win.webContents.send('log', 'session', `◈ Session: ${detectedHandle} (GEID:${detectedGeid})`)
          }
          // "Legacy login response" carries the actual live handle and
          // always overrides whatever AccountLoginCharacterStatus_Character
          // set — that field can be stale/mismatched (see LEGACY_LOGIN_RE
          // comment above). This is the name that will actually appear as
          // attacker in ProcessHit lines, so it's what fallback detection
          // and attribution both need to match against.
          const llm = LEGACY_LOGIN_RE.exec(line)
          if (llm && llm[1] !== detectedHandle) {
            const prev = detectedHandle
            detectedHandle = llm[1]
            win.webContents.send('log', 'session', prev
              ? `◈ Live handle corrected: ${prev} → ${detectedHandle}`
              : `◈ Session: ${detectedHandle}`)
          }
          if (lm || llm) {
            const cfg2 = loadConfig()
            if (!cfg2.attacker_handle && detectedHandle) {
              cfg2.attacker_handle = detectedHandle
              saveConfig(cfg2)
              win.webContents.send('log', 'ok', `  ✓ Auto-set handle to ${detectedHandle}`)
            }
          }

          // ── Jurisdiction/location detection ────────────────────────────
          // Pyro's lawless zones broadcast "Entered <name> Jurisdiction" —
          // this is the only reliable location signal Game.log exposes.
          // Attached to fallback kill forensics below so kills carry a
          // location even when no Crime Committed line exists.
          const locm = LOCATION_ENTER_RE.exec(line)
          if (locm) {
            const newLoc = locm[1].trim()
            if (newLoc !== currentLocation) {
              currentLocation = newLoc
              win.webContents.send('log', 'info', `📍 Entered ${currentLocation} Jurisdiction`)
            }
          }
          const lcm = LOCATION_CODE_RE.exec(line)
          if (lcm && lcm[1] !== currentLocationCode) {
            currentLocationCode = lcm[1]
            win.webContents.send('log', 'info', `📍 Location code: ${currentLocationCode}`)
          }


          // ── Ship entry / exit ────────────────────────────────────────────
          const shipM = SHIP_RE.exec(line)
          if (shipM) {
            currentShip = shipM[1].trim()
            lastShip    = currentShip
            inShip      = true
            win.webContents.send('log', 'info', `🚀 In ship: ${currentShip}`)
          }
          const exitM = SHIP_EXIT_RE.exec(line)
          if (exitM) {
            // Only clear if this is the local player's GEID
            if (detectedGeid && exitM[1] === detectedGeid) {
              inShip      = false
              // SC never re-logs the ship channel join when you climb back into
              // the SAME ship, so we can't see a re-entry. Keep crediting kills to
              // this ship (as flight) whenever the player's hands are EMPTY — a kill
              // with no weapon in hand means they got back in the seat. The moment
              // a weapon is in their hands, they're on foot and kills are FPS.
              if (currentShip) lastShip = currentShip
              win.webContents.send('log', 'info', `🛬 Left seat: ${currentShip || lastShip || '?'} — counted as flight while hands are empty`)
              currentShip = null
            }
          }

          // ── Weapon in hand tracking ───────────────────────────────────────
          const weaponM = WEAPON_HAND_RE.exec(line)
          if (weaponM && weaponM[1] === (detectedHandle || '')) {
            const w = weaponM[2].trim()
            if (w !== weaponInHand) {
              weaponInHand = w
              win.webContents.send('log', 'info', `🔫 Weapon ready: ${fmtWeapon(weaponInHand) || weaponInHand}`)
            }
          }
          const holsterM = WEAPON_HOLSTER_RE.exec(line)
          if (holsterM && holsterM[1] === (detectedHandle || '') && holsterM[2].trim() === weaponInHand) {
            win.webContents.send('log', 'info', `🔫 Holstered ${fmtWeapon(weaponInHand) || weaponInHand}`)
            weaponInHand = null
          }

          // ── Vehicle destruction — attacker POV ────────────────────────────
          // Crime Committed: Destruction of Vehicle against X
          const vehCrimeM = VEH_DESTROY_CRIME_RE.exec(line)
          if (vehCrimeM) {
            const tsM = line.match(/^<([\d\-T:.Z]+)>/)
            pendingVehicleDestroy = { victim: vehCrimeM[1].trim(), ts: tsM ? tsM[1] : null, ship: currentShip }
            win.webContents.send('log', 'info', `💥 Vehicle destroyed: ${vehCrimeM[1].trim()}`)
          }

          // ── Vehicle destruction — victim POV ──────────────────────────────
          const vehVictimM = VEH_DESTROY_VICTIM_RE.exec(line)
          if (vehVictimM) {
            const tsM = line.match(/^<([\d\-T:.Z]+)>/)
            win.webContents.send('log', 'warn', `💥 My ship destroyed by: ${vehVictimM[1].trim()}`)
          }


          // ── Death detection — victim POV ─────────────────────────────────
          // "X committed Murder/Homicide/etc against you" — fires via CIG's
          // standard HUD notification, no user.cfg needed.
          // Delayed 45s so the killer's own tracker (if they have one) gets
          // first right of refusal to post a fuller attacker-side record.
          // Backend dedupes crime_victim against attacker-side within 30s.
          const deathM = DEATH_RE.exec(line)
          if (deathM) {
            const killer = deathM[1].trim()
            const crime  = deathM[2].trim()
            const tsM    = line.match(/^<([\d\-T:.Z]+)>/)
            const ts     = tsM ? tsM[1] : new Date().toISOString()
            const cfg    = loadConfig()
            const me     = cfg.attacker_handle || detectedHandle || ''
            if (me && KILL_CRIMES.has(crime) && !isNpcName(killer)) {
              // Capture method now — inShip state may change during the 45s delay.
              // A death counts as "ship" if we were piloting or the crime is a
              // vehicle destruction; otherwise it's an on-foot (FPS) death.
              const deathMethod = (inShip || /vehicle|destruction of vehicle/i.test(crime)) ? 'ship' : 'fps'
              const deathLoc = fmtZone() || ''
              win.webContents.send('log', 'warn', `💀 Killed by ${killer} (${crime}) — reporting in 45s`)
              setTimeout(() => handleDeath(crime, killer, me, ts, win, deathMethod, deathLoc), 45000)
            }
          }

          // ── Bounty detection ──────────────────────────────────────────────
          // Step 1: Grab MissionId from CommsNotifications bounty line
          const bountyCommsM = BOUNTY_COMMS_RE.exec(line)
          if (bountyCommsM) {
            const missionId = bountyCommsM[1]
            if (!activeBounty) {
              activeBounty = { target: null, missionId, missionType: 'bounty' }
            } else {
              activeBounty.missionId = missionId
            }
            bountyCompleted = false
          }

          // Step 2: Extract target handle from Neutralize line
          const bountyTargetM = BOUNTY_TARGET_RE.exec(line)
          if (bountyTargetM) {
            const target = bountyTargetM[1].trim()
            if (activeBounty) {
              activeBounty.target = target
            } else {
              activeBounty = { target, missionId: null, missionType: 'bounty' }
            }
            win.webContents.send('log', 'info', `🎯 Bounty target: ${target}`)
          }

          // Step 3: Mission completed — fire kill (guard against double fire)
          const bountyCompleteM  = BOUNTY_COMPLETE_RE.exec(line)
          const bountyEndM       = BOUNTY_ENDMISSION_RE.exec(line)
          const completedMissionId = (bountyCompleteM && bountyCompleteM[1]) ||
                                     (bountyEndM && bountyEndM[1])
          if (completedMissionId && activeBounty && !bountyCompleted &&
              (!activeBounty.missionId || activeBounty.missionId === completedMissionId)) {
            if (activeBounty.target) {
              bountyCompleted = true  // set immediately to block duplicate lines
              const tsM = line.match(/^<([\d\-T:.Z]+)>/)
              const ts  = tsM ? tsM[1] : new Date().toISOString()
              win.webContents.send('log', 'ok', `✓ Bounty completed: ${activeBounty.target}`)
              handleKill('Pro Tem Bounty', activeBounty.target, ts, null, win,
                { ship: currentShip, bounty: { ...activeBounty } })
              activeBounty = null  // clear so duplicate MissionId can't re-trigger
            } else {
              win.webContents.send('log', 'warn', `⚠ Bounty completed but no target identified`)
            }
          }

          // ── Stanton kill detection ────────────────────────────────────
          const cm = CRIME_RE.exec(line)
          if (cm) { pendingCrime = { ts: cm[1], crime: cm[2].trim().replace(/"$/, '').trim() }; continue }
          if (pendingCrime) {
            const vm = VICTIM_RE.exec(line)
            if (vm) {
              const { ts, crime } = pendingCrime
              const victim = vm[1].trim()
              pendingCrime = null
              if (isNpcName(victim)) {
                win.webContents.send('log', 'info', `↷ Skipping NPC victim "${victim}" (not a player)`)
              } else if (KILL_CRIMES.has(crime)) {
                // Skip if this victim was already handled as a bounty kill
                if (bountyCompleted && activeBounty === null) {
                  win.webContents.send('log', 'info', `↷ Skipping crime kill — already posted as bounty`)
                } else {
                const kill = { crime, victim, ts }
                // A "Destruction of Vehicle" crime is definitive proof this was a
                // ship/vehicle kill — record it so the near-simultaneous homicide
                // line against the same victim is also credited as flight, even if
                // the player drew a weapon at some point after leaving the seat.
                if (/destruction of vehicle/i.test(crime)) {
                  pendingVehicleDestroy = { victim, ts, ship: currentShip || lastShip }
                }
                // ── Ship vs FPS decided NOW (state can drift during the 35s wait) ──
                // An FPS kill REQUIRES a weapon in the player's hands. Flight if:
                // seated; OR a vehicle-destruction kill; OR the hands are empty and
                // the player has been in a ship — meaning they climbed back into it
                // (SC never re-logs the channel join, so we can't see the re-entry).
                // Credited to the last ship they were in.
                const isVehicleKill = /destruction of vehicle/i.test(crime) ||
                  (pendingVehicleDestroy && pendingVehicleDestroy.victim.toLowerCase() === victim.toLowerCase())
                const flightByReentry = !inShip && !weaponInHand && !!lastShip
                const isShipKill = inShip || isVehicleKill || flightByReentry
                const killShip   = isShipKill ? (currentShip || lastShip || (pendingVehicleDestroy && pendingVehicleDestroy.ship) || '') : ''
                // Capture the weapon the attacker had drawn AT kill time — for an
                // on-foot kill this IS the FPS weapon used. Null for a ship kill.
                const handWeapon = isShipKill ? null : weaponInHand
                const vkey = victim.toLowerCase()
                const prevPending = pendingKills.get(vkey)
                if (prevPending && prevPending.timer) clearTimeout(prevPending.timer) // same victim re-reported → replace, keep one
                const entry = { ...kill, weapon: null, handWeapon,
                  method: isShipKill ? 'ship' : 'fps', ship: killShip, bounty: activeBounty }
                entry.timer = setTimeout(() => {
                  pendingKills.delete(vkey)
                  handleKill(entry.crime, entry.victim, entry.ts,
                    entry.handWeapon || entry.weapon, win,
                    { ship: entry.ship, method: entry.method, bounty: entry.bounty })
                }, 35000)
                pendingKills.set(vkey, entry)
                const isBounty = activeBounty && activeBounty.target &&
                  activeBounty.target.toLowerCase() === victim.toLowerCase()
                const killTypeLabel = isBounty ? '🎯 BOUNTY' : UNLAWFUL_CRIMES.has(crime) ? '🔴 UNLAWFUL' : '🔵 LAWFUL'
                win.webContents.send('log', 'kill', `⚔ ${killTypeLabel} KILL — ${crime} → ${victim} (waiting for weapon…)`)
                } // end else (not already posted as bounty)
              }
            } else if (line.trim()) { pendingCrime = null }
          }
          if (pendingKills.size) {
            const cm2 = CORPSE_RE.exec(line)
            if (cm2) {
              // Attach the corpse-recovered weapon to the OLDEST pending kill still
              // missing a weapon, and submit it early (before its 35s timeout).
              for (const [vkey, entry] of pendingKills) {
                if (!entry.weapon) {
                  entry.weapon = cm2[1]
                  clearTimeout(entry.timer)
                  pendingKills.delete(vkey)
                  // Prefer the attacker's in-hand weapon (the actual kill weapon);
                  // fall back to the corpse-recovered weapon if none was tracked.
                  handleKill(entry.crime, entry.victim, entry.ts,
                    entry.handWeapon || entry.weapon, win,
                    { ship: entry.ship, method: entry.method, bounty: entry.bounty })
                  break
                }
              }
            }
          }


          // ── Fallback forensics: ProcessHit damage tracking ─────────────
          // Only fires for hits dealt BY the local player. Used to detect
        }
    } catch(e) {}
  }, 500)
  return true
}

function stopWatcher() {
  if (watcherInterval) { clearInterval(watcherInterval); watcherInterval = null }
}


// ── IPC handlers ─────────────────────────────────────────────────────────────────

function fmtWeapon(raw) {
  if (!raw) return null
  const WEAPON_MAP = {
    // ── FPS weapons — from objectcatalog.json (authoritative) ──────────────
    // Klaus & Werner
    'klwe_rifle_energy_01': 'Gallant Rifle',
    'klwe_smg_energy_01': 'Lumin V SMG',
    'klwe_pistol_energy_01': 'Arclight Pistol',
    'klwe_sniper_energy_01': 'Arrowhead Sniper Rifle',
    'klwe_lmg_energy_01': 'Demeco LMG',
    // Gemini
    'gmni_shotgun_ballistic_01': 'R97 Shotgun',
    'gmni_sniper_ballistic_01': 'A03 Sniper Rifle',
    'gmni_smg_ballistic_01': 'C54 SMG',
    'gmni_lmg_ballistic_01': 'F55 LMG',
    'gmni_pistol_ballistic_01': 'LH86 Pistol',
    'gmni_rifle_ballistic_01': 'S71 Rifle',
    // Volt
    'volt_rifle_energy_01': 'Parallax Rifle',
    'volt_shotgun_energy_01': 'Prism Shotgun',
    'volt_smg_energy_01': 'Quartz SMG',
    // Apocalypse Arms
    'apar_special_ballistic_02': 'Animus Missile Launcher',
    'apar_special_ballistic_01': 'Scourge Railgun',
    // Kastak Arms
    'ksar_pistol_ballistic_01': 'Coda Pistol',
    'ksar_smg_energy_01': 'Custodian SMG',
    'ksar_shotgun_energy_01': 'Devastator Shotgun',
    'ksar_rifle_energy_01': 'Karna Rifle',
    'ksar_shotgun_ballistic_01': 'Ravager-212 Shotgun',
    'ksar_sniper_ballistic_01': 'Scalpel Sniper Rifle',
    // Lightning Bolt Co.
    'lbco_pistol_energy_01': 'Yubarev Pistol',
    'lbco_sniper_energy_01': 'Atzkav Sniper Rifle',
    // Hedeby Gunworks
    'hdgw_pistol_ballistic_01': 'Salvo Frag Pistol',
    // Behring
    'behr_shotgun_ballistic_01': 'BR-2 Shotgun',
    'behr_lmg_ballistic_01': 'FS-9 LMG',
    'behr_glauncher_ballistic_01': 'GP-33 MOD Grenade Launcher',
    'behr_rifle_ballistic_01': 'P4-AR Rifle',
    'behr_sniper_ballistic_01': 'P6-LR Sniper Rifle',
    'behr_rifle_ballistic_02': 'P8-AR Rifle',
    'behr_smg_ballistic_01': 'P8-SC SMG',
    'behr_pistol_ballistic_01': 'S-38 Pistol',
    // Misc / generic
    'sasu_pistol_toy_01': 'WowBlast Toy Pistol',
    'none_shotgun_ballistic_01': 'Deadrig Shotgun',
    'none_smg_energy_01': 'Ripper SMG',
    'utfl_melee_01': 'FSK-8 Combat Knife',
    'none_melee_01': 'Prison Shiv',
    // ── Extras not in the catalog (kept from the previous map) ─────────────
    'none_lmg_ballistic_01': 'Hammerbolt',
    'utfl_crossbow_ballistic_01': 'Devastator',
    'klwe_rifle_laser_01': 'Klaus & Werner Rifle',
    'arst_shotgun_ballistic_01': 'Devastator Shotgun',
    'gyrs_knife_01': 'Knife',
    'banu_melee_04': 'Banu Staff',
    'crlf_medgun_01': 'Medpen',
  }
  for (const [key, label] of Object.entries(WEAPON_MAP)) {
    if (raw.toLowerCase().startsWith(key)) return label
  }
  return raw.replace(/_\d+$/, '').replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
}

function cleanShipName(raw) {
  if (!raw) return ''
  const SHIPS = {
    'AEGS_AVENGER': "Aegis Avenger",     'AEGS_AVENGER_STALKER': "Avenger Stalker",     'AEGS_AVENGER_TITAN': "Avenger Titan",
    'AEGS_AVENGER_TITAN_RENEGADE': "Avenger Titan Renegade",     'AEGS_AVENGER_WARLOCK': "Avenger Warlock",     'AEGS_ECLIPSE': "Eclipse",
    'AEGS_GLADIUS': "Gladius",     'AEGS_GLADIUS_DUNLEVY': "Gladius Dunlevy",     'AEGS_GLADIUS_PIR': "Gladius Pirate",
    'AEGS_GLADIUS_VALIANT': "Gladius Valiant",     'AEGS_HAMMERHEAD': "Hammerhead",     'AEGS_IDRIS': "Aegis Idris",
    'AEGS_IDRIS_M': "Idris M",     'AEGS_IDRIS_P': "Idris P",     'AEGS_NAUTILUS': "Aegis Nautilus",
    'AEGS_RECLAIMER': "Reclaimer",     'AEGS_REDEEMER': "Redeemer",     'AEGS_RETALIATOR': "Retaliator",
    'AEGS_SABRE': "Sabre",     'AEGS_SABRE_COMET': "Sabre Comet",     'AEGS_SABRE_FIREBIRD': "Sabre Firebird",
    'AEGS_SABRE_PEREGRINE': "Sabre Peregrine",     'AEGS_SABRE_RAVEN': "Sabre Raven",     'AEGS_TITAN': "Aegis Titan",
    'AEGS_VANGUARD': "Aegis Vanguard",     'AEGS_VANGUARD_HARBINGER': "Vanguard Harbinger",     'AEGS_VANGUARD_HOPLITE': "Vanguard Hoplite",
    'AEGS_VANGUARD_SENTINEL': "Vanguard Sentinel",     'AEGS_VANGUARD_WARDEN': "Vanguard Warden",     'ANVL_ARROW': "Arrow",
    'ANVL_ASGARD': "Asgard",     'ANVL_BALLISTA': "Ballista",     'ANVL_BALLISTA_DUNESTALKER': "Ballista Dunestalker",
    'ANVL_BALLISTA_SNOWBLIND': "Ballista Snowblind",     'ANVL_C8R_PISCES': "C8R Pisces Rescue",     'ANVL_C8X_PISCES': "C8X Pisces Expidition",
    'ANVL_C8_PISCES': "C8 Pisces",     'ANVL_CARRACK': "Carrack",     'ANVL_CARRACK_EXPEDITION': "Carrack Expedition",
    'ANVL_CENTURION': "Centurion",     'ANVL_CRUSADER': "Anvil Crusader",     'ANVL_F7A': "Anvil F7A Hornet",
    'ANVL_F7C': "Anvil Hornet",     'ANVL_GLADIATOR': "Gladiator",     'ANVL_HAWK': "Hawk",
    'ANVL_HORNET_F7A_MK1': "Military Hornet Mk1",     'ANVL_HORNET_F7A_MK2': "Military Hornet Mk2",     'ANVL_HORNET_F7C': "Hornet Base Mk1",
    'ANVL_HORNET_F7CM': "Super Hornet Mk1",     'ANVL_HORNET_F7CM_HEARTSEEKER': "Super Hornet Heartseeker Mk1",     'ANVL_HORNET_F7CM_MK2': "Super Hornet Mk2",
    'ANVL_HORNET_F7CM_MK2_HEARTSEEKER': "Super Hornet Heartseeker Mk2",     'ANVL_HORNET_F7CR': "Hornet Tracker Mk1",     'ANVL_HORNET_F7CR_MK2': "Hornet Tracker Mk2",
    'ANVL_HORNET_F7CS': "Hornet Ghost Mk1",     'ANVL_HORNET_F7CS_MK2': "Hornet Ghost Mk2",     'ANVL_HORNET_F7C_MK2': "Hornet Base Mk2",
    'ANVL_HORNET_F7C_WILDFIRE': "Hornet Wildfire Mk1",     'ANVL_HURRICANE': "Hurricane",     'ANVL_LIBERATOR': "Anvil Liberator",
    'ANVL_LIGHTNING_F8C': "Lightning F8C",     'ANVL_LIGHTNING_F8C_PLAT': "Lightning F8C Whale Wdition",     'ANVL_SPARTAN': "Spartan",
    'ANVL_TERRAPIN': "Terrapin",     'ANVL_TERRAPIN_MEDIC': "Terrapin Medic",     'ANVL_VALKYRIE': "Valkyrie",
    'ARGO_ATLS': "ATLS",     'ARGO_ATLS_IKTI': "ATLS Ikti",     'ARGO_ATLS_IKTI_ARGOS': "ATLS Ikti Rad",
    'ARGO_CSV_CARGO': "CSV-SM",     'ARGO_MOLE': "Mole",     'ARGO_MPUV': "MPUV Cargo",
    'ARGO_MPUV_1T': "MPUV Tractor",     'ARGO_MPUV_TRANSPORT': "MPUV Personnel",     'ARGO_RAFT': "Raft",
    'ARGO_SRV': "SRV",     'BANU_DEFENDER': "Defender",     'BANU_MERCHANTMAN': "Banu Merchantman",
    'CNOU_HOVERQUAD': "HoverQuad",     'CNOU_MUSTANG': "Consolidated Mustang",     'CNOU_MUSTANG_ALPHA': "Mustang Alpha",
    'CNOU_MUSTANG_ALPHA_DELTA': "Mustang Delta",     'CNOU_MUSTANG_ALPHA_GAMMA': "Mustang Gamma",     'CNOU_MUSTANG_BETA': "Mustang Beta",
    'CNOU_MUSTANG_OMEGA': "Mustang Omega",     'CNOU_NOMAD': "Nomad",     'CRUS_INTREPID': "Intrepid",
    'CRUS_SPIRIT_A1': "A1 Spirit",     'CRUS_SPIRIT_C1': "C1 Spirit",     'CRUS_STARFIGHTER_INFERNO': "Ares Starfighter Inferno",
    'CRUS_STARFIGHTER_ION': "Ares Starfighter Ion",     'CRUS_STARLIFTER_A2': "A2 Hercules Starlifter",     'CRUS_STARLIFTER_C2': "C2 Hercules Starlifter",
    'CRUS_STARLIFTER_M2': "M2 Hercules Starlifter",     'CRUS_STAR_RUNNER': "Mercury Star Runner",     'DRAK_BUCCANEER': "Buccaneer",
    'DRAK_CATERPILLAR': "Caterpillar",     'DRAK_CATERPILLAR_PIRATE': "Caterpillar Pirate",     'DRAK_CORSAIR': "Corsair",
    'DRAK_CUTLASS': "Drake Cutlass",     'DRAK_CUTLASS_BLACK': "Cutlass Black",     'DRAK_CUTLASS_BLUE': "Cutlass Blue",
    'DRAK_CUTLASS_RED': "Cutlass Red",     'DRAK_CUTLASS_STEEL': "Cutlass Steel",     'DRAK_CUTTER': "Cutter",
    'DRAK_CUTTER_RAMBLER': "Cutter Rambler",     'DRAK_CUTTER_SCOUT': "Cutter Scout",     'DRAK_DRAGONFLY': "Dragonfly",
    'DRAK_DRAGONFLY_PINK': "Dragonfly Star Kitten",     'DRAK_DRAGONFLY_YELLOW': "Dragonfly Yellowjacket",     'DRAK_GOLEM': "Golem",
    'DRAK_HERALD': "Herald",     'DRAK_KRAKEN': "Drake Kraken",     'DRAK_MULE': "Mule",
    'DRAK_VULTURE': "Vulture",     'ESPR_PROWLER': "Prowler",     'ESPR_PROWLER_UTILITY': "Prowler Utility",
    'ESPR_TALON': "Talon",     'ESPR_TALON_SHRIKE': "Talon Shrike",     'GAMA_SYULEN': "Syulen",
    'GAMA_TOXICAT': "Gatac Railen",     'GRIN_MTC': "MTC",     'GRIN_PTV': "PTV",
    'GRIN_ROC': "ROC",     'GRIN_ROC_DS': "ROC-DS",     'GRIN_STV': "STV",
    'KRIG_P52': "Kruger P-52",     'KRIG_P52_MERLIN': "P-52 Merlin",     'KRIG_P72': "Kruger P-72",
    'KRIG_P72_ARCHIMEDES': "Kruger P-72 Archimedes",     'KRIG_P72_ARCHIMEDES_EMERALD': "P-72 Archimedes Emerald",     'MISC_FORTUNE': "Miscfortune",
    'MISC_FREELANCER': "Freelancer",     'MISC_FREELANCER_DUR': "Freelancer DUR",     'MISC_FREELANCER_MAX': "Freelancer Max",
    'MISC_FREELANCER_MIS': "Freelancer MIS",     'MISC_FURY': "Fury",     'MISC_FURY_LX': "Fury LX",
    'MISC_FURY_MIRU': "Fury LX",     'MISC_HULL': "MISC Hull",     'MISC_HULL_A': "Hull A",
    'MISC_HULL_C': "Hull C",     'MISC_PROSPECTOR': "Prospector",     'MISC_RAZOR': "Razor",
    'MISC_RAZOR_EX': "Razor EX",     'MISC_RAZOR_LX': "Razor LX",     'MISC_RELIANT': "Reliant Kore",
    'MISC_RELIANT_MAKO': "Reliant Mako",     'MISC_RELIANT_SEN': "Relaint Sen",     'MISC_RELIANT_TANA': "Reliant Tana",
    'MISC_STARFARER': "Starfarer",     'MISC_STARFARER_GEMINI': "Starfarer Gemini",     'MISC_STARLANCER': "MISC Starlancer",
    'MISC_STARLANCER_MAX': "Starlancer Max",     'MISC_STARLANCER_TAC': "Starlancer Tac",     'MRAI_FURY': "Mirai Fury",
    'MRAI_GUARDIAN': "Guardian",     'MRAI_GUARDIAN_MX': "Guardian MX",     'MRAI_GUARDIAN_QI': "Guardian QI",
    'MRAI_PULSE': "Pulse",     'MRAI_PULSE_LX': "Pulse LX",     'ORIG_100I': "100i",
    'ORIG_125A': "125a",     'ORIG_135C': "135c",     'ORIG_300I': "300i",
    'ORIG_315P': "315p",     'ORIG_325A': "325a",     'ORIG_350R': "350r",
    'ORIG_400I': "400i",     'ORIG_600I': "600i",     'ORIG_600I_EXECUTIVE_EDITION': "600i Whale Edition",
    'ORIG_600I_TOURING': "600i Touring",     'ORIG_85X': "85x Limited",     'ORIG_890JUMP': "890j",
    'ORIG_M50': "M50 Interceptor",     'ORIG_M80': "Origin M80",     'ORIG_X1': "X1",
    'ORIG_X1_FORCE': "X1 Force",     'ORIG_X1_VELOCITY': "X1 Velocity",     'RSI_AURORA': "RSI Aurora",
    'RSI_AURORA_CL': "Aurora CL",     'RSI_AURORA_ES': "Aurora ES",     'RSI_AURORA_LN': "Aurora LN",
    'RSI_AURORA_LX': "Aurora LX",     'RSI_AURORA_MR': "Aurora MR",     'RSI_CONSTELLATION': "RSI Constellation",
    'RSI_CONSTELLATION_ANDROMEDA': "Constellation Andromeda",     'RSI_CONSTELLATION_AQUILA': "Constellation Aquila",     'RSI_CONSTELLATION_PHOENIX': "Constellation Phoenix",
    'RSI_CONSTELLATION_PHOENIX_EMERALD': "Constellation Phoenix Emerald",     'RSI_CONSTELLATION_TAURUS': "Constellation Taurus",     'RSI_LYNX': "Lynx",
    'RSI_MANTIS': "Mantis",     'RSI_PERSEUS': "RSI Perseus",     'RSI_POLARIS': "Polaris",
    'RSI_SCORPIUS': "Scorpius",     'RSI_SCORPIUS_ANTARES': "Scorpius Antares",     'RSI_URSA': "RSI Ursa",
    'RSI_URSA_MEDIVAC': "Ursa Medivac",     'RSI_URSA_ROVER': "Ursa",     'RSI_URSA_ROVER_EMERALD': "Ursa Fortuna",
    'RSI_ZEUS': "RSI Zeus",     'RSI_ZEUS_CL': "Zeuc Mk2 CL",     'RSI_ZEUS_ES': "Zeus Mk2 ES",
    'TMBL_CYCLONE': "Cyclone",     'TMBL_CYCLONE_AA': "Cyclone AA",     'TMBL_CYCLONE_MT': "Cyclone MT",
    'TMBL_CYCLONE_RC': "Cyclone RC",     'TMBL_CYCLONE_RN': "Cyclone RN",     'TMBL_CYCLONE_TR': "Cyclone TR",
    'TMBL_NOVA': "Nova",     'TMBL_RANGER': "Tumbril Ranger",     'TMBL_STORM': "Storm",
    'TMBL_STORM_AA': "Storm AA",     'VNCL_BLADE': "Blade",     'VNCL_GLAIVE': "Glaive",
    'VNCL_SCYTHE': "Scythe",     'XIAN_NOX': "Nox",     'XIAN_SCOUT': "Khartu-al",
    'XNAA_NURO': "Xian Nuro",     'XNAA_PUCK': "Xian Puck",     'XNAA_SANTOKYAI': "San'tok.yai",
  }
  const key = raw.toUpperCase().replace(/^VEH_/, '').replace(/_PU$/, '').replace(/_\d+$/, '')
  if (SHIPS[key]) return SHIPS[key]
  return raw.replace(/^VEH_/i, '').replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()).trim()
}

async function handleKill(crime, victim, ts, weapon, win, ctx = {}) {
  // Safety net — every kill path funnels through here.
  // NPCs always have "First Last" style names with a space.
  if (isNpcName(victim)) {
    win.webContents.send('log', 'info', `↷ Skipping NPC victim "${victim}" (not a player)`)
    return
  }

  // ── SC process check ─────────────────────────────────────────────────────
  // Star Citizen must be running when a kill is credited. Prevents fake
  // submissions by replaying an old Game.log without the game actually open.
  const scRunning = await isScRunning()
  if (!scRunning) {
    win.webContents.send('log', 'warn', `  ↷ Kill vs ${victim} skipped — Star Citizen not detected`)
    return
  }

  const cfg = loadConfig()
  const attacker    = cfg.attacker_handle || 'Unknown'
  const personalWebhook = cfg.personal_enabled ? cfg.personal_webhook : ''
  const weaponLabel = weapon ? fmtWeapon(weapon) : null
  const ship        = cleanShipName(ctx.ship || currentShip || lastShip || '')
  const bounty      = ctx.bounty || activeBounty || null
  const zone        = ctx.location || fmtZone() || ''

  // ── Kill method: ship vs FPS ──────────────────────────────────────────────
  const wasVehicleKill = pendingVehicleDestroy &&
    pendingVehicleDestroy.victim.toLowerCase() === victim.toLowerCase() &&
    (Date.now() - new Date(pendingVehicleDestroy.ts || 0).getTime()) < 10000
  // Prefer the method captured at detection time (ctx.method). Fall back to a
  // live computation for callers that don't pass one (e.g. bounty kills): seated,
  // a vehicle destroy, or empty hands + a known last ship all count as flight.
  const flightByReentry = !inShip && !weaponInHand && !!lastShip
  const killMethod = ctx.method || ((inShip || wasVehicleKill || flightByReentry) ? 'ship' : 'fps')
  if (wasVehicleKill) pendingVehicleDestroy = null

  // ── Kill type: bounty / lawful / unlawful ─────────────────────────────────
  const isBountyKill  = bounty && bounty.target &&
    bounty.target.toLowerCase() === victim.toLowerCase()
  const isUnlawful    = UNLAWFUL_CRIMES.has(crime)
  const killType      = isBountyKill ? 'bounty' : isUnlawful ? 'unlawful' : 'lawful'
  const killTypeLabel = isBountyKill ? '🎯 BOUNTY' : isUnlawful ? '🔴 UNLAWFUL' : '🔵 LAWFUL'
  const methodLabel   = killMethod === 'ship' ? '🚀' : '🔫'

  win.webContents.send('log', 'kill',
    `⚔ ${killTypeLabel} ${methodLabel} — ${crime} → ${victim}${weaponLabel ? ' [' + weaponLabel + ']' : ''}${ship ? ' · ' + ship : ''}`)
  win.webContents.send('log', 'info', '  Fetching RSI profiles…')

  const [ap, vp] = await Promise.all([
    fetchRsiProfile(attacker).catch(() => ({ handle: attacker })),
    fetchRsiProfile(victim).catch(() => ({ handle: victim })),
  ])

  // ── NPC guard ──────────────────────────────────────────────────────────────
  // Real players ALWAYS have an RSI profile; NPCs never do. This catches NPCs the
  // whitespace filter misses — e.g. single-token names in the Russian client, or
  // bounty targets like "Targets". Only skip on a CONFIRMED 404 (vp.lookup ===
  // 'notfound'); a transient lookup failure ('error') still posts, so a brief RSI
  // outage can't silently drop real kills.
  if (vp && vp.lookup === 'notfound') {
    win.webContents.send('log', 'info', `↷ Skipping "${victim}" — no RSI profile found (NPC, not a real player)`)
    return
  }

  try {
    const result = await apiRequest('POST', '/kill', {
      crime_type: crime, victim, attacker, timestamp: ts,
      personal_webhook: personalWebhook, weapon: weaponLabel,
      kill_type:         killType,
      kill_method:       killMethod,
      ship_attacker:     ship,
      zone:              zone,
      location:          zone,
      bounty_target:     bounty?.target || '',
      bounty_mission_id: bounty?.missionId || '',
      att_avatar:   ap.avatar_url  || '', att_org_logo: ap.org_logo   || '',
      att_org_name: ap.org_name    || '', att_org_sid:  ap.org_sid    || '',
      att_org_rank: ap.org_rank    || '', att_enlisted: ap.enlisted   || '',
      att_location: ap.location    || '',
      vic_avatar:   vp.avatar_url  || '', vic_org_logo: vp.org_logo   || '',
      vic_org_name: vp.org_name    || '', vic_org_sid:  vp.org_sid    || '',
      vic_org_rank: vp.org_rank    || '', vic_enlisted: vp.enlisted   || '',
      vic_location: vp.location    || '',
    })
    if (result.ok) {
      killCount++
      win.webContents.send('kill-count', killCount)
      win.webContents.send('last-kill-handle', attacker)
      win.webContents.send('log', 'ok', `  ✓ Posted to Discord`)
      if (isBountyKill) { activeBounty = null; bountyCompleted = false }
    } else {
      const errDetail = result.error || result.message || JSON.stringify(result)
      win.webContents.send('log', 'error', `  ✗ Failed: ${errDetail}`)
    }
  } catch(e) {
    win.webContents.send('log', 'error', `  ✗ Network error: ${e.message}`)
  }
}

// ── Death submission (victim POV) ────────────────────────────────────────────
async function handleDeath(crime, killer, me, ts, win, killMethod = 'fps', location = '') {
  try {
    const [ap, vp] = await Promise.all([
      fetchRsiProfile(killer).catch(() => ({ handle: killer })),
      fetchRsiProfile(me).catch(()     => ({ handle: me })),
    ])
    // NPC guard (death side): if the KILLER has no RSI profile (confirmed 404),
    // an NPC killed you — not a PvP death. Skip. Uncertain lookups still post.
    if (ap && ap.lookup === 'notfound') {
      win.webContents.send('log', 'info', `↷ Skipping death — killer "${killer}" has no RSI profile (NPC, not a real player)`)
      return
    }
    const result = await apiRequest('POST', '/kill', {
      crime_type: crime, victim: me, attacker: killer, timestamp: ts,
      method: 'crime_victim',
      kill_type: 'lawful', kill_method: killMethod, ship_attacker: '', zone: location, location: location,
      bounty_target: '', bounty_mission_id: '',
      att_avatar:   ap.avatar_url || '', att_org_logo: ap.org_logo  || '',
      att_org_name: ap.org_name   || '', att_org_sid:  ap.org_sid   || '',
      att_org_rank: ap.org_rank   || '', att_enlisted: ap.enlisted  || '',
      att_location: ap.location   || '',
      vic_avatar:   vp.avatar_url || '', vic_org_logo: vp.org_logo  || '',
      vic_org_name: vp.org_name   || '', vic_org_sid:  vp.org_sid   || '',
      vic_org_rank: vp.org_rank   || '', vic_enlisted: vp.enlisted  || '',
      vic_location: vp.location   || '',
    })
    if (result.ok) {
      if (result.duplicate) {
        win.webContents.send('log', 'info', `  ↷ Death already recorded by attacker's tracker`)
      } else {
        win.webContents.send('log', 'ok', `  ✓ Death recorded — ${killer} credited`)
      }
    } else {
      win.webContents.send('log', 'error', `  ✗ Death submit failed: ${result.error || ''}`)
    }
  } catch(e) {
    win.webContents.send('log', 'error', `  ✗ Death submit error: ${e.message}`)
  }
}

let splashWin = null
let mainWin   = null
let audioWin  = null

function createAudio() {
  audioWin = new BrowserWindow({
    show: false, width: 1, height: 1,
    skipTaskbar: true,
    webPreferences: { nodeIntegration: false, contextIsolation: true }
  })
  audioWin.loadFile(path.join(__dirname, 'audio.html'))
  audioWin.webContents.once('did-finish-load', () => {
    const musicPath = path.join(__dirname, '..', 'assets', 'bg_music.m4a')
      .replace(/\\/g, '/')
    // Honour the saved audio preference from the very first frame. If the user
    // last muted the launcher (or set the volume to 0), the opening intro stays
    // silent too — we remember that they don't want to hear it. A fresh install
    // has no preference yet, so it defaults to the quiet background track.
    const cfg   = loadConfig()
    const vol   = (typeof cfg.volume === 'number') ? cfg.volume : 0.067
    const muted = !!cfg.muted
    audioWin.webContents.executeJavaScript(`
      const a = document.getElementById('bg');
      a.src = 'file:///${musicPath}';
      a.loop = true;
      a.muted = ${muted ? 'true' : 'false'};
      a.volume = ${vol};
      a.play().catch(e => console.log('play error:', e));
    `)
  })
  audioWin.on('closed', () => { audioWin = null })
}

const EULA_VERSION = 1  // bump to force everyone to re-accept after a material change

function createSplash() {
  createAudio()
  splashWin = new BrowserWindow({
    width: 900, height: 420, resizable: false, frame: false,
    title: 'scKillboard', backgroundColor: '#080809',
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false }
  })
  splashWin.setMenuBarVisibility(false)
  splashWin.on('closed', () => { splashWin = null; if (!mainWin) app.quit() })

  const _cfg = loadConfig()
  const _accepted = _cfg.eula_accepted && _cfg.eula_version === EULA_VERSION
  if (_accepted && _cfg.skip_intro) {
    // User opted out of the boot intro — go straight to auto-login / sign-in.
    proceedAfterIntro()
  } else {
    splashWin.loadFile(path.join(__dirname, _accepted ? 'boot.html' : 'eula.html'))
  }
}

// Shared by the boot screen (once its animation finishes) and the skip-intro
// path: if a valid session exists, jump straight into the main window; otherwise
// show the sign-in screen and start polling for Star Citizen.
async function proceedAfterIntro() {
  if (!splashWin) return
  const cfg = loadConfig()
  if (cfg.session_token) {
    try {
      const me = await apiRequest('GET', '/api/auth/me')
      if (me && me.ok !== false && (me.sc_handle || me.username)) {
        cfg.attacker_handle = me.sc_handle || cfg.attacker_handle
        saveConfig(cfg)
        createMain()
        setTimeout(() => { if (splashWin) { splashWin.close(); splashWin = null } }, 300)
        return
      }
    } catch (e) {
      // Network hiccup or invalid/expired token — fall through to manual login
    }
    delete cfg.session_token
    saveConfig(cfg)
  }
  splashWin.loadFile(path.join(__dirname, 'splash.html'))
  splashWin.webContents.once('did-finish-load', () => startScPoll(splashWin))
}

function createMain() {
  mainWin = new BrowserWindow({
    width: 700, height: 750, minWidth: 700, minHeight: 700,
    title: 'scKillboard', backgroundColor: '#080809',
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false }
  })
  mainWin.loadFile(path.join(__dirname, 'index.html'))
  mainWin.setMenuBarVisibility(false)
  // Keep watching whether Star Citizen is running so the renderer can hard-block
  // "Start Tracking" until SC is closed — tracking must be live BEFORE the game
  // opens, or early kills arrive missing ship/weapon details.
  mainWin.webContents.once('did-finish-load', () => {
    startScPoll(mainWin)
    // Voluntary auto-check once the main UI is up (the launch-time check runs
    // before this window exists, so its events wouldn't reach the banner).
    if (autoUpdater && app.isPackaged) { try { autoUpdater.checkForUpdates() } catch (e) {} }
  })
  mainWin.on('closed', () => { stopScPoll(); stopWatcher(); mainWin = null; app.quit() })
}

ipcMain.handle('get-config',   () => loadConfig())
ipcMain.handle('get-quotes',   () => QUOTES)

ipcMain.on('eula-accept', () => {
  const cfg = loadConfig()
  cfg.eula_accepted = true
  cfg.eula_version  = EULA_VERSION
  saveConfig(cfg)
  if (splashWin) splashWin.loadFile(path.join(__dirname, 'boot.html'))
})
ipcMain.on('eula-decline', () => { app.quit() })

ipcMain.on('open-external', (e, url) => {
  // Only open https URLs — never arbitrary schemes from the renderer.
  if (typeof url === 'string' && /^https:\/\//i.test(url)) shell.openExternal(url)
})
ipcMain.handle('check-server', async () => {
  try { const r = await apiRequest('GET', '/health', null); return !!r.status }
  catch(e) { return false }
})

// Merge into the existing config. The renderer only sends the few fields shown in
// Settings, so a straight overwrite would wipe everything else it doesn't know
// about (session token, EULA acceptance, volume/mute).
ipcMain.on('save-config', (e, cfg) => {
  const merged = Object.assign(loadConfig(), cfg || {})
  saveConfig(merged)
})

ipcMain.handle('login', async (e, { username, password }) => {
  return new Promise((resolve) => {
    const body = JSON.stringify({ username, password })
    const url  = new URL(API_BASE + '/api/auth/login')
    const opts = {
      hostname: url.hostname,
      path:     url.pathname,
      method:   'POST',
      headers:  { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body),
                  'X-Client-Version': app.getVersion() }
    }
    const req = (url.protocol === 'https:' ? https : http).request(opts, res => {
      let data = ''
      res.on('data', c => data += c)
      res.on('end', () => {
        try {
          const r = JSON.parse(data)
          // Outdated launcher — server rejected the login (HTTP 426).
          if (res.statusCode === 426 || r.update_required) {
            handleUpdateRequired(r)
            resolve({ ok: false, error: r.message || 'Update required', update_required: true }); return
          }
          if (r.error) { resolve({ ok: false, error: r.error }); return }
          // Extract session cookie from response
          const cookies = res.headers['set-cookie'] || []
          const sessionCookie = cookies.find(c => c.startsWith('vkb_session='))
          const token = sessionCookie ? sessionCookie.split(';')[0].split('=')[1] : ''
          if (token) {
            const cfg = loadConfig()
            cfg.session_token   = token
            cfg.attacker_handle = r.sc_handle || username
            saveConfig(cfg)
          }
          resolve({ ok: true, sc_handle: r.sc_handle, username: r.username, token })
        } catch(e) {
          resolve({ ok: false, error: 'Parse error: ' + e.message })
        }
      })
    })
    req.on('error', err => resolve({ ok: false, error: err.message }))
    req.write(body)
    req.end()
  })
})

ipcMain.handle('logout', async () => {
  try { await apiRequest('POST', '/api/auth/logout') } catch (e) {}
  const cfg = loadConfig()
  delete cfg.session_token
  saveConfig(cfg)
  return { ok: true }
})

ipcMain.on('launch', (e, handle) => {
  stopScPoll()
  const cfg = loadConfig()
  cfg.attacker_handle = handle
  saveConfig(cfg)
  createMain()
  if (splashWin) {
    setTimeout(() => { if (splashWin) { splashWin.close(); splashWin = null } }, 300)
  }
})


ipcMain.on('start-tracking', async (e, logPath) => {
  if (!mainWin) return
  const running = await isScRunning()
  if (running) {
    // Hard block: SC is already open, so it's mid-session and we'd have missed the
    // context lines (ship entered, weapon drawn) that complete a kill. Refuse until
    // it's closed so tracking can be live before the next session starts.
    mainWin.webContents.send('log', 'error', '✗ Star Citizen is already running. Close it, press Start Tracking, THEN reopen Star Citizen — this guarantees every kill has full details.')
    mainWin.webContents.send('status', 'error', 'Close Star Citizen first')
    mainWin.webContents.send('tracking-state', false)
    return
  }
  const started = startWatcher(logPath, mainWin)
  mainWin.webContents.send('tracking-state', !!started)
  if (started) {
    mainWin.webContents.send('log', 'ok', '✓ Tracking active — you can now launch Star Citizen.')
  }
})
ipcMain.on('stop-tracking', () => {
  stopWatcher()
  if (mainWin && !mainWin.isDestroyed()) mainWin.webContents.send('tracking-state', false)
})

// ── Audio IPC ─────────────────────────────────────────────────────────────────
ipcMain.on('set-volume', (e, v) => {
  const vol = parseFloat(v)
  const cfg = loadConfig(); cfg.volume = vol; saveConfig(cfg)
  if (audioWin && !audioWin.isDestroyed()) {
    audioWin.webContents.executeJavaScript(
      `(function(){ var a=document.getElementById('bg'); if(a) a.volume=${vol}; })()`
    ).catch(() => {})
  }
})
ipcMain.on('set-mute', (e, m) => {
  const cfg = loadConfig(); cfg.muted = !!m; saveConfig(cfg)
  if (audioWin && !audioWin.isDestroyed()) {
    audioWin.webContents.executeJavaScript(
      `(function(){ var a=document.getElementById('bg'); if(a) a.muted=${m ? 'true' : 'false'}; })()`
    ).catch(() => {})
  }
})

ipcMain.on('clear-feed', () => {
  killCount = 0
  if (mainWin) mainWin.webContents.send('kill-count', 0)
})

ipcMain.on('boot-complete', () => { proceedAfterIntro() })

ipcMain.on('browse-log', async () => {
  if (!mainWin) return
  const cfg = loadConfig()
  const result = await dialog.showOpenDialog(mainWin, {
    title: 'Select Game.log',
    defaultPath: cfg.log_path,
    filters: [{ name: 'Log files', extensions: ['log'] }, { name: 'All files', extensions: ['*'] }]
  })
  if (!result.canceled && result.filePaths[0]) {
    // Persist straight away — the user shouldn't have to also click Save Settings.
    cfg.log_path = result.filePaths[0]; saveConfig(cfg)
    mainWin.webContents.send('log-path-selected', result.filePaths[0])
  }
})


ipcMain.handle('resync-profiles', async () => {
  if (mainWin) mainWin.webContents.send('log', 'info', 'Fetching player list from server…')
  try {
    const data = await apiRequest('GET', '/api/player-leaderboard', null)
    const players = Array.isArray(data) ? data : []
    const handles = players.map(p => p.handle).filter(Boolean)
    if (!handles.length) return { ok: true, total: 0 }
    const synced = await syncAllProfiles(handles, mainWin)
    return { ok: true, total: synced }
  } catch(e) {
    return { ok: false, error: e.message }
  }
})

// ── App lifecycle ────────────────────────────────────────────────────────────────
// ── Update checker ────────────────────────────────────────────────────────────
// Compares the running app version (package.json, via app.getVersion()) to
// the latest version your backend reports. Deliberately does NOT download or
// execute anything automatically — just prompts and opens the download page
// in the user's browser if they say yes. Auto-downloading/running an .exe
// silently is a real security liability if the version endpoint is ever
// compromised, so this stays a confirmed, manual download every time.
function compareVersions(a, b) {
  const pa = String(a).split('.').map(n => parseInt(n, 10) || 0)
  const pb = String(b).split('.').map(n => parseInt(n, 10) || 0)
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const diff = (pa[i] || 0) - (pb[i] || 0)
    if (diff !== 0) return diff > 0 ? 1 : -1
  }
  return 0
}

// ── Forced ("Update Required") flow ──────────────────────────────────────────
// Shown when the server reports this launcher is below MIN_CLIENT_VERSION — either
// via the startup version check, or via an HTTP 426 on any kill/login attempt.
// This is a hard stop: the only choices are download-and-quit or quit. The server
// enforces the same rule regardless, so a bypassed screen still can't submit kills.
const DEFAULT_RELEASES_URL = 'https://github.com/ver9jl-cell/sckillboard-launcher/releases/latest'
let _updateBlocking = false

function handleUpdateRequired(info) {
  if (_updateBlocking) return   // only ever act once
  _updateBlocking = true
  _forcedUpdate   = true
  _lastUpdateInfo = info || {}
  // Show the blocking "updating" overlay and pull + install the new build in-app.
  _sendUpdate({ state: 'forced', version: (info && info.version) || '' })
  if (autoUpdater && app.isPackaged) {
    try {
      autoUpdater.checkForUpdates()
      _forcedTimer = setTimeout(() => _forcedBrowserFallback(), 30000)  // safety net
    } catch (e) { _forcedBrowserFallback() }
  } else {
    _forcedBrowserFallback()   // dev run or missing dep → old browser+quit flow
  }
}

function _forcedBrowserFallback() {
  if (_forcedTimer) { clearTimeout(_forcedTimer); _forcedTimer = null }
  forceUpdate(mainWin || splashWin || null, _lastUpdateInfo || {})
}

async function forceUpdate(win, info) {
  try {
    const choice = await dialog.showMessageBox(win || undefined, {
      type: 'warning',
      noLink: true,
      title: 'Update Required',
      message: 'A newer scKillboard launcher is required to continue.',
      detail: (info.changelog ||
        'Your launcher is out of date and can no longer sign in or submit kills. ' +
        'Please install the latest version to keep using scKillboard.') +
        '\n\nThe app will close so you can install the update.',
      buttons: ['Download Update', 'Quit'],
      defaultId: 0,
      cancelId: 1,
    })
    if (choice.response === 0) {
      // Always our own GitHub releases page — never a server-supplied URL, so a
      // compromised update server can't redirect users to a malicious download.
      shell.openExternal(DEFAULT_RELEASES_URL)
    }
  } catch (e) {
    // If the dialog itself fails, still quit — we must not let an outdated client run.
  }
  app.quit()
}

async function checkForUpdates(win) {
  try {
    const res = await apiRequest('GET', '/api/launcher/version')
    if (!res || !res.version) return
    const current = app.getVersion()
    // Hard gate: below the server's minimum supported version → forced update.
    if (res.min_version && compareVersions(current, res.min_version) < 0) {
      handleUpdateRequired(res)
      return
    }
    // Soft: a newer build exists — let electron-updater fetch it and show the
    // in-app banner (renderer reacts to the 'update-status' events).
    if (compareVersions(res.version, current) > 0 && autoUpdater && app.isPackaged) {
      try { autoUpdater.checkForUpdates() } catch (e) {}
    }
  } catch (e) {
    // Update server unreachable — fail silently, never block app startup
  }
}

// ── In-app auto-update (electron-updater) ────────────────────────────────────
// Pulls new versions straight from the GitHub Releases and installs on restart —
// no browser, no manual installer. Only runs in a packaged build; a dev run or a
// missing dependency falls back to the old open-the-download-page flow.
let autoUpdater = null
try { autoUpdater = require('electron-updater').autoUpdater } catch (e) { autoUpdater = null }

let _forcedUpdate   = false   // true when the server forced the update (HTTP 426)
let _lastUpdateInfo = {}
let _forcedTimer    = null

function _sendUpdate(payload) {
  for (const w of [mainWin, splashWin]) {
    if (w && !w.isDestroyed()) { try { w.webContents.send('update-status', payload) } catch (e) {} }
  }
}

if (autoUpdater) {
  autoUpdater.autoDownload = false          // prompt before downloading (voluntary updates)
  autoUpdater.autoInstallOnAppQuit = true   // if downloaded, install on next quit as a fallback
  autoUpdater.on('checking-for-update', () => _sendUpdate({ state: 'checking' }))
  autoUpdater.on('update-available', (info) => {
    _sendUpdate({ state: 'available', version: info && info.version, forced: _forcedUpdate })
    if (_forcedUpdate) { try { autoUpdater.downloadUpdate() } catch (e) { _forcedBrowserFallback() } }
  })
  autoUpdater.on('update-not-available', () => {
    _sendUpdate({ state: 'none' })
    if (_forcedUpdate) _forcedBrowserFallback()
  })
  autoUpdater.on('download-progress', (p) => {
    if (_forcedTimer) { clearTimeout(_forcedTimer); _forcedTimer = null }
    _sendUpdate({ state: 'downloading', percent: Math.round((p && p.percent) || 0), forced: _forcedUpdate })
  })
  autoUpdater.on('update-downloaded', (info) => {
    _sendUpdate({ state: 'downloaded', version: info && info.version, forced: _forcedUpdate })
    if (_forcedUpdate) setImmediate(() => { try { autoUpdater.quitAndInstall(true, true) } catch (e) {} })
  })
  autoUpdater.on('error', (err) => {
    _sendUpdate({ state: 'error', message: String((err && err.message) || err || 'update error') })
    if (_forcedUpdate) _forcedBrowserFallback()
  })
}

ipcMain.on('update:check', () => {
  if (!autoUpdater || !app.isPackaged) { _sendUpdate({ state: 'none', dev: true }); return }
  try { autoUpdater.checkForUpdates() } catch (e) { _sendUpdate({ state: 'error', message: String(e.message || e) }) }
})
ipcMain.on('update:download', () => {
  if (!autoUpdater) return
  try { autoUpdater.downloadUpdate() } catch (e) { _sendUpdate({ state: 'error', message: String(e.message || e) }) }
})
ipcMain.on('update:install', () => {
  if (autoUpdater) setImmediate(() => { try { autoUpdater.quitAndInstall(true, true) } catch (e) {} })
})

app.on('web-contents-created', (e, contents) => {
  contents.setWindowOpenHandler(({ url }) => {
    if (/^https:\/\//i.test(url)) shell.openExternal(url)
    return { action: 'deny' }
  })
  contents.on('will-navigate', (event, url) => {
    if (!url.startsWith('file://')) event.preventDefault()
  })
})

app.whenReady().then(() => {
  createSplash()
  checkForUpdates()
})
app.on('before-quit', () => {
  stopWatcher()
  stopScPoll()
  if (audioWin && !audioWin.isDestroyed()) { audioWin.destroy(); audioWin = null }
})

app.on('window-all-closed', () => {
  if (mainWin && !mainWin.isDestroyed()) return  // main still open
  app.quit()
})
