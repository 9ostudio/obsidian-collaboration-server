import http from 'node:http'
import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { WebSocketServer } from 'ws'
import { joinPage, setupPage, messagePage } from './pages.mjs'

const PORT = Number(process.env.PORT || 8790)
const HOST = process.env.HOST || '127.0.0.1'
const DATA_DIR = path.resolve(process.env.DATA_DIR || './data')
const PUBLIC_URL = (process.env.PUBLIC_URL || `http://localhost:${PORT}`).replace(/\/+$/, '')
const PLUGIN_REPO = process.env.PLUGIN_REPO || '9ostudio/obsidian-collaboration-client'
const INVITE_TTL_MS = 7 * 24 * 3600 * 1000
const MOVED_TO = (process.env.MOVED_TO || '').replace(/\/+$/, '')
const MAX_JSON = 256 * 1024
const MAX_EVENT = 12 * 1024 * 1024
const MAX_AWARENESS = 64 * 1024
const TYPES = new Set(['create', 'meta', 'update', 'snap', 'delete', 'restore'])
const WRITE_TYPES = new Set(['create', 'meta', 'update', 'snap'])
const ALL = { read: true, write: true, delete: true }
const ID = /^[A-Za-z0-9_-]{8,64}$/

fs.mkdirSync(path.join(DATA_DIR, 'shares'), { recursive: true })

const DB_FILE = path.join(DATA_DIR, 'db.json')
let db = { users: {}, shares: {}, invites: {} }
if (fs.existsSync(DB_FILE)) db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'))

function saveDb () {
  const tmp = DB_FILE + '.tmp'
  fs.writeFileSync(tmp, JSON.stringify(db, null, 1))
  fs.renameSync(tmp, DB_FILE)
}

function sha256 (data) { return crypto.createHash('sha256').update(data).digest('hex') }
function randomToken () { return crypto.randomBytes(24).toString('base64url') }
function nowIso () { return new Date().toISOString() }

function safeEqual (a, b) {
  const ab = Buffer.from(String(a))
  const bb = Buffer.from(String(b))
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb)
}

function writeAtomic (file, data, mode = 0o644) {
  fs.mkdirSync(path.dirname(file), { recursive: true })
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`
  fs.writeFileSync(tmp, data, { mode })
  fs.renameSync(tmp, file)
}

const OWNER_TOKEN_FILE = path.join(DATA_DIR, 'owner-token')

function validOwnerToken (token) {
  let current = ''
  try { current = fs.readFileSync(OWNER_TOKEN_FILE, 'utf8').trim() } catch {}
  return current.length >= 16 && safeEqual(token || '', current)
}

const shareDir = (id) => path.join(DATA_DIR, 'shares', id)
const isString = (v, max) => typeof v === 'string' && v.length > 0 && v.length <= max

function cleanPerms (p) {
  const perms = { read: p?.read !== false, write: !!p?.write, delete: !!p?.delete }
  if (!perms.read) { perms.write = false; perms.delete = false }
  return perms
}

function roleOf (share, userId) {
  if (!share || !userId) return null
  if (share.ownerId === userId) return 'owner'
  if (share.members[userId]) return 'member'
  return null
}

function permsOf (share, userId) {
  const role = roleOf(share, userId)
  if (role === 'owner') return ALL
  if (role === 'member') return share.members[userId].perms
  return null
}

function canRead (share, userId) { return !!permsOf(share, userId)?.read }

function payloadEpoch (b64) {
  try {
    const head = Buffer.from(b64.slice(0, 8), 'base64')
    if (head.length < 5 || head[0] !== 1) return -1
    return head.readUInt32BE(1)
  } catch {
    return -1
  }
}

function authUser (bearer) {
  const raw = String(bearer || '').replace(/^Bearer\s+/i, '')
  const dot = raw.indexOf('.')
  if (dot < 1) return null
  const userId = raw.slice(0, dot)
  const user = db.users[userId]
  if (!user || !safeEqual(user.secretHash, sha256(raw.slice(dot + 1)))) return null
  return { id: userId, ...user }
}

function findInvite (token) {
  if (!token || typeof token !== 'string') return null
  const hash = sha256(token)
  const invite = db.invites[hash]
  return invite ? { hash, ...invite } : null
}

function inviteProblem (invite) {
  if (!invite) return 'This invite link is not valid.'
  if (!db.shares[invite.shareId]) return 'This shared folder no longer exists.'
  if (invite.usedBy) return 'This invite link has already been used.'
  if (Date.parse(invite.expiresAt) <= Date.now()) return 'This invite link has expired.'
  return null
}

function clientIp (req) {
  const remote = req.socket.remoteAddress || ''
  const local = remote === '127.0.0.1' || remote === '::1' || remote === '::ffff:127.0.0.1'
  const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()
  return local && forwarded ? forwarded : remote
}

const registrations = new Map()
function allowRegistration (ip) {
  const key = `${ip}:${Math.floor(Date.now() / 3600000)}`
  const count = (registrations.get(key) || 0) + 1
  registrations.set(key, count)
  if (registrations.size > 10000) registrations.clear()
  return count <= 20
}

function membersView (share, withKeys = false) {
  const entry = (userId, nameEnc, perms, owner, joinedAt) => ({
    userId, nameEnc, perms, owner, joinedAt, ...(withKeys ? { publicKey: db.users[userId]?.publicKey || '' } : {})
  })
  return [
    entry(share.ownerId, share.ownerNameEnc, ALL, true, share.createdAt),
    ...Object.entries(share.members).map(([id, m]) => entry(id, m.nameEnc, m.perms, false, m.joinedAt))
  ]
}

function youView (share, userId) {
  return { perms: permsOf(share, userId) || { read: false, write: false, delete: false }, owner: share.ownerId === userId }
}

function shareSummary (share, userId) {
  return { id: share.id, role: roleOf(share, userId), perms: permsOf(share, userId), nameEnc: share.nameEnc, pathEnc: share.pathEnc || null, epoch: share.epoch }
}

const states = new Map()

function stateOf (shareId) {
  let state = states.get(shareId)
  if (state) return state
  state = { events: [], cids: new Map(), files: new Map(), conns: new Map(), log: path.join(shareDir(shareId), 'log.jsonl') }
  states.set(shareId, state)
  if (fs.existsSync(state.log)) {
    for (const line of fs.readFileSync(state.log, 'utf8').split('\n')) {
      if (!line) continue
      try { index(state, JSON.parse(line)) } catch {}
    }
  }
  return state
}

function index (state, ev) {
  const i = state.events.length
  state.events.push(ev)
  if (ev.cid) state.cids.set(ev.cid, ev.seq)
  let file = state.files.get(ev.f)
  if (!file) {
    file = { create: i, lastMeta: i, lastSnap: -1, snapBase: 0, lastStatus: -1, deleted: false, idx: [] }
    state.files.set(ev.f, file)
  }
  file.idx.push(i)
  if (ev.type === 'meta') file.lastMeta = i
  if (ev.type === 'snap') { file.lastSnap = i; file.snapBase = ev.b || 0 }
  if (ev.type === 'delete' || ev.type === 'restore') { file.lastStatus = i; file.deleted = ev.type === 'delete' }
}

function send (ws, msg) {
  if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(msg))
}

function broadcast (shareId, msg, except = null) {
  const state = states.get(shareId)
  if (!state) return
  for (const ws of state.conns.keys()) if (ws !== except) send(ws, msg)
}

function broadcastMembers (share) {
  const state = states.get(share.id)
  if (!state) return
  const members = membersView(share)
  for (const [ws, meta] of state.conns) send(ws, { t: 'members', members, you: youView(share, meta.userId) })
}

function closeConns (shareId, code, reason, userId = null) {
  const state = states.get(shareId)
  if (!state) return
  for (const [ws, meta] of Array.from(state.conns)) {
    if (userId && meta.userId !== userId) continue
    state.conns.delete(ws)
    try { ws.close(code, reason) } catch {}
  }
}

function bootstrap (state) {
  const picked = new Set()
  for (const file of state.files.values()) {
    picked.add(file.create)
    picked.add(file.lastMeta)
    if (file.lastStatus >= 0) picked.add(file.lastStatus)
    for (const i of file.idx) {
      const ev = state.events[i]
      if (ev.type === 'snap' ? i === file.lastSnap : ev.type === 'update' && ev.seq > file.snapBase) picked.add(i)
    }
  }
  return Array.from(picked).sort((a, b) => a - b).map((i) => state.events[i])
}

function handleEvent (ws, share, userId, msg) {
  const state = stateOf(share.id)
  const { cid, type, f, d } = msg
  const reject = (code) => send(ws, { t: 'err', cid, code })
  if (!isString(cid, 64) || !ID.test(cid)) return
  if (!TYPES.has(type) || !isString(f, 64) || !ID.test(f)) return reject('bad_event')
  const existing = state.cids.get(cid)
  if (existing) return send(ws, { t: 'ev', ...state.events[existing - 1] })
  const perms = permsOf(share, userId)
  if (!perms || (WRITE_TYPES.has(type) ? !perms.write : !perms.delete)) return reject('forbidden')
  const file = state.files.get(f)
  if (type === 'create' ? file : !file) return reject(type === 'create' ? 'exists' : 'no_file')
  if (file && WRITE_TYPES.has(type) && file.deleted) return reject('deleted')
  if (type === 'delete' && file.deleted) return reject('deleted')
  if (type === 'restore' && !file.deleted) return reject('not_deleted')
  if (WRITE_TYPES.has(type)) {
    if (!isString(d, MAX_EVENT)) return reject('bad_event')
    if (payloadEpoch(d) < share.epoch) return reject('stale_key')
  }
  const ev = { seq: state.events.length + 1, ts: Date.now(), a: userId, type, f, cid }
  if (WRITE_TYPES.has(type)) ev.d = d
  if (type === 'snap' && Number.isInteger(msg.b) && msg.b >= 0) ev.b = msg.b
  fs.mkdirSync(path.dirname(state.log), { recursive: true })
  fs.appendFileSync(state.log, JSON.stringify(ev) + '\n')
  index(state, ev)
  broadcast(share.id, { t: 'ev', ...ev })
}

function handleConnection (ws, share, userId) {
  const state = stateOf(share.id)
  state.conns.set(ws, { userId })
  let alive = true
  ws.on('pong', () => { alive = true })
  const ping = setInterval(() => {
    if (!alive) { clearInterval(ping); ws.terminate(); return }
    alive = false
    try { ws.ping() } catch {}
  }, 30000)

  ws.on('message', (data, isBinary) => {
    if (isBinary) return
    let msg
    try { msg = JSON.parse(data.toString('utf8')) } catch { return }
    const current = db.shares[share.id]
    if (!current || !canRead(current, userId)) { try { ws.close(4403, 'not_a_member') } catch {} return }
    if (msg.t === 'hello') {
      const since = Number.isInteger(msg.since) && msg.since > 0 ? msg.since : 0
      const events = since === 0 ? bootstrap(state) : state.events.slice(since)
      for (const ev of events) send(ws, { t: 'ev', ...ev })
      send(ws, { t: 'synced', head: state.events.length })
    } else if (msg.t === 'ev') {
      handleEvent(ws, current, userId, msg)
    } else if (msg.t === 'aw') {
      if (isString(msg.d, MAX_AWARENESS)) broadcast(share.id, { t: 'aw', a: userId, d: msg.d }, ws)
    } else if (msg.t === 'history') {
      const file = isString(msg.f, 64) ? state.files.get(msg.f) : null
      send(ws, { t: 'history', rid: msg.rid, events: file ? file.idx.map((i) => state.events[i]) : [] })
    }
  })

  ws.on('close', () => {
    clearInterval(ping)
    state.conns.delete(ws)
    const stillHere = Array.from(state.conns.values()).some((m) => m.userId === userId)
    if (!stillHere) broadcast(share.id, { t: 'gone', a: userId })
  })

  send(ws, {
    t: 'welcome',
    you: youView(share, userId),
    members: membersView(share),
    envelope: share.envelopes?.[userId] || null,
    pathEnc: share.pathEnc || null,
    epoch: share.epoch,
    head: state.events.length
  })
}

function receiveBlob (req, file, epoch) {
  return new Promise((resolve, reject) => {
    fs.mkdirSync(path.dirname(file), { recursive: true })
    const tmp = `${file}.${process.pid}.${Date.now()}.upload`
    const out = fs.createWriteStream(tmp)
    let head = Buffer.alloc(0)
    let size = 0
    let rejected = false
    const fail = () => {
      if (rejected) return
      rejected = true
      req.unpipe(out)
      out.destroy()
      fs.rmSync(tmp, { force: true })
      resolve(false)
    }
    req.on('data', (chunk) => {
      size += chunk.length
      if (head.length < 5) {
        head = Buffer.concat([head, chunk])
        if (head.length >= 5 && (head[0] !== 1 || head.readUInt32BE(1) < epoch)) fail()
      }
    })
    req.on('error', (err) => { out.destroy(); fs.rmSync(tmp, { force: true }); reject(err) })
    out.on('error', (err) => { fs.rmSync(tmp, { force: true }); reject(err) })
    out.on('finish', () => {
      if (rejected) return
      if (size < 18) { fs.rmSync(tmp, { force: true }); resolve(false); return }
      fs.renameSync(tmp, file)
      resolve(true)
    })
    req.pipe(out)
  })
}

function json (res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' })
  res.end(JSON.stringify(body))
}

function html (res, status, body) {
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"
  })
  res.end(body)
}

function readBody (req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let size = 0
    req.on('data', (c) => {
      size += c.length
      if (size > limit) { reject(Object.assign(new Error('too_large'), { status: 413 })); req.destroy(); return }
      chunks.push(c)
    })
    req.on('end', () => resolve(Buffer.concat(chunks)))
    req.on('error', reject)
  })
}

async function readJson (req) {
  const buf = await readBody(req, MAX_JSON)
  if (buf.length === 0) return {}
  try { return JSON.parse(buf.toString('utf8')) } catch { throw Object.assign(new Error('bad_json'), { status: 400 }) }
}

async function handleApi (req, res, url, parts) {
  const method = req.method

  if (method === 'POST' && parts[1] === 'register' && parts.length === 2) {
    const { userId, secret, publicKey } = await readJson(req)
    if (!/^[A-Za-z0-9-]{8,64}$/.test(userId || '') || !isString(secret, 200) || secret.length < 32 || !isString(publicKey, 2000)) return json(res, 400, { error: 'bad_identity' })
    const existing = db.users[userId]
    if (existing && !safeEqual(existing.secretHash, sha256(secret))) return json(res, 409, { error: 'identity_taken' })
    if (!existing && !allowRegistration(clientIp(req))) return json(res, 429, { error: 'too_many_requests' })
    db.users[userId] = { secretHash: sha256(secret), publicKey, createdAt: existing?.createdAt || nowIso(), canShare: existing?.canShare || false }
    saveDb()
    return json(res, 200, { canShare: db.users[userId].canShare })
  }

  const user = authUser(req.headers.authorization)
  if (!user) return json(res, 401, { error: 'unauthorized' })

  if (parts[1] === 'claim' && method === 'POST') {
    const { token } = await readJson(req)
    if (!validOwnerToken(token)) return json(res, 403, { error: 'This setup link is not valid or was already used.' })
    fs.rmSync(OWNER_TOKEN_FILE, { force: true })
    db.users[user.id].canShare = true
    saveDb()
    return json(res, 200, { ok: true })
  }

  if (parts[1] === 'invites' && parts[2]) {
    const invite = findInvite(parts[2])
    const problem = inviteProblem(invite)
    const share = invite && db.shares[invite.shareId]
    if (method === 'GET' && parts.length === 3) {
      if (share && roleOf(share, user.id)) return json(res, 200, { shareId: share.id, perms: permsOf(share, user.id), keyring: invite.keyring, shareNameEnc: share.nameEnc, ownerNameEnc: share.ownerNameEnc, pathEnc: share.pathEnc || null, ownerId: share.ownerId })
      if (problem) return json(res, 410, { error: problem })
      return json(res, 200, { shareId: share.id, perms: invite.perms, keyring: invite.keyring, shareNameEnc: share.nameEnc, ownerNameEnc: share.ownerNameEnc, pathEnc: share.pathEnc || null, ownerId: share.ownerId })
    }
    if (method === 'POST' && parts[3] === 'accept') {
      if (share && roleOf(share, user.id)) return json(res, 200, shareSummary(share, user.id))
      if (problem) return json(res, 410, { error: problem })
      const { nameEnc } = await readJson(req)
      if (!isString(nameEnc, 4096)) return json(res, 400, { error: 'missing_name' })
      share.members[user.id] = { nameEnc, perms: cleanPerms(invite.perms), joinedAt: nowIso() }
      db.invites[invite.hash].usedBy = user.id
      db.invites[invite.hash].usedAt = nowIso()
      saveDb()
      broadcastMembers(share)
      return json(res, 200, shareSummary(share, user.id))
    }
  }

  if (parts[1] !== 'shares') return json(res, 404, { error: 'not_found' })

  if (parts.length === 2) {
    if (method === 'GET') {
      return json(res, 200, { shares: Object.values(db.shares).filter((s) => roleOf(s, user.id)).map((s) => shareSummary(s, user.id)) })
    }
    if (method === 'POST') {
      if (!user.canShare) return json(res, 403, { error: 'not_owner' })
      const { id, nameEnc, ownerNameEnc, pathEnc } = await readJson(req)
      if (!isString(id, 64) || !ID.test(id) || !isString(nameEnc, 4096) || !isString(ownerNameEnc, 4096)) return json(res, 400, { error: 'bad_share' })
      if (pathEnc !== undefined && !isString(pathEnc, 8192)) return json(res, 400, { error: 'bad_share' })
      if (db.shares[id]) return json(res, 409, { error: 'exists' })
      db.shares[id] = { id, ownerId: user.id, ownerNameEnc, nameEnc, ...(pathEnc ? { pathEnc } : {}), createdAt: nowIso(), epoch: 0, members: {}, envelopes: {} }
      saveDb()
      fs.mkdirSync(path.join(shareDir(id), 'blobs'), { recursive: true })
      return json(res, 200, shareSummary(db.shares[id], user.id))
    }
  }

  const share = db.shares[parts[2]]
  const role = roleOf(share, user.id)
  if (!share || !role) return json(res, 404, { error: 'share_not_found' })
  const owner = role === 'owner'
  const sub = parts[3]

  if (parts.length === 3 && method === 'PATCH') {
    if (!owner) return json(res, 403, { error: 'owner_only' })
    const { pathEnc } = await readJson(req)
    if (!isString(pathEnc, 8192)) return json(res, 400, { error: 'bad_path' })
    share.pathEnc = pathEnc
    saveDb()
    broadcast(share.id, { t: 'share', pathEnc })
    return json(res, 200, { ok: true })
  }

  if (parts.length === 3 && method === 'DELETE') {
    if (!owner) return json(res, 403, { error: 'owner_only' })
    delete db.shares[share.id]
    for (const [hash, inv] of Object.entries(db.invites)) if (inv.shareId === share.id) delete db.invites[hash]
    saveDb()
    closeConns(share.id, 4404, 'share_deleted')
    states.delete(share.id)
    fs.rmSync(shareDir(share.id), { recursive: true, force: true })
    return json(res, 200, { ok: true })
  }

  if (sub === 'invites' && parts.length === 4) {
    if (!owner) return json(res, 403, { error: 'owner_only' })
    if (method === 'POST') {
      const { perms, keyring } = await readJson(req)
      if (!isString(keyring, 65536)) return json(res, 400, { error: 'missing_keyring' })
      const token = randomToken()
      const expiresAt = new Date(Date.now() + INVITE_TTL_MS).toISOString()
      db.invites[sha256(token)] = { shareId: share.id, perms: cleanPerms(perms), keyring, createdAt: nowIso(), expiresAt, usedBy: null, usedAt: null }
      saveDb()
      return json(res, 200, { token, expiresAt })
    }
    if (method === 'DELETE') {
      for (const [hash, inv] of Object.entries(db.invites)) if (inv.shareId === share.id && !inv.usedBy) delete db.invites[hash]
      saveDb()
      return json(res, 200, { ok: true })
    }
  }

  if (sub === 'members' && parts.length === 4 && method === 'GET') {
    if (!owner) return json(res, 403, { error: 'owner_only' })
    const pending = Object.values(db.invites).filter((i) => i.shareId === share.id && !i.usedBy && Date.parse(i.expiresAt) > Date.now()).length
    return json(res, 200, { members: membersView(share, true), pendingInvites: pending })
  }

  if (sub === 'members' && parts[4] && method === 'PATCH') {
    if (!owner) return json(res, 403, { error: 'owner_only' })
    const target = parts[4]
    const { perms, nameEnc } = await readJson(req)
    if (nameEnc !== undefined && !isString(nameEnc, 4096)) return json(res, 400, { error: 'bad_name' })
    if (target === share.ownerId) {
      if (nameEnc) share.ownerNameEnc = nameEnc
    } else {
      const member = share.members[target]
      if (!member) return json(res, 404, { error: 'not_a_member' })
      if (nameEnc) member.nameEnc = nameEnc
      if (perms) member.perms = cleanPerms(perms)
      if (!member.perms.read) closeConns(share.id, 4403, 'no_access', target)
    }
    saveDb()
    broadcastMembers(share)
    return json(res, 200, { ok: true })
  }

  if (sub === 'members' && parts[4] && method === 'DELETE') {
    if (!owner) return json(res, 403, { error: 'owner_only' })
    if (!share.members[parts[4]]) return json(res, 404, { error: 'not_a_member' })
    delete share.members[parts[4]]
    if (share.envelopes) delete share.envelopes[parts[4]]
    saveDb()
    closeConns(share.id, 4403, 'removed', parts[4])
    broadcastMembers(share)
    return json(res, 200, { ok: true })
  }

  if (sub === 'membership' && method === 'DELETE') {
    if (owner) return json(res, 400, { error: 'owner_cannot_leave' })
    delete share.members[user.id]
    if (share.envelopes) delete share.envelopes[user.id]
    saveDb()
    closeConns(share.id, 4403, 'left', user.id)
    broadcastMembers(share)
    return json(res, 200, { ok: true })
  }

  if (sub === 'keys' && method === 'POST') {
    if (!owner) return json(res, 403, { error: 'owner_only' })
    const { epoch, envelopes } = await readJson(req)
    if (epoch !== share.epoch + 1 || !envelopes || typeof envelopes !== 'object') return json(res, 400, { error: 'bad_epoch' })
    const next = {}
    for (const [id, data] of Object.entries(envelopes)) {
      if (roleOf(share, id) && isString(data, 16384)) next[id] = { epoch, data }
    }
    share.epoch = epoch
    share.envelopes = next
    for (const [hash, inv] of Object.entries(db.invites)) if (inv.shareId === share.id && !inv.usedBy) delete db.invites[hash]
    saveDb()
    const state = states.get(share.id)
    if (state) for (const [ws, meta] of state.conns) send(ws, { t: 'key', envelope: next[meta.userId] || null })
    return json(res, 200, { ok: true })
  }

  if (sub === 'key' && method === 'GET') {
    if (!canRead(share, user.id)) return json(res, 403, { error: 'forbidden' })
    return json(res, 200, { epoch: share.epoch, envelope: share.envelopes?.[user.id] || null })
  }

  if (sub === 'blobs' && parts[4]) {
    const blobId = parts[4]
    if (!ID.test(blobId)) return json(res, 400, { error: 'bad_blob' })
    const perms = permsOf(share, user.id)
    if (!perms?.read) return json(res, 403, { error: 'forbidden' })
    const file = path.join(shareDir(share.id), 'blobs', blobId)
    if (method === 'GET') {
      if (!fs.existsSync(file)) return json(res, 404, { error: 'blob_not_found' })
      res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Cache-Control': 'private, max-age=31536000, immutable' })
      return fs.createReadStream(file).pipe(res)
    }
    if (method === 'PUT') {
      if (!perms.write) return json(res, 403, { error: 'forbidden' })
      if (fs.existsSync(file)) return json(res, 409, { error: 'exists' })
      const ok = await receiveBlob(req, file, share.epoch)
      return ok ? json(res, 200, { ok: true }) : json(res, 400, { error: 'stale_key' })
    }
  }

  return json(res, 404, { error: 'not_found' })
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost')
    const parts = url.pathname.split('/').filter(Boolean)
    if (url.pathname === '/health') return json(res, 200, MOVED_TO ? { ok: true, moved: MOVED_TO } : { ok: true })
    if (MOVED_TO) {
      if (parts[0] === 'api') return json(res, 410, { error: 'moved', location: MOVED_TO })
      res.writeHead(308, { Location: MOVED_TO + url.pathname + url.search, 'Cache-Control': 'no-store' })
      return res.end()
    }
    if (parts[0] === 'join' && parts[1] && req.method === 'GET') {
      const invite = findInvite(parts[1])
      const problem = inviteProblem(invite)
      if (problem) return html(res, 410, messagePage('Invite unavailable', `${problem} Ask the person who shared the folder for a new link.`))
      const share = db.shares[invite.shareId]
      return html(res, 200, joinPage({ server: PUBLIC_URL, token: parts[1], repo: PLUGIN_REPO, shareId: share.id, ownerId: share.ownerId, keyring: invite.keyring, shareNameEnc: share.nameEnc, ownerNameEnc: share.ownerNameEnc }))
    }
    if (parts[0] === 'setup' && parts[1] && req.method === 'GET') {
      if (!validOwnerToken(parts[1])) return html(res, 404, messagePage('Link not valid', 'This setup link is not valid or was already used. Run owner-link.sh on the server for a new one.'))
      return html(res, 200, setupPage({ server: PUBLIC_URL, token: parts[1], repo: PLUGIN_REPO }))
    }
    if (parts[0] === 'api') return await handleApi(req, res, url, parts)
    if (url.pathname === '/') {
      res.writeHead(200, { 'Content-Type': 'text/plain' })
      return res.end('Collaboration server')
    }
    json(res, 404, { error: 'not_found' })
  } catch (err) {
    if (!res.headersSent) json(res, err.status || 500, { error: err.status ? err.message : 'server_error' })
    if (!err.status) console.error('[http]', err)
  }
})

const wss = new WebSocketServer({ noServer: true, maxPayload: 16 * 1024 * 1024 })

server.on('upgrade', (req, socket, head) => {
  const url = new URL(req.url, 'http://localhost')
  const parts = url.pathname.split('/').filter(Boolean)
  if (parts[0] !== 'ws' || !parts[1]) { socket.write('HTTP/1.1 404 Not Found\r\n\r\n'); socket.destroy(); return }
  wss.handleUpgrade(req, socket, head, (ws) => {
    if (MOVED_TO) return ws.close(4410, 'moved')
    const user = authUser(url.searchParams.get('token'))
    if (!user) return ws.close(4401, 'unauthorized')
    const share = db.shares[parts[1]]
    if (!share) return ws.close(4404, 'share_not_found')
    if (!canRead(share, user.id)) return ws.close(4403, 'not_a_member')
    handleConnection(ws, share, user.id)
  })
})

process.on('SIGTERM', () => process.exit(0))
process.on('SIGINT', () => process.exit(0))

server.listen(PORT, HOST, () => console.log(`listening on http://${HOST}:${PORT} (${PUBLIC_URL})`))
