import { spawn } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { Api, type HttpFn, type Perms } from '@plugin/core/api'
import { Cipher, INVITE_PURPOSE, exportPublicKey, fromB64, fromB64Url, fromUtf8, generateDeviceKeys, newKey, openWithSecret, randomBytes, randomId, sealWithSecret, sha256Hex, toB64, toB64Url, utf8, type Keyring } from '@plugin/core/crypto'
import { SyncEngine, type VaultIO } from '@plugin/core/engine'
import { buildVersions } from '@plugin/core/history'
import { LinkMirror, type ExternalFS } from '@plugin/core/mirror'
import { ShareSession, openSharedKey } from '@plugin/core/share'
import { MemoryStore } from '@plugin/core/store'

Object.assign(globalThis, { window: globalThis })

const PORT = 18791
const BASE = `http://127.0.0.1:${PORT}`
const PORT2 = 18792
const BASE2 = `http://127.0.0.1:${PORT2}`
const OWNER = 'owner-token-0123456789abcdef'
let passes = 0
let failures = 0

function check (name: string, ok: boolean, detail?: unknown): void {
  if (ok) { passes++; console.log(`  ok   ${name}`) } else { failures++; console.log(`  FAIL ${name}`, detail ?? '') }
}

async function until (fn: () => boolean | Promise<boolean>, ms = 10000): Promise<boolean> {
  const end = Date.now() + ms
  while (Date.now() < end) {
    if (await fn()) return true
    await new Promise((r) => setTimeout(r, 50))
  }
  return false
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))

async function status (fn: () => Promise<unknown>): Promise<number> {
  try { await fn(); return 200 } catch (e) { return (e as { status?: number }).status ?? -1 }
}

const fetchHttp: HttpFn = async (req) => {
  const res = await fetch(req.url, { method: req.method, headers: req.headers, body: req.body as BodyInit | undefined })
  const buf = await res.arrayBuffer()
  return { status: res.status, text: () => new TextDecoder().decode(buf), arrayBuffer: () => buf }
}

class MemoryVault implements VaultIO {
  files = new Map<string, string | Uint8Array>()
  folders = new Set<string>()
  mtimes = new Map<string, number>()
  listeners: Array<(path: string) => void> = []
  engine: () => SyncEngine | undefined = () => undefined

  touch (p: string): void {
    this.mtimes.set(p, Date.now())
    for (const listener of this.listeners) listener(p)
  }

  stat (p: string): { size: number, mtime: number } | null {
    const v = this.files.get(p)
    if (v === undefined) return null
    return { size: typeof v === 'string' ? new TextEncoder().encode(v).length : v.length, mtime: this.mtimes.get(p) ?? 0 }
  }

  listFiles (root: string): string[] { return Array.from(this.files.keys()).filter((p) => p.startsWith(root + '/')) }
  listFolders (root: string): string[] { return Array.from(this.folders).filter((p) => p.startsWith(root + '/')) }

  async ensureFolder (p: string): Promise<void> {
    this.mkdirs(p + '/_')
    this.touch(p)
  }

  userMkdir (p: string): void {
    this.mkdirs(p + '/_')
    this.touch(p)
    this.engine()?.onLocalFolder(p)
  }
  isFile (p: string): boolean { return this.files.has(p) }
  isFolder (p: string): boolean { return this.folders.has(p) }
  async read (p: string): Promise<string> {
    const v = this.files.get(p)
    if (typeof v !== 'string') throw new Error(`not text: ${p}`)
    return v
  }

  async readBinary (p: string): Promise<ArrayBuffer> {
    const v = this.files.get(p)
    if (v === undefined) throw new Error(`missing: ${p}`)
    const bytes = typeof v === 'string' ? new TextEncoder().encode(v) : v
    return bytes.slice().buffer
  }

  mkdirs (p: string): void {
    const parts = p.split('/')
    for (let i = 1; i < parts.length; i++) this.folders.add(parts.slice(0, i).join('/'))
  }

  private echo (fn: (e: SyncEngine) => void): void {
    setTimeout(() => { const e = this.engine(); if (e) fn(e) }, 1)
  }

  async write (p: string, text: string): Promise<void> {
    await sleep(2)
    this.mkdirs(p); this.files.set(p, text); this.touch(p)
    this.echo((e) => e.onLocalChange(p))
  }

  async writeBinary (p: string, data: ArrayBuffer): Promise<void> {
    this.mkdirs(p); this.files.set(p, new Uint8Array(data.slice(0))); this.touch(p)
    this.echo((e) => e.onLocalChange(p))
  }

  async rename (from: string, to: string): Promise<void> {
    const v = this.files.get(from)
    if (v === undefined) return
    this.files.delete(from); this.mkdirs(to); this.files.set(to, v); this.touch(from); this.touch(to)
    this.echo((e) => e.onLocalRename(from, to, false))
  }

  async remove (p: string): Promise<void> {
    this.files.delete(p); this.touch(p)
    this.echo((e) => e.onLocalDelete(p))
  }

  isEmptyFolder (p: string): boolean {
    if (!this.folders.has(p)) return false
    const prefix = p + '/'
    return !Array.from(this.files.keys()).some((f) => f.startsWith(prefix)) && !Array.from(this.folders).some((d) => d.startsWith(prefix))
  }

  async removeFolder (p: string): Promise<void> {
    if (!this.isEmptyFolder(p)) return
    this.folders.delete(p)
    this.touch(p)
    this.echo((e) => e.onLocalDelete(p))
  }

  userWrite (p: string, content: string | Uint8Array): void { this.mkdirs(p); this.files.set(p, content); this.touch(p); this.engine()?.onLocalChange(p) }

  userDelete (p: string): void {
    if (this.files.delete(p)) { this.engine()?.onLocalDelete(p); return }
    for (const f of Array.from(this.files.keys())) if (f.startsWith(p + '/')) { this.files.delete(f); this.engine()?.onLocalDelete(f) }
    for (const d of Array.from(this.folders)) if (d === p || d.startsWith(p + '/')) this.folders.delete(d)
    this.engine()?.onLocalDelete(p)
  }

  userRename (from: string, to: string): void {
    const v = this.files.get(from)
    if (v !== undefined) {
      this.files.delete(from); this.mkdirs(to); this.files.set(to, v)
      this.engine()?.onLocalRename(from, to, false)
      return
    }
    for (const [f, val] of Array.from(this.files)) {
      if (f.startsWith(from + '/')) { this.files.delete(f); const n = to + f.slice(from.length); this.mkdirs(n); this.files.set(n, val) }
    }
    for (const d of Array.from(this.folders)) {
      if (d === from || d.startsWith(from + '/')) { this.folders.delete(d); this.folders.add(to + d.slice(from.length)) }
    }
    this.mkdirs(to + '/_')
    this.engine()?.onLocalRename(from, to, true)
  }

  text (p: string): string | undefined { const v = this.files.get(p); return typeof v === 'string' ? v : undefined }
}

interface Client {
  name: string
  base: string
  userId: string
  secret: string
  keys: CryptoKeyPair
  api: Api
  vault: MemoryVault
  stores: Map<string, MemoryStore>
  session?: ShareSession
  engine?: SyncEngine
  codes: number[]
  open: Set<string>
  denied: string[]
  conflicts: string[]
  rootMissing: number
}

async function makeClient (name: string): Promise<Client> {
  const keys = await generateDeviceKeys()
  const userId = `user-${name}-${Math.random().toString(16).slice(2, 10)}`
  const secret = toB64Url(randomBytes(32))
  const c = { name, base: BASE, userId, secret, keys, vault: new MemoryVault(), stores: new Map(), codes: [], open: new Set(), denied: [], conflicts: [], rootMissing: 0 } as unknown as Client
  c.api = new Api(fetchHttp, () => c.base, () => `${userId}.${secret}`, (location) => { c.base = location; c.session?.reconnect() })
  await c.api.register(userId, secret, await exportPublicKey(keys.publicKey))
  return c
}

async function sameIdentity (src: Client, name: string): Promise<Client> {
  const c = { name, base: src.base, userId: src.userId, secret: src.secret, keys: src.keys, vault: new MemoryVault(), stores: new Map(), codes: [], open: new Set(), denied: [], conflicts: [], rootMissing: 0 } as unknown as Client
  c.api = new Api(fetchHttp, () => c.base, () => `${c.userId}.${c.secret}`, (location) => { c.base = location; c.session?.reconnect() })
  return c
}

async function start (c: Client, shareId: string, root: string, keyring?: Keyring): Promise<void> {
  let store = c.stores.get(shareId)
  if (!store) { store = new MemoryStore(); c.stores.set(shareId, store) }
  c.vault.folders.add(root)
  let engine: SyncEngine | null = null
  const session = new ShareSession({
    shareId,
    store,
    api: c.api,
    wsUrl: () => c.base.replace(/^http/, 'ws') + '/ws',
    identity: { userId: c.userId, privateKey: c.keys.privateKey, token: () => `${c.userId}.${c.secret}` },
    onReady: () => { void engine?.onReady() },
    onResynced: () => { void engine?.retryPending() },
    onAccessLost: (code) => { c.codes.push(code) },
    onMoved: () => { void c.api.checkMoved() }
  })
  await session.load()
  if (keyring) session.setKeyring(keyring)
  engine = new SyncEngine({
    session,
    root,
    io: c.vault,
    onRootMissing: () => { c.rootMissing++ },
    onConflict: (p) => { c.conflicts.push(p) },
    onDenied: (m) => { c.denied.push(m) },
    isOpen: (p) => c.open.has(p)
  })
  await engine.loadBase()
  const e = engine
  c.vault.engine = () => e
  c.session = session
  c.engine = engine
  await engine.reconcileOffline()
  session.start()
  await until(() => session.ready)
  await engine.idle()
}

async function stop (c: Client): Promise<void> {
  c.engine?.destroy()
  await c.session?.close()
  c.vault.engine = () => undefined
}

async function settle (...clients: Client[]): Promise<void> {
  for (let round = 0; round < 2; round++) {
    await sleep(400)
    for (const c of clients) await c.engine?.idle()
  }
}

async function createShare (owner: Client, folder: string, ownerName: string): Promise<{ id: string, keyring: Keyring }> {
  const id = randomId()
  const keyring: Keyring = [newKey(0)]
  const cipher = new Cipher(keyring)
  await owner.api.createShare(id, await cipher.encryptText(`${id}:share-name`, folder), await cipher.encryptText(`${id}:member-name:${owner.userId}`, ownerName), await cipher.encryptText(`${id}:share-path`, folder))
  return { id, keyring }
}

async function invite (owner: Client, shareId: string, perms: Perms): Promise<{ token: string, secret: string }> {
  const secret = randomBytes(32)
  const sealed = await sealWithSecret(secret, INVITE_PURPOSE, utf8(JSON.stringify(owner.session!.cipher.ring)))
  const { token } = await owner.api.createInvite(shareId, perms, toB64(sealed))
  return { token, secret: toB64Url(secret) }
}

async function join (c: Client, inv: { token: string, secret: string }, name: string): Promise<{ shareId: string, keyring: Keyring, folder: string, path: string | null }> {
  const record = await c.api.getInvite(inv.token)
  const keyring = JSON.parse(fromUtf8(await openWithSecret(fromB64Url(inv.secret), INVITE_PURPOSE, fromB64(record.keyring)))) as Keyring
  const cipher = new Cipher(keyring)
  const folder = await cipher.decryptText(`${record.shareId}:share-name`, record.shareNameEnc)
  const path = record.pathEnc ? await cipher.decryptText(`${record.shareId}:share-path`, record.pathEnc) : null
  const summary = await c.api.acceptInvite(inv.token, await cipher.encryptText(`${record.shareId}:member-name:${c.userId}`, name))
  return { shareId: summary.id, keyring, folder, path }
}

const bytes = (n: number, seed: number): Uint8Array => Uint8Array.from({ length: n }, (_, i) => (i * 31 + seed) % 256)
const same = (a: unknown, b: Uint8Array): boolean => a instanceof Uint8Array && a.length === b.length && a.every((v, i) => v === b[i])

function readAll (dir: string): string {
  let out = ''
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name)
    out += entry.isDirectory() ? readAll(p) : fs.readFileSync(p).toString('latin1')
  }
  return out
}

const nodeExternal: ExternalFS = {
  exists: async (dir) => { try { return fs.statSync(dir).isDirectory() } catch { return false } },
  list: async (dir) => {
    const files: string[] = []
    const dirs: string[] = []
    const walk = (abs: string, prefix: string): void => {
      for (const e of fs.readdirSync(abs, { withFileTypes: true })) {
        if (e.name.startsWith('.')) continue
        const rel = prefix ? `${prefix}/${e.name}` : e.name
        if (e.isDirectory()) { dirs.push(rel); walk(path.join(abs, e.name), rel) } else if (e.isFile()) files.push(rel)
      }
    }
    walk(dir, '')
    return { files, dirs }
  },
  makeDir: async (dir, rel) => { fs.mkdirSync(path.join(dir, rel), { recursive: true }) },
  removeDir: async (dir, rel) => { try { fs.rmdirSync(path.join(dir, rel)); return true } catch { return !fs.existsSync(path.join(dir, rel)) } },
  stat: async (dir, rel) => { try { const st = fs.statSync(path.join(dir, rel)); return st.isFile() ? { size: st.size, mtime: st.mtimeMs } : null } catch { return null } },
  read: async (dir, rel) => new Uint8Array(fs.readFileSync(path.join(dir, rel))),
  write: async (dir, rel, data) => { const t = path.join(dir, rel); fs.mkdirSync(path.dirname(t), { recursive: true }); fs.writeFileSync(t, data) },
  remove: async (dir, rel) => { fs.rmSync(path.join(dir, rel), { force: true }) },
  watch: (dir, onChange) => { const w = fs.watch(dir, { recursive: true }, onChange); return () => w.close() }
}

function spawnServer (port: number, dataDir: string, base: string, extra: Record<string, string> = {}): ReturnType<typeof spawn> {
  return spawn(process.execPath, [path.resolve('server.mjs')], {
    env: { ...process.env, PORT: String(port), DATA_DIR: dataDir, PUBLIC_URL: base, ...extra },
    stdio: ['ignore', 'inherit', 'inherit']
  })
}

async function healthy (base: string): Promise<boolean> {
  return until(async () => { try { return (await fetch(`${base}/health`)).ok } catch { return false } })
}

async function main (): Promise<void> {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'collaboration-test-'))
  const dataDir2 = fs.mkdtempSync(path.join(os.tmpdir(), 'collaboration-test2-'))
  let liveData = dataDir
  fs.writeFileSync(path.join(dataDir, 'owner-token'), OWNER + '\n')
  let server = spawnServer(PORT, dataDir, BASE)
  let server2: ReturnType<typeof spawn> | null = null
  try {
    await healthy(BASE)
    const A = await makeClient('alice')
    const B = await makeClient('bob')
    const C = await makeClient('carol')
    const D = await makeClient('dave')

    console.log('owner setup')
    check('sharing needs the owner link', await status(() => A.api.createShare(randomId(), 'x', 'y')) === 403)
    check('wrong setup token rejected', await status(() => B.api.claimOwner('wrong-token-0123456789')) === 403)
    check('setup page shown with the token', (await fetch(`${BASE}/setup/${OWNER}`)).status === 200)
    await A.api.claimOwner(OWNER)
    check('setup link works only once', (await fetch(`${BASE}/setup/${OWNER}`)).status === 404 && await status(() => C.api.claimOwner(OWNER)) === 403)

    console.log('share, invite, join')
    const png = bytes(5000, 7)
    A.vault.userWrite('Proj/a.md', 'Hello\n')
    A.vault.userWrite('Proj/sub/b.md', 'B file\n')
    A.vault.userWrite('Proj/img.png', png)
    const share = await createShare(A, 'Proj', 'Alice')
    const shareId = share.id
    await start(A, shareId, 'Proj', share.keyring)
    await settle(A)
    const invB = await invite(A, shareId, { read: true, write: true, delete: true })
    const invC = await invite(A, shareId, { read: true, write: false, delete: false })
    const invD = await invite(A, shareId, { read: true, write: true, delete: false })
    const page = await (await fetch(`${BASE}/join/${invB.token}`)).text()
    check('join page has no plaintext names', !page.includes('Proj') && !page.includes('Alice') && page.includes('collaboration-invite-v1'))
    const jB = await join(B, invB, 'Bob')
    check('invite decrypts the folder name', jB.folder === 'Proj')
    check('invite works only once', await status(() => C.api.acceptInvite(invB.token, 'x')) === 410)
    const jC = await join(C, invC, 'Carol')
    const jD = await join(D, invD, 'Dave')
    await start(B, shareId, 'Proj', jB.keyring)
    await start(C, shareId, 'Proj', jC.keyring)
    await start(D, shareId, 'Proj', jD.keyring)
    await settle(A, B, C, D)
    for (const c of [B, C, D]) {
      check(`${c.name} got the folder`, c.vault.text('Proj/a.md') === 'Hello\n' && c.vault.text('Proj/sub/b.md') === 'B file\n' && same(c.vault.files.get('Proj/img.png'), png), Array.from(c.vault.files.keys()))
    }

    console.log('end-to-end encryption')
    const stored = readAll(dataDir)
    check('server stores no plaintext', !['Hello', 'B file', 'Proj', 'Alice', 'Bob', 'Carol', 'a.md', 'sub/b.md', 'img.png'].some((s) => stored.includes(s)))
    check('member names decrypt for members', B.session!.memberName(C.userId) === 'Carol' && B.session!.memberName(A.userId) === 'Alice')

    console.log('live editing and owner offline')
    A.vault.userWrite('Proj/a.md', 'Hello world\n')
    check('edit reaches everyone', await until(() => [B, C, D].every((c) => c.vault.text('Proj/a.md') === 'Hello world\n')))
    await stop(A)
    B.vault.userWrite('Proj/a.md', 'Hello world\nfrom Bob\n')
    check('edits sync while the owner is offline', await until(() => C.vault.text('Proj/a.md') === 'Hello world\nfrom Bob\n' && D.vault.text('Proj/a.md') === 'Hello world\nfrom Bob\n'))
    D.vault.userWrite('Proj/dave.md', 'dave\n')
    check('new files sync while the owner is offline', await until(() => B.vault.text('Proj/dave.md') === 'dave\n'))
    await start(A, shareId, 'Proj')
    await settle(A, B, C, D)
    check('owner catches up', A.vault.text('Proj/a.md') === 'Hello world\nfrom Bob\n' && A.vault.text('Proj/dave.md') === 'dave\n')

    console.log('speed')
    const speedFile = A.session!.fileAt('a.md')!
    const typed = B.engine!.bind(speedFile, B.vault.text('Proj/a.md')!)
    const t0 = Date.now()
    B.session!.doc(speedFile).transact(() => typed.ytext.insert(0, 'Z'), 'editor')
    await until(() => A.session!.text(speedFile).toJSON().startsWith('Z'), 3000)
    const latency = Date.now() - t0
    check(`typing reaches others fast (${latency} ms)`, latency < 300)
    B.session!.doc(speedFile).transact(() => typed.ytext.delete(0, 1), 'editor')
    B.engine!.unbind(speedFile)
    await settle(A, B, C, D)
    check('typing session leaves the file intact', [A, B, C, D].every((c) => c.vault.text('Proj/a.md') === 'Hello world\nfrom Bob\n'))

    console.log('open notes')
    B.vault.userWrite('Proj/live.md', 'one\n')
    check('note for editor tests reaches others', await until(() => A.vault.text('Proj/live.md') === 'one\n'))
    await settle(A, B)
    const liveFile = B.session!.fileAt('live.md')!
    B.engine!.bind(liveFile, 'one\n')
    B.engine!.bind(liveFile, 'one\n')
    B.engine!.unbind(liveFile)
    A.vault.userWrite('Proj/live.md', 'one\ntwo\n')
    await until(() => B.session!.text(liveFile).toJSON() === 'one\ntwo\n')
    await settle(A, B)
    check('a second editor keeps the note from being rewritten on disk', B.vault.text('Proj/live.md') === 'one\n', B.vault.text('Proj/live.md'))
    B.engine!.unbind(liveFile)
    check('closing the last editor writes the note', await until(() => B.vault.text('Proj/live.md') === 'one\ntwo\n'))
    await settle(A, B)
    B.open.add('Proj/live.md')
    A.vault.userWrite('Proj/live.md', 'one\ntwo\nthree\n')
    await until(() => B.session!.text(liveFile).toJSON() === 'one\ntwo\nthree\n')
    await settle(A, B)
    check('an open note is not written underneath its editor', B.vault.text('Proj/live.md') === 'one\ntwo\n', B.vault.text('Proj/live.md'))
    const editor = B.engine!.bind(liveFile, B.vault.text('Proj/live.md')!)
    check('the editor gets the latest text when it connects', editor.ytext.toJSON() === 'one\ntwo\nthree\n', editor.ytext.toJSON())
    B.engine!.unbind(liveFile)
    B.open.delete('Proj/live.md')
    B.engine!.retryDeferred()
    check('the note catches up once the editor is closed', await until(() => B.vault.text('Proj/live.md') === 'one\ntwo\nthree\n'))
    await settle(A, B, C, D)

    console.log('canvas')
    const fmt = (d: unknown): string => JSON.stringify(d, null, '\t')
    const board = {
      nodes: [
        { id: 'n1', type: 'text', text: 'one', x: 0, y: 0, width: 100, height: 60 },
        { id: 'n2', type: 'text', text: 'two', x: 200, y: 0, width: 100, height: 60 }
      ],
      edges: [{ id: 'e1', fromNode: 'n1', fromSide: 'right', toNode: 'n2', toSide: 'left' }]
    }
    type Board = typeof board & { nodes: Array<Record<string, unknown>>, edges: Array<Record<string, unknown>> }
    const read = (c: Client): Board | null => { try { return JSON.parse(c.vault.text('Proj/board.canvas') ?? 'null') as Board } catch { return null } }
    A.vault.userWrite('Proj/board.canvas', fmt(board))
    check('canvas reaches everyone', await until(() => [B, C, D].every((c) => read(c)?.nodes.length === 2 && read(c)?.edges.length === 1)))
    const canvasFile = A.session!.fileAt('board.canvas')!
    check('canvas is synced as a canvas, not a file blob', A.session!.files.get(canvasFile)?.kind === 'canvas')
    const moved = structuredClone(board) as Board
    moved.nodes[0].x = 50
    const retexted = structuredClone(board) as Board
    retexted.nodes[1].text = 'two edited'
    B.vault.userWrite('Proj/board.canvas', fmt(moved))
    D.vault.userWrite('Proj/board.canvas', fmt(retexted))
    check('simultaneous edits to different cards both survive', await until(() => [A, B, C, D].every((c) => {
      const b = read(c)
      return b?.nodes.find((n) => n.id === 'n1')?.x === 50 && b.nodes.find((n) => n.id === 'n2')?.text === 'two edited' && b.edges.length === 1
    })), [A, B, C, D].map((c) => c.vault.text('Proj/board.canvas')))
    await settle(A, B, C, D)
    await stop(D)
    const withCard = read(D)!
    withCard.nodes.push({ id: 'n4', type: 'text', text: 'offline card', x: 0, y: 200, width: 100, height: 60 })
    D.vault.files.set('Proj/board.canvas', fmt(withCard))
    const noEdge = read(B)!
    noEdge.edges = []
    B.vault.userWrite('Proj/board.canvas', fmt(noEdge))
    await settle(A, B, C)
    await start(D, shareId, 'Proj')
    check('offline canvas edits merge', await until(() => [A, B, C, D].every((c) => {
      const b = read(c)
      return !!b && b.nodes.some((n) => n.id === 'n4') && b.edges.length === 0 && b.nodes.find((n) => n.id === 'n1')?.x === 50
    })), [A, B, C, D].map((c) => c.vault.text('Proj/board.canvas')))
    await settle(A, B, C, D)
    const canvasVersions = await buildVersions(A.session!, canvasFile)
    const firstBoard = canvasVersions[canvasVersions.length - 1]
    check('canvas history keeps the original', firstBoard.label === 'created' && JSON.parse(firstBoard.text ?? '{}').nodes?.length === 2)
    A.session!.restoreCanvas(canvasFile, firstBoard.text ?? '')
    check('restoring a canvas version reaches everyone', await until(() => [A, B, C, D].every((c) => {
      const b = read(c)
      return !!b && b.nodes.length === 2 && b.edges.length === 1 && b.nodes.find((n) => n.id === 'n1')?.x === 0 && b.nodes.find((n) => n.id === 'n2')?.text === 'two'
    })), [A, B, C, D].map((c) => c.vault.text('Proj/board.canvas')))

    console.log('folder paths')
    check('the folder path travels with the invite', jB.path === 'Proj', jB.path)
    const E = await makeClient('erin')
    const jE = await join(E, await invite(A, shareId, { read: true, write: true, delete: false }), 'Erin')
    await start(E, shareId, 'Elsewhere/Proj', jE.keyring)
    const readAt = (c: Client, p: string): Board | null => { try { return JSON.parse(c.vault.text(p) ?? 'null') as Board } catch { return null } }
    const withFile = read(A)!
    withFile.nodes.push({ id: 'n5', type: 'file', file: 'Proj/data/pic.png', x: 0, y: 400, width: 200, height: 200 })
    A.vault.userWrite('Proj/board.canvas', fmt(withFile))
    check('canvas file links follow each person’s folder', await until(() =>
      readAt(E, 'Elsewhere/Proj/board.canvas')?.nodes.find((n) => n.id === 'n5')?.file === 'Elsewhere/Proj/data/pic.png' &&
      read(B)?.nodes.find((n) => n.id === 'n5')?.file === 'Proj/data/pic.png'
    ), [readAt(E, 'Elsewhere/Proj/board.canvas'), read(B)])
    const fromE = readAt(E, 'Elsewhere/Proj/board.canvas')!
    fromE.nodes.find((n) => n.id === 'n5')!.x = 300
    E.vault.userWrite('Elsewhere/Proj/board.canvas', fmt(fromE))
    check('edits from another folder keep the owner’s links', await until(() => {
      const n = read(A)?.nodes.find((x) => x.id === 'n5')
      return n?.x === 300 && n.file === 'Proj/data/pic.png'
    }), read(A))
    await stop(E)

    console.log('old canvases')
    const legacyText = fmt({ nodes: [{ id: 'L1', type: 'text', text: 'legacy', x: 0, y: 0, width: 50, height: 50 }], edges: [] })
    const legacyBytes = new TextEncoder().encode(legacyText)
    A.vault.files.set('Proj/legacy.canvas', legacyText)
    await A.session!.createBlob('legacy.canvas', legacyBytes, await sha256Hex(legacyBytes))
    const asText = (v: unknown): string | undefined => typeof v === 'string' ? v : v instanceof Uint8Array ? new TextDecoder().decode(v) : undefined
    check('old-style canvas reaches others as a file', await until(() => asText(B.vault.files.get('Proj/legacy.canvas')) === legacyText))
    await settle(A, B, C, D)
    await stop(A)
    await start(A, shareId, 'Proj')
    await settle(A, B, C, D)
    const kindOf = (c: Client): string | undefined => c.session!.files.get(c.session!.fileAt('legacy.canvas') ?? '')?.kind
    check('owner upgrades old canvases to live canvases', kindOf(A) === 'canvas' && await until(() => kindOf(B) === 'canvas'), [kindOf(A), kindOf(B)])
    check('upgraded canvas keeps its content', [A, B, C, D].every((c) => (readAt(c, 'Proj/legacy.canvas')?.nodes[0] as { text?: string } | undefined)?.text === 'legacy'))

    console.log('permissions')
    C.vault.userWrite('Proj/a.md', 'Carol was here\n')
    await settle(A, B, C, D)
    check('read-only edit is undone locally', C.vault.text('Proj/a.md') === 'Hello world\nfrom Bob\n' && C.denied.length > 0, C.vault.text('Proj/a.md'))
    check('read-only edit never reaches others', A.vault.text('Proj/a.md') === 'Hello world\nfrom Bob\n')
    const forged = await new Promise<string>((resolve) => {
      const ws = new WebSocket(`${BASE.replace(/^http/, 'ws')}/ws/${shareId}?token=${encodeURIComponent(`${C.userId}.${C.secret}`)}`)
      ws.onmessage = (e) => {
        const msg = JSON.parse(String(e.data)) as { t: string, code?: string }
        if (msg.t === 'welcome') {
          void C.session!.cipher.encrypt('x', utf8('x')).then((p) => ws.send(JSON.stringify({ t: 'ev', cid: randomId(), type: 'update', f: A.session!.fileAt('a.md'), d: toB64(p) })))
        }
        if (msg.t === 'err') { resolve(msg.code ?? ''); ws.close() }
      }
      setTimeout(() => resolve('timeout'), 5000)
    })
    check('server rejects forged edits from read-only members', forged === 'forbidden', forged)
    D.vault.userDelete('Proj/dave.md')
    await settle(A, B, C, D)
    check('delete without permission is undone', D.vault.text('Proj/dave.md') === 'dave\n' && A.vault.text('Proj/dave.md') === 'dave\n')
    const daveFile = A.session!.fileAt('dave.md')!
    B.vault.userDelete('Proj/dave.md')
    check('delete with permission reaches everyone', await until(() => [A, C, D].every((c) => !c.vault.isFile('Proj/dave.md'))))
    check('deleted files are listed', A.session!.deletedFiles().some((f) => f.id === daveFile && f.changedBy === B.userId))
    B.session!.restore(daveFile)
    check('restoring a deleted file reaches everyone', await until(() => [A, C, D].every((c) => c.vault.text('Proj/dave.md') === 'dave\n')))

    console.log('renames and history')
    const aFile = A.session!.fileAt('a.md')!
    A.vault.userRename('Proj/a.md', 'Proj/notes/a.md')
    check('rename reaches everyone', await until(() => [B, C, D].every((c) => c.vault.text('Proj/notes/a.md') === 'Hello world\nfrom Bob\n' && !c.vault.isFile('Proj/a.md'))))
    check('rename keeps the file identity', B.session!.fileAt('notes/a.md') === aFile)
    const versions = await buildVersions(B.session!, aFile)
    const labels = versions.map((v) => v.label)
    check('history has created, edited and renamed versions', labels.includes('created') && labels.includes('edited') && labels.includes('renamed'), labels)
    check('history shows the right authors', versions[versions.length - 1].author === A.userId && versions.some((v) => v.author === B.userId))
    const oldest = versions[versions.length - 1]
    check('oldest version has the original text', oldest.text === 'Hello\n', oldest.text)
    B.session!.restoreText(aFile, oldest.text ?? '')
    check('restoring a version reaches everyone', await until(() => [A, C, D].every((c) => c.vault.text('Proj/notes/a.md') === 'Hello\n')))
    const png2 = bytes(4000, 9)
    A.vault.userWrite('Proj/img.png', png2)
    check('replaced attachment reaches everyone', await until(() => [B, C, D].every((c) => same(c.vault.files.get('Proj/img.png'), png2))))
    const imgFile = A.session!.fileAt('img.png')!
    const imgVersions = await buildVersions(A.session!, imgFile)
    const firstImg = imgVersions.find((v) => v.label === 'created')
    check('attachment history has both versions', imgVersions.some((v) => v.label === 'replaced') && !!firstImg?.blob)
    if (firstImg?.blob) B.session!.setBlob(imgFile, firstImg.blob)
    check('restoring an attachment version reaches everyone', await until(() => [A, C, D].every((c) => same(c.vault.files.get('Proj/img.png'), png))))

    console.log('names')
    C.session!.awareness.setLocalStateField('user', { name: 'Alice', color: '#000', colorLight: '#0003' })
    C.session!.awareness.setLocalStateField('cursor', { anchor: null, head: null })
    const cId = C.session!.awareness.clientID
    check('cursor names come from the server, not the sender', await until(() => (B.session!.awareness.getStates().get(cId) as { user?: { name?: string } } | undefined)?.user?.name === 'Carol'))
    check('members cannot rename themselves', await status(() => B.api.updateMember(shareId, B.userId, { nameEnc: 'x' })) === 403)
    await A.api.updateMember(shareId, C.userId, { nameEnc: await A.session!.cipher.encryptText(A.session!.memberAad(C.userId), 'Caroline') })
    check('owner can rename members', await until(() => B.session!.memberName(C.userId) === 'Caroline'))

    console.log('offline merges and conflicts')
    await settle(A, B, C, D)
    await stop(D)
    B.vault.userWrite('Proj/notes/a.md', 'B line\nHello\n')
    await settle(A, B, C)
    D.vault.files.set('Proj/notes/a.md', 'Hello\nD line\n')
    await start(D, shareId, 'Proj')
    const mergedText = 'B line\nHello\nD line\n'
    check('offline edits merge for everyone', await until(() => [A, B, C, D].every((c) => c.vault.text('Proj/notes/a.md') === mergedText)), [A, B, C, D].map((c) => c.vault.text('Proj/notes/a.md')))
    await settle(A, B, C, D)
    await stop(B)
    await stop(D)
    B.vault.files.set('Proj/same.md', 'from B\n')
    D.vault.files.set('Proj/same.md', 'from D\n')
    await start(B, shareId, 'Proj')
    await start(D, shareId, 'Proj')
    await settle(A, B, C, D)
    const conflictCopy = Array.from(A.vault.files.keys()).find((p) => p.startsWith('Proj/same (conflict'))
    check('conflicting new files are both kept', A.vault.text('Proj/same.md') === 'from B\n' && !!conflictCopy && A.vault.text(conflictCopy) === 'from D\n', Array.from(A.vault.files.keys()))
    check('everyone ends up with the same files', [B, C, D].every((c) => JSON.stringify(Array.from(c.vault.files.keys()).sort()) === JSON.stringify(Array.from(A.vault.files.keys()).sort())))

    console.log('removing someone rotates the key')
    const stale = await invite(A, shareId, { read: true, write: true, delete: false })
    await A.api.removeMember(shareId, D.userId)
    const members = await A.api.members(shareId)
    await A.session!.rotateKeys(members.members.filter((m) => m.userId !== D.userId).map((m) => ({ userId: m.userId, publicKey: m.publicKey })))
    check('removed member is disconnected', await until(() => D.codes.includes(4403)))
    check('removed member loses the folder', !(await D.api.listShares()).some((s) => s.id === shareId))
    check('remaining members get the new key', await until(() => B.session!.cipher.epoch === 1 && C.session!.cipher.epoch === 1))
    check('unused invites are cancelled on rotation', await status(() => C.api.getInvite(stale.token)) === 410)
    B.vault.userWrite('Proj/after.md', 'written after rotation\n')
    check('editing continues with the new key', await until(() => C.vault.text('Proj/after.md') === 'written after rotation\n'))
    const log = fs.readFileSync(path.join(dataDir, 'shares', shareId, 'log.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l) as { d?: string, type: string, f: string })
    const latest = log.reverse().find((e) => e.type === 'update' && e.d)!
    let dCanRead = true
    try { await D.session!.cipher.decrypt(`${shareId}:${latest.f}:content`, fromB64(latest.d!)) } catch { dCanRead = false }
    check('removed member cannot decrypt new changes', !dCanRead)
    await stop(D)

    console.log('your other devices')
    const laptop = await sameIdentity(A, 'alice-laptop')
    const desk = await sameIdentity(A, 'alice-desk')
    laptop.vault.userWrite('Desk/plan.md', 'plan\n')
    const deskShare = await createShare(laptop, 'Desk', 'Alice')
    await start(laptop, deskShare.id, 'Desk', deskShare.keyring)
    await settle(laptop)
    check('a new share has no key copy for your other devices yet', await openSharedKey(desk.api, deskShare.id, desk.keys.privateKey) === null)
    await laptop.session!.keepKeyForSelf(await exportPublicKey(laptop.keys.publicKey))
    const listed = (await desk.api.listShares()).find((s) => s.id === deskShare.id)
    const deskRing = await openSharedKey(desk.api, deskShare.id, desk.keys.privateKey)
    check('your other device sees the share and can open its key', listed?.role === 'owner' && deskRing !== null)
    await start(desk, deskShare.id, 'Desk', deskRing!)
    check('your other device gets the folder', await until(() => desk.vault.text('Desk/plan.md') === 'plan\n'))
    desk.vault.userWrite('Desk/plan.md', 'plan\nfrom the desk\n')
    check('both devices edit the same folder', await until(() => laptop.vault.text('Desk/plan.md') === 'plan\nfrom the desk\n'))
    check('a stale key copy is refused', await status(() => laptop.api.putKeyEnvelope(shareId, 0, 'x'.repeat(40))) === 400)
    check('only people in the share can store a key copy', await status(() => B.api.putKeyEnvelope(deskShare.id, 0, 'x'.repeat(40))) === 404)
    await stop(desk)
    await stop(laptop)
    await A.api.deleteShare(deskShare.id)

    console.log('restart after offline edits')
    await settle(A, B, C)
    await stop(B)
    A.vault.userWrite('Proj/notes/a.md', mergedText + 'A after\n')
    await settle(A, C)
    B.vault.files.set('Proj/notes/a.md', 'B before\n' + mergedText)
    await start(B, shareId, 'Proj')
    const both = 'B before\n' + mergedText + 'A after\n'
    check('restart merges both sides', await until(() => A.vault.text('Proj/notes/a.md') === both && B.vault.text('Proj/notes/a.md') === both), [A.vault.text('Proj/notes/a.md'), B.vault.text('Proj/notes/a.md')])

    console.log('deleting')
    B.vault.userWrite('Proj/tmp/open.md', 'temp\n')
    check('new note reaches others', await until(() => A.vault.text('Proj/tmp/open.md') === 'temp\n'))
    await settle(A, B, C)
    const openFile = B.session!.fileAt('tmp/open.md')!
    B.engine!.bind(openFile, 'temp\n')
    B.vault.userDelete('Proj/tmp/open.md')
    await sleep(60)
    B.engine!.unbind(openFile)
    await settle(A, B, C)
    check('deleting the open note sticks', !B.vault.isFile('Proj/tmp/open.md') && !A.vault.isFile('Proj/tmp/open.md') && !C.vault.isFile('Proj/tmp/open.md'), [B.vault.isFile('Proj/tmp/open.md'), A.vault.isFile('Proj/tmp/open.md')])
    check('emptied folders are removed for others', !A.vault.folders.has('Proj/tmp') && !C.vault.folders.has('Proj/tmp'))
    A.vault.userWrite('Proj/old/x.md', 'x\n')
    A.vault.userWrite('Proj/old/deep/y.md', 'y\n')
    check('nested files reach others', await until(() => B.vault.text('Proj/old/x.md') === 'x\n' && B.vault.text('Proj/old/deep/y.md') === 'y\n'))
    await settle(A, B, C)
    A.vault.userDelete('Proj/old')
    check('deleting a folder removes it everywhere', await until(() => [B, C].every((c) => !c.vault.isFile('Proj/old/x.md') && !c.vault.isFile('Proj/old/deep/y.md') && !c.vault.folders.has('Proj/old') && !c.vault.folders.has('Proj/old/deep'))), Array.from(B.vault.folders))
    A.vault.userWrite('Proj/move/z.md', 'z\n')
    check('file in folder reaches others', await until(() => B.vault.text('Proj/move/z.md') === 'z\n'))
    await settle(A, B, C)
    A.vault.userRename('Proj/move', 'Proj/moved')
    check('moving a folder leaves no empty folder behind', await until(() => B.vault.text('Proj/moved/z.md') === 'z\n' && !B.vault.folders.has('Proj/move')), Array.from(B.vault.folders))

    console.log('folders')
    await settle(A, B, C)
    A.vault.userMkdir('Proj/empty')
    check('an empty folder reaches everyone', await until(() => B.vault.isFolder('Proj/empty') && C.vault.isFolder('Proj/empty')))
    A.vault.userMkdir('Proj/empty/inner')
    check('a nested empty folder reaches everyone', await until(() => B.vault.isFolder('Proj/empty/inner')))
    await settle(A, B, C)
    A.vault.userRename('Proj/empty', 'Proj/renamed')
    check('renaming an empty folder renames it everywhere', await until(() => B.vault.isFolder('Proj/renamed/inner') && !B.vault.isFolder('Proj/empty') && C.vault.isFolder('Proj/renamed/inner')), Array.from(B.vault.folders).filter((d) => d.includes('empty') || d.includes('renamed')))
    A.vault.userWrite('Proj/renamed/inner/n.md', 'n\n')
    check('a note in it reaches everyone', await until(() => B.vault.text('Proj/renamed/inner/n.md') === 'n\n'))
    await settle(A, B, C)
    A.vault.userDelete('Proj/renamed/inner/n.md')
    await until(() => !B.vault.isFile('Proj/renamed/inner/n.md'))
    await settle(A, B, C)
    check('emptying a folder keeps it for everyone', B.vault.isFolder('Proj/renamed/inner') && C.vault.isFolder('Proj/renamed/inner'))
    B.vault.userMkdir('Proj/renamed/fromB')
    check('a member’s new folder reaches the owner', await until(() => A.vault.isFolder('Proj/renamed/fromB')))
    await settle(A, B, C)
    A.vault.userDelete('Proj/renamed')
    check('deleting a folder removes it and its empty folders everywhere', await until(() => [B, C].every((c) => !Array.from(c.vault.folders).some((d) => d === 'Proj/renamed' || d.startsWith('Proj/renamed/')))), Array.from(B.vault.folders))
    C.vault.userMkdir('Proj/fromC')
    await sleep(800)
    check('a read-only member’s new folder stays on their computer', !A.vault.isFolder('Proj/fromC') && C.vault.isFolder('Proj/fromC'))
    C.vault.userDelete('Proj/fromC')

    console.log('folder links')
    await settle(A, B, C)
    const linkRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'collaboration-link-'))
    const exportDir = path.join(linkRoot, 'export')
    fs.mkdirSync(exportDir)
    A.vault.userWrite('Proj/Sound/s1.wav', bytes(2000, 1))
    check('sound folder reaches others', await until(() => same(B.vault.files.get('Proj/Sound/s1.wav'), bytes(2000, 1))))
    await settle(A, B, C)
    fs.writeFileSync(path.join(exportDir, 's2.wav'), bytes(3000, 2))
    fs.writeFileSync(path.join(exportDir, 's1.wav'), bytes(2000, 9))
    const future = new Date(Date.now() + 60000)
    fs.utimesSync(path.join(exportDir, 's1.wav'), future, future)
    const linkConflicts: string[] = []
    const mirror = new LinkMirror({ vaultDir: () => 'Proj/Sound', external: exportDir, io: B.vault, fs: nodeExternal, load: async () => ({}), save: async () => undefined, onConflict: (p) => { linkConflicts.push(p) }, onFolder: (p) => B.vault.engine()?.onLocalFolder(p) })
    B.vault.listeners.push((p) => { if (mirror.covers(p)) mirror.schedule() })
    await mirror.start()
    check('linking merges files both ways', await until(() => same(A.vault.files.get('Proj/Sound/s2.wav'), bytes(3000, 2))), Array.from(A.vault.files.keys()).filter((k) => k.includes('Sound')))
    check('the newer copy wins a conflict and the older is kept', await until(() => same(A.vault.files.get('Proj/Sound/s1.wav'), bytes(2000, 9)) && linkConflicts.length === 1 && fs.readdirSync(exportDir).some((n) => n.startsWith('s1 (conflict'))), [linkConflicts, fs.readdirSync(exportDir)])
    fs.writeFileSync(path.join(exportDir, 'new.wav'), bytes(1500, 4))
    check('a file added to the linked folder reaches everyone', await until(() => same(A.vault.files.get('Proj/Sound/new.wav'), bytes(1500, 4)) && same(C.vault.files.get('Proj/Sound/new.wav'), bytes(1500, 4))))
    A.vault.userWrite('Proj/Sound/fromA.wav', bytes(1800, 5))
    check('a shared file reaches the linked folder', await until(() => fs.existsSync(path.join(exportDir, 'fromA.wav')) && same(new Uint8Array(fs.readFileSync(path.join(exportDir, 'fromA.wav'))), bytes(1800, 5))))
    fs.rmSync(path.join(exportDir, 's2.wav'))
    check('deleting in the linked folder deletes for everyone', await until(() => !A.vault.isFile('Proj/Sound/s2.wav') && !B.vault.isFile('Proj/Sound/s2.wav')))
    await settle(A, B, C)
    await mirror.idle()
    fs.renameSync(exportDir, exportDir + '-away')
    mirror.schedule(0)
    await sleep(600)
    check('a missing linked folder pauses instead of deleting', mirror.paused && A.vault.isFile('Proj/Sound/new.wav') && B.vault.isFile('Proj/Sound/new.wav'))
    fs.renameSync(exportDir + '-away', exportDir)
    mirror.resume()
    await sleep(600)
    await settle(A, B, C)
    fs.mkdirSync(path.join(exportDir, 'drafts', 'old'), { recursive: true })
    check('an empty folder in the linked folder reaches everyone', await until(() => A.vault.isFolder('Proj/Sound/drafts/old') && C.vault.isFolder('Proj/Sound/drafts/old')))
    A.vault.userMkdir('Proj/Sound/takes')
    check('an empty shared folder reaches the linked folder', await until(() => fs.existsSync(path.join(exportDir, 'takes'))))
    await settle(A, B, C)
    A.vault.userDelete('Proj/Sound/drafts')
    check('deleting a shared folder removes it from the linked folder', await until(() => !fs.existsSync(path.join(exportDir, 'drafts')) && !B.vault.isFolder('Proj/Sound/drafts')), fs.readdirSync(exportDir))
    await settle(A, B, C)
    fs.rmdirSync(path.join(exportDir, 'takes'))
    check('deleting a folder in the linked folder deletes it for everyone', await until(() => !A.vault.isFolder('Proj/Sound/takes') && !C.vault.isFolder('Proj/Sound/takes')))
    await settle(A, B, C)
    check('resuming carries on', !mirror.paused && fs.existsSync(path.join(exportDir, 'new.wav')) && B.vault.isFile('Proj/Sound/new.wav'))
    mirror.stop()
    const readDir = path.join(linkRoot, 'read')
    fs.mkdirSync(readDir)
    let refused = 0
    const readMirror = new LinkMirror({ vaultDir: () => 'Proj/Sound', external: readDir, io: C.vault, fs: nodeExternal, load: async () => ({}), save: async () => undefined, canWrite: () => C.session!.canWrite, canDelete: () => C.session!.canDelete, onRefused: () => { refused++ } })
    C.vault.listeners.push((p) => { if (readMirror.covers(p)) readMirror.schedule() })
    await readMirror.start()
    check('a read-only member’s linked folder gets the files', fs.existsSync(path.join(readDir, 'new.wav')) && fs.existsSync(path.join(readDir, 'fromA.wav')))
    fs.writeFileSync(path.join(readDir, 'mine.wav'), bytes(900, 6))
    fs.writeFileSync(path.join(readDir, 'new.wav'), bytes(1500, 8))
    fs.rmSync(path.join(readDir, 'fromA.wav'))
    readMirror.schedule(0)
    await sleep(1500)
    await readMirror.idle()
    await settle(A, B, C)
    const readState = { newWav: same(new Uint8Array(fs.readFileSync(path.join(readDir, 'new.wav'))), bytes(1500, 8)), mine: fs.existsSync(path.join(readDir, 'mine.wav')), fromA: fs.existsSync(path.join(readDir, 'fromA.wav')), sharedNew: same(A.vault.files.get('Proj/Sound/new.wav'), bytes(1500, 4)), sharedMine: A.vault.isFile('Proj/Sound/mine.wav'), sharedFromA: A.vault.isFile('Proj/Sound/fromA.wav'), refused }
    check('a read-only member’s own changes stay on their computer', readState.newWav && readState.mine && !readState.fromA && readState.sharedNew && !readState.sharedMine && readState.sharedFromA && refused > 0, readState)
    A.vault.userWrite('Proj/Sound/new.wav', bytes(1500, 3))
    check('a newer shared version still reaches them and keeps theirs as a copy', await until(() => same(new Uint8Array(fs.readFileSync(path.join(readDir, 'new.wav'))), bytes(1500, 3)) && fs.readdirSync(readDir).some((n) => n.startsWith('new (conflict'))), fs.readdirSync(readDir))
    readMirror.stop()
    fs.rmSync(linkRoot, { recursive: true, force: true })

    console.log('large files')
    const big = new Uint8Array(60 * 1024 * 1024)
    big.fill(7)
    big[123] = 1
    big[big.length - 1] = 2
    A.vault.userWrite('Proj/Sound/big.wav', big)
    check('files above the old 50 MB limit sync', await until(() => {
      const got = B.vault.files.get('Proj/Sound/big.wav')
      return got instanceof Uint8Array && got.length === big.length && got[123] === 1 && got[got.length - 1] === 2
    }, 60000))

    console.log('server move')
    await settle(A, B, C)
    const exited = new Promise((resolve) => server.once('exit', resolve))
    server.kill('SIGTERM')
    await exited
    fs.cpSync(dataDir, dataDir2, { recursive: true })
    server2 = spawnServer(PORT2, dataDir2, BASE2)
    await healthy(BASE2)
    server = spawnServer(PORT, dataDir, BASE, { MOVED_TO: BASE2 })
    await healthy(BASE)
    liveData = dataDir2
    check('the old server says where it moved', ((await (await fetch(`${BASE}/health`)).json()) as { moved?: string }).moved === BASE2)
    check('everyone follows the move', await until(() => [A, B, C].every((c) => c.base === BASE2 && c.session!.connected && c.session!.synced), 30000), [A, B, C].map((c) => c.base))
    A.vault.userWrite('Proj/after-move.md', 'moved\n')
    check('syncing continues on the new server', await until(() => B.vault.text('Proj/after-move.md') === 'moved\n'))
    check('old links redirect to the new server', (await fetch(`${BASE}/join/whatever-token-123456`, { redirect: 'manual' })).status === 308)

    console.log('safety')
    await settle(A, B, C)
    const liveBefore = A.session!.liveFiles().length
    B.vault.userDelete('Proj')
    await sleep(1500)
    check('deleting the whole folder pauses instead of deleting', B.rootMissing > 0 && A.session!.liveFiles().length === liveBefore && A.vault.isFile('Proj/notes/a.md'))
    await stop(B)
    await A.api.updateMember(shareId, C.userId, { perms: { read: false, write: false, delete: false } })
    check('turning off read access disconnects', await until(() => C.codes.includes(4403)))
    check('a refused connection is marked as stalled so it can be retried', C.session!.stalled && !A.session!.stalled)
    await stop(C)
    await A.api.deleteShare(shareId)
    check('stopping sharing removes the server data', !fs.existsSync(path.join(liveData, 'shares', shareId)))
    await stop(A)
  } finally {
    server.kill('SIGTERM')
    server2?.kill('SIGTERM')
    fs.rmSync(dataDir, { recursive: true, force: true })
    fs.rmSync(dataDir2, { recursive: true, force: true })
  }
  console.log(`\n${passes} passed, ${failures} failed`)
  process.exit(failures === 0 ? 0 : 1)
}

main().catch((err) => { console.error(err); process.exit(1) })
