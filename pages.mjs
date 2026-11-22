const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))
const jsonData = (value) => JSON.stringify(value).replace(/</g, '\\u003c')

function layout (title, body, script = '') {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><title>${esc(title)}</title><style>
:root{--bg:#fafafa;--fg:#1d1d1f;--muted:#6e6e73;--card:#fff;--line:#e3e3e8;--accent:#7c3aed}
@media (prefers-color-scheme:dark){:root{--bg:#161618;--fg:#f2f2f4;--muted:#a1a1a6;--card:#1f1f22;--line:#333338;--accent:#a78bfa}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:560px;margin:48px auto;padding:0 16px}.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:24px}
h1{font-size:22px;margin:0 0 12px}li{margin:14px 0}a{color:var(--accent)}.muted{color:var(--muted);font-size:14px}
.btn{display:inline-block;padding:6px 12px;border-radius:8px;border:1px solid var(--line);color:var(--fg);text-decoration:none}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}code{font-size:14px}</style></head>
<body><main><div class="card">${body}</div></main>${script}</body></html>`
}

export function messagePage (title, text) {
  return layout(title, `<h1>${esc(title)}</h1><p>${esc(text)}</p>`)
}

function pluginSteps (repo) {
  const brat = `obsidian://brat?plugin=${encodeURIComponent(repo)}`
  return `<li><a class="btn" href="obsidian://show-plugin?id=collaboration">Install Collaboration</a> from the community plugins and enable it. <span class="muted">Skip if you already have it.</span><br>
<span class="muted">Not listed yet? Install <a href="obsidian://show-plugin?id=obsidian42-brat">BRAT</a>, then <a href="${esc(brat)}">add Collaboration with BRAT</a>.</span></li>`
}

export function joinPage (data) {
  const body = `<h1 id="title">Join a shared folder</h1>
<p id="who">You were invited to an end-to-end encrypted shared folder.</p>
<ol>${pluginSteps(data.repo)}<li><a class="btn primary" id="open" href="#">Open in Obsidian</a></li></ol>
<p class="muted" id="hint">If the button does nothing, run <i>Collaboration: Join shared folder</i> in Obsidian and paste this page’s full address.</p>
<script type="application/json" id="data">${jsonData(data)}</script>`
  const script = `<script>
(async () => {
  const data = JSON.parse(document.getElementById('data').textContent)
  const secret = location.hash.slice(1)
  if (!/^[A-Za-z0-9_-]{20,}$/.test(secret)) {
    document.getElementById('who').textContent = 'This link is incomplete. Ask for the full link, including the part after “#”.'
    return
  }
  document.getElementById('open').href = 'obsidian://collaboration?server=' + encodeURIComponent(data.server) + '&invite=' + data.token + '&key=' + secret
  try {
    const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0))
    const b64u = (s) => b64(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - s.length % 4) % 4))
    const te = new TextEncoder()
    const td = new TextDecoder()
    const base = await crypto.subtle.importKey('raw', b64u(secret), 'HKDF', false, ['deriveKey'])
    const inviteKey = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: te.encode('collaboration-invite-v1') }, base, { name: 'AES-GCM', length: 256 }, false, ['decrypt'])
    const sealed = b64(data.keyring)
    const ring = JSON.parse(td.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: sealed.slice(0, 12) }, inviteKey, sealed.slice(12))))
    const open = async (payload, aad) => {
      const p = b64(payload)
      const epoch = new DataView(p.buffer).getUint32(1)
      const entry = ring.find((e) => e.epoch === epoch)
      const key = await crypto.subtle.importKey('raw', b64(entry.key), 'AES-GCM', false, ['decrypt'])
      return td.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: p.slice(5, 17), additionalData: te.encode(aad) }, key, p.slice(17)))
    }
    const folder = await open(data.shareNameEnc, data.shareId + ':share-name')
    const owner = await open(data.ownerNameEnc, data.shareId + ':member-name:' + data.ownerId)
    document.title = 'Join “' + folder + '”'
    document.getElementById('title').textContent = 'Join “' + folder + '”'
    document.getElementById('who').textContent = owner + ' invited you to the shared folder “' + folder + '”. Its contents are end-to-end encrypted.'
  } catch (err) {}
})()
</script>`
  return layout('Join a shared folder', body, script)
}

export function setupPage (data) {
  const open = `obsidian://collaboration?server=${encodeURIComponent(data.server)}&owner=${encodeURIComponent(data.token)}`
  return layout('Set up Collaboration', `<h1>Set up Collaboration</h1>
<p>Connect your vault to <b>${esc(data.server)}</b> as an owner, so you can share folders from it.</p>
<ol>${pluginSteps(data.repo)}<li><a class="btn primary" href="${esc(open)}">Connect this vault</a></li></ol>
<p class="muted">This link works once. Run <code>owner-link.sh</code> on the server for a new one.</p>`)
}
