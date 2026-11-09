#!/usr/bin/env python3
"""Password-protect the site, page and photos.

Readable files, never committed (see .gitignore):
  src.html  the page
  img/      the photos

Committed:
  index.html  a password screen holding src.html encrypted
  p/*.bin     each photo, encrypted, under a meaningless name

Everything uses one key derived from the password (PBKDF2-SHA256, AES-256-GCM).
The browser derives the same key from the password the guest types, decrypts
the page, then decrypts photos as their section comes near the screen.

  python3 tools/lock.py unlock   # index.html + p/ -> src.html + img/, to edit
  python3 tools/lock.py lock     # src.html + img/ -> index.html + p/, to publish

The password is read from SITE_PASSWORD or asked for. It is never written to disk.
"""
import base64, getpass, hashlib, hmac, json, os, re, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, 'src.html')
OUT = os.path.join(ROOT, 'index.html')
ENC = 'p'
ITER = 600_000
BLANK = 'data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw=='
LOADER_ID = 'enc-img-loader'


def derive(pw, salt, it=ITER):
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=it).derive(pw.encode())


def password():
    pw = os.environ.get('SITE_PASSWORD') or getpass.getpass('Site password: ')
    if not pw:
        sys.exit('No password given.')
    return pw


b64 = lambda x: base64.b64encode(x).decode()
unb64 = base64.b64decode


def read_payload():
    if not os.path.exists(OUT):
        return None
    m = re.search(r'var P=(\{.*?\}),K=', open(OUT).read())
    return json.loads(m.group(1)) if m else None


def open_page(p, key):
    return AESGCM(key).decrypt(unb64(p['n']), unb64(p['c']), None).decode()


def enc_name(key, path):
    return '%s/%s.bin' % (ENC, hmac.new(key, path.encode(), hashlib.sha256).hexdigest()[:20])


# Runs inside the decrypted page: decrypt photos near the screen.
LOADER = '''<script id="%s">
(function(){
  var K=window.__K;if(!K||!window.crypto||!crypto.subtle)return;
  function u8(s){var b=atob(s),a=new Uint8Array(b.length);for(var i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a}
  var key=crypto.subtle.importKey('raw',u8(K),'AES-GCM',false,['decrypt']);
  function load(img){
    var u=img.getAttribute('data-enc');if(!u)return;img.removeAttribute('data-enc');
    fetch(u).then(function(r){if(!r.ok)throw r.status;return r.arrayBuffer()})
      .then(function(buf){return key.then(function(k){return crypto.subtle.decrypt({name:'AES-GCM',iv:new Uint8Array(buf,0,12)},k,new Uint8Array(buf,12))})})
      .then(function(d){img.src=URL.createObjectURL(new Blob([d],{type:'image/jpeg'}))})
      .catch(function(){});
  }
  function group(el){return el.closest('section,header,details')||document.body}
  var groups=[];[].forEach.call(document.querySelectorAll('img[data-enc]'),function(img){var g=group(img);if(groups.indexOf(g)<0)groups.push(g)});
  function loadGroup(g){[].forEach.call(g.querySelectorAll('img[data-enc]'),load)}
  [].forEach.call(document.querySelectorAll('header img[data-enc]'),load);
  if(!('IntersectionObserver' in window)){groups.forEach(loadGroup);return}
  var io=new IntersectionObserver(function(es){es.forEach(function(e){if(e.isIntersecting){io.unobserve(e.target);loadGroup(e.target)}})},{rootMargin:'100%% 0px'});
  groups.forEach(function(g){io.observe(g)});
  document.addEventListener('toggle',function(e){if(e.target.tagName==='DETAILS'&&e.target.open)loadGroup(e.target)},true);
})();
</script>''' % LOADER_ID


TEMPLATE = r'''<!doctype html>
<html lang="en-GB">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow">
<title>Tao's 30th</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wdth,wght@62..125,300..900&display=swap">
<style>
:root{--bg:#e4eefa;--ink:#13203a;--grey:#5d6b82;--rule:#c8d9ed;--orange:#ee8a3c;--f:"Archivo","Helvetica Neue",Arial,sans-serif;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--bg:#0e1626;--ink:#e9eff7;--grey:#9aa8bd;--rule:#2b3c5c;color-scheme:dark}}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;background:var(--bg);color:var(--ink);font:400 17px/1.5 var(--f);-webkit-font-smoothing:antialiased;display:grid;place-items:center;padding:24px}
form{width:100%;max-width:420px}
h1{margin:0 0 28px;font-stretch:62%;font-weight:800;text-transform:uppercase;line-height:.9;font-size:clamp(3rem,13vw,4.6rem)}
label{display:block;font-size:.95rem;color:var(--grey);margin-bottom:8px}
.row{display:flex;border-bottom:2px solid var(--ink)}
input{flex:1;min-width:0;font:inherit;font-size:1.25rem;color:inherit;background:none;border:0;padding:10px 0;outline:none}
button{font:inherit;font-weight:600;color:inherit;background:none;border:0;padding:10px 0 10px 16px;cursor:pointer}
button:hover,button:focus-visible{color:var(--orange)}
.row:focus-within{border-color:var(--orange)}
.msg{min-height:1.5em;margin:12px 0 0;font-size:.95rem;color:var(--grey)}
.msg.bad{color:#c2410c}
.keep{display:flex;gap:8px;align-items:center;margin-top:18px;font-size:.95rem;color:var(--grey);cursor:pointer}
.keep input{flex:none;width:16px;height:16px;accent-color:var(--orange)}
noscript p{margin-top:16px;color:var(--grey)}
</style>
</head>
<body>
<form id="f" autocomplete="off">
  <h1>Tao's 30th</h1>
  <label for="pw">Password</label>
  <div class="row"><input id="pw" type="password" autocomplete="current-password" autofocus required><button type="submit">Come in</button></div>
  <p class="msg" id="msg" role="status" aria-live="polite"></p>
  <label class="keep"><input type="checkbox" id="keep" checked>Remember me on this device</label>
  <noscript><p>This page needs JavaScript turned on.</p></noscript>
</form>
<script>
(function(){
  var P=__PAYLOAD__,K='tao30-pw';
  function u8(s){var b=atob(s),a=new Uint8Array(b.length);for(var i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a}
  function b64(a){var s='';for(var i=0;i<a.length;i++)s+=String.fromCharCode(a[i]);return btoa(s)}
  function open(pw){
    var c=crypto.subtle,raw;
    return c.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveBits'])
      .then(function(k){return c.deriveBits({name:'PBKDF2',salt:u8(P.s),iterations:P.i,hash:'SHA-256'},k,256)})
      .then(function(bits){raw=new Uint8Array(bits);return c.importKey('raw',raw,'AES-GCM',false,['decrypt'])})
      .then(function(k){return c.decrypt({name:'AES-GCM',iv:u8(P.n)},k,u8(P.c))})
      .then(function(buf){return new TextDecoder().decode(buf).replace('<head>','<head><script>window.__K="'+b64(raw)+'"<\/script>')});
  }
  function show(h){document.open();document.write(h);document.close()}
  var f=document.getElementById('f'),pw=document.getElementById('pw'),msg=document.getElementById('msg'),keep=document.getElementById('keep');
  if(!window.crypto||!crypto.subtle){msg.textContent='This browser can\'t open the page. Please try a recent version of Chrome, Safari or Firefox.';msg.className='msg bad';return}
  var saved=null;try{saved=localStorage.getItem(K)}catch(e){}
  if(saved){msg.textContent='Opening…';open(saved).then(show,function(){try{localStorage.removeItem(K)}catch(e){}msg.textContent=''})}
  f.addEventListener('submit',function(e){
    e.preventDefault();var v=pw.value.trim();if(!v)return;
    msg.className='msg';msg.textContent='Checking…';
    open(v).then(function(h){try{if(keep.checked)localStorage.setItem(K,v);else localStorage.removeItem(K)}catch(e){}show(h)},
      function(){msg.className='msg bad';msg.textContent='That\'s not it. Check the group chat for the password.';pw.select()});
  });
})();
</script>
</body>
</html>
'''

IMG_SRC = re.compile(r'(<img\b[^>]*?)\bsrc="(img/[^"]+)"')
IMG_ENC = re.compile(r'\bsrc="' + re.escape(BLANK) + r'" data-enc="[^"]+" data-orig="([^"]+)"')


def lock():
    if not os.path.exists(SRC):
        sys.exit('src.html not found. Run "unlock" first.')
    pw = password()
    old = read_payload()
    salt = None
    if old:  # keep the same key when the password is unchanged, so unchanged photos keep the same files
        try:
            k = derive(pw, unb64(old['s']), old['i'])
            open_page(old, k)
            salt = unb64(old['s'])
        except Exception:
            pass
    salt = salt or os.urandom(16)
    key = derive(pw, salt)
    aes = AESGCM(key)
    page = open(SRC).read()

    os.makedirs(os.path.join(ROOT, ENC), exist_ok=True)
    used, wrote = set(), 0

    def swap(m):
        nonlocal wrote
        path = m.group(2)
        plain = open(os.path.join(ROOT, path), 'rb').read()
        name = enc_name(key, path)
        used.add(name)
        dest = os.path.join(ROOT, name)
        same = False
        if os.path.exists(dest):
            blob = open(dest, 'rb').read()
            try:
                same = aes.decrypt(blob[:12], blob[12:], None) == plain
            except Exception:
                pass
        if not same:
            n = os.urandom(12)
            open(dest, 'wb').write(n + aes.encrypt(n, plain, None))
            wrote += 1
        return '%ssrc="%s" data-enc="%s" data-orig="%s"' % (m.group(1), BLANK, name, path)

    page = IMG_SRC.sub(swap, page)
    page = page.replace('</body>', LOADER + '\n</body>', 1)
    removed = 0
    for f in os.listdir(os.path.join(ROOT, ENC)):
        if '%s/%s' % (ENC, f) not in used:
            os.remove(os.path.join(ROOT, ENC, f))
            removed += 1

    nonce = os.urandom(12)
    payload = json.dumps({'s': b64(salt), 'n': b64(nonce), 'i': ITER, 'c': b64(aes.encrypt(nonce, page.encode(), None))}, separators=(',', ':'))
    open(OUT, 'w').write(TEMPLATE.replace('__PAYLOAD__', payload))
    print('Locked page and %d photos (%d re-encrypted, %d removed) -> index.html + %s/' % (len(used), wrote, removed, ENC))


def unlock():
    p = read_payload()
    if not p:
        sys.exit('index.html is not a locked page.')
    key = derive(password(), unb64(p['s']), p['i'])
    try:
        page = open_page(p, key)
    except Exception:
        sys.exit('Wrong password.')
    aes = AESGCM(key)
    count = 0
    for m in re.finditer(r'data-enc="([^"]+)" data-orig="([^"]+)"', page):
        blob = open(os.path.join(ROOT, m.group(1)), 'rb').read()
        dest = os.path.join(ROOT, m.group(2))
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        open(dest, 'wb').write(aes.decrypt(blob[:12], blob[12:], None))
        count += 1
    page = IMG_ENC.sub(lambda m: 'src="%s"' % m.group(1), page)
    page = page.replace('\n' + LOADER, '', 1)
    open(SRC, 'w').write(page)
    print('Unlocked index.html + %d photos -> src.html + img/' % count)


if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else ''
    {'lock': lock, 'unlock': unlock}.get(cmd, lambda: sys.exit(__doc__))()
