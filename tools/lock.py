#!/usr/bin/env python3
"""Password-protect the site.

The readable page lives in src.html, which is never committed (see .gitignore).
index.html is the published page: a password screen that holds src.html
encrypted (PBKDF2-SHA256 + AES-256-GCM) and decrypts it in the browser.

  python3 tools/lock.py unlock   # index.html -> src.html, to edit the page
  python3 tools/lock.py lock     # src.html   -> index.html, before committing

The password is read from the SITE_PASSWORD environment variable, or asked for.
It is never written to disk.
"""
import base64, getpass, json, os, re, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, 'src.html')
OUT = os.path.join(ROOT, 'index.html')
ITER = 600_000


def key(pw, salt, it=ITER):
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=it).derive(pw.encode())


def password():
    pw = os.environ.get('SITE_PASSWORD') or getpass.getpass('Site password: ')
    if not pw:
        sys.exit('No password given.')
    return pw


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
  function b64(s){var b=atob(s),a=new Uint8Array(b.length);for(var i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a}
  function open(pw){
    var c=crypto.subtle;
    return c.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveKey'])
      .then(function(k){return c.deriveKey({name:'PBKDF2',salt:b64(P.s),iterations:P.i,hash:'SHA-256'},k,{name:'AES-GCM',length:256},false,['decrypt'])})
      .then(function(k){return c.decrypt({name:'AES-GCM',iv:b64(P.n)},k,b64(P.c))})
      .then(function(buf){return new TextDecoder().decode(buf)});
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


def lock():
    if not os.path.exists(SRC):
        sys.exit('src.html not found. Run "unlock" first.')
    pw = password()
    salt, nonce = os.urandom(16), os.urandom(12)
    ct = AESGCM(key(pw, salt)).encrypt(nonce, open(SRC, 'rb').read(), None)
    b = lambda x: base64.b64encode(x).decode()
    payload = json.dumps({'s': b(salt), 'n': b(nonce), 'i': ITER, 'c': b(ct)}, separators=(',', ':'))
    open(OUT, 'w').write(TEMPLATE.replace('__PAYLOAD__', payload))
    print('Locked src.html -> index.html (%d KB)' % (os.path.getsize(OUT) // 1024))


def unlock():
    m = re.search(r'var P=(\{.*?\}),K=', open(OUT).read())
    if not m:
        sys.exit('index.html is not a locked page.')
    p = json.loads(m.group(1))
    d = lambda x: base64.b64decode(x)
    try:
        out = AESGCM(key(password(), d(p['s']), p['i'])).decrypt(d(p['n']), d(p['c']), None)
    except Exception:
        sys.exit('Wrong password.')
    open(SRC, 'wb').write(out)
    print('Unlocked index.html -> src.html')


if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else ''
    {'lock': lock, 'unlock': unlock}.get(cmd, lambda: sys.exit(__doc__))()
