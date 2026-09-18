package main

// indexHTML is the entire console: no framework, no npm, no build step.
// {{USER}} is substituted with the default SSH username at request time.
const indexHTML = `<!DOCTYPE html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ssh spike</title>
<style>
:root{--bg:#0f1115;--panel:#171a21;--line:#252a33;--fg:#e6e9ef;--dim:#9aa3b2;
--ok:#3fb950;--err:#f85149;--warn:#d29922;--btn:#21262d}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.55 system-ui,-apple-system,"Noto Sans TC",sans-serif}
header{background:var(--panel);border-bottom:1px solid var(--line);padding:12px 18px}
h1{margin:0;font-size:15px;font-weight:600}
.sub{color:var(--dim);font-size:12px;margin-top:4px}
main{max-width:1020px;margin:0 auto;padding:16px 18px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;
padding:14px;margin-bottom:14px}
h2{font-size:12px;color:var(--dim);font-weight:500;margin:0 0 10px;
text-transform:uppercase;letter-spacing:.5px}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end;margin-bottom:10px}
label{display:block;font-size:11px;color:var(--dim);margin-bottom:3px}
input,textarea{background:#0f1115;color:var(--fg);border:1px solid var(--line);
border-radius:6px;padding:7px 9px;font-size:13px;width:100%}
textarea{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;resize:vertical;min-height:62px}
input:focus,textarea:focus{outline:none;border-color:#3d6fd1}
.f-host{flex:2 1 220px}.f-port{flex:0 0 78px}.f-user{flex:1 1 130px}.f-to{flex:0 0 108px}
button{background:var(--btn);color:var(--fg);border:1px solid var(--line);
border-radius:6px;padding:7px 15px;font-size:13px;cursor:pointer}
button:hover:not(:disabled){border-color:#3d444d}
button:disabled{opacity:.45;cursor:not-allowed}
button.primary{background:#1f6feb;border-color:#1f6feb}
.hint{color:var(--dim);font-size:11px}
pre{background:#0b0d11;border:1px solid var(--line);border-radius:6px;
padding:10px;overflow:auto;max-height:340px;margin:6px 0 0;
font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap;
word-break:break-word}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;color:var(--dim);font-weight:500;padding:5px 6px;
border-bottom:1px solid var(--line)}
td{padding:5px 6px;border-bottom:1px solid var(--line)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.ok{color:var(--ok)}.err{color:var(--err)}.warn{color:var(--warn)}.dim{color:var(--dim)}
.badge{display:inline-block;padding:1px 7px;border-radius:9px;background:var(--btn);
font-size:11px;margin-right:5px}
.empty{color:var(--dim);padding:14px 0;text-align:center;font-size:12px}
.stat{display:flex;gap:14px;flex-wrap:wrap;font-size:12px;color:var(--dim);margin-top:8px}
.stat b{color:var(--fg);font-weight:600}
</style>
</head>
<body>
<header>
  <h1>ssh spike <span class="dim">— 憑證登入 / 持久連線 / 指令派送</span></h1>
  <div class="sub" id="agentline">讀取 ssh-agent…</div>
</header>

<main>
  <div class="card">
    <h2>ssh-agent 身分</h2>
    <div id="ids"><div class="empty">載入中…</div></div>
  </div>

  <div class="card">
    <h2>執行指令</h2>
    <div class="row">
      <div class="f-host"><label>IP / Host</label>
        <input id="host" placeholder="10.0.0.1" autocomplete="off"></div>
      <div class="f-port"><label>Port</label>
        <input id="port" type="number" value="22"></div>
      <div class="f-user"><label>User</label>
        <input id="user" value="{{USER}}" autocomplete="off"></div>
      <div class="f-to"><label>Timeout (ms)</label>
        <input id="timeout" type="number" value="15000"></div>
    </div>
    <div style="margin-bottom:10px">
      <label>指令</label>
      <textarea id="cmd" placeholder="uname -a">uname -a</textarea>
    </div>
    <div class="row" style="margin-bottom:0">
      <button class="primary" id="run">執行</button>
      <button id="run3">連續執行 3 次（測連線重用）</button>
      <button id="closeconn">關閉此連線</button>
      <span class="hint">第一次會握手，之後應重用連線</span>
    </div>
  </div>

  <div class="card">
    <h2>結果</h2>
    <div id="result"><div class="empty">尚未執行</div></div>
  </div>

  <div class="card">
    <h2>連線池 <button id="refresh" style="float:right;padding:3px 9px;font-size:11px">更新</button></h2>
    <div id="conns"><div class="empty">尚無連線</div></div>
  </div>
</main>

<script>
"use strict";
var $ = function(s){ return document.querySelector(s); };

function esc(s){
  return String(s == null ? "" : s).replace(/[&<>"']/g, function(c){
    return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c];
  });
}

function api(path, body){
  var opt = {};
  if (body) {
    opt.method = "POST";
    opt.headers = {"Content-Type":"application/json"};
    opt.body = JSON.stringify(body);
  }
  return fetch(path, opt).then(function(r){
    return r.json().then(function(j){
      if (!r.ok) throw new Error(j.error || r.statusText);
      return j;
    });
  });
}

function target(){
  return {
    host: $("#host").value.trim(),
    port: parseInt($("#port").value, 10) || 22,
    user: $("#user").value.trim(),
    command: $("#cmd").value,
    timeout_ms: parseInt($("#timeout").value, 10) || 15000
  };
}

function loadIdentities(){
  api("/api/identities").then(function(d){
    var ids = d.identities || [];
    var certs = ids.filter(function(i){ return i.is_certificate; }).length;
    $("#agentline").innerHTML = "ssh-agent：<b>" + ids.length +
      "</b> 個身分，其中 <b>" + certs + "</b> 個憑證";
    if (!ids.length) {
      $("#ids").innerHTML = '<div class="empty">agent 沒有任何金鑰，請先 ssh-add</div>';
      return;
    }
    $("#ids").innerHTML = "<table><thead><tr><th>類型</th><th>Fingerprint</th>" +
      "<th>Key ID</th><th>有效期限</th></tr></thead><tbody>" +
      ids.map(function(i){
        var kind = i.is_certificate
          ? '<span class="badge ok">cert</span>'
          : '<span class="badge dim">key</span>';
        var exp = i.valid_before
          ? (i.expired ? '<span class="err">' + esc(i.valid_before) + ' 已過期</span>'
                       : esc(i.valid_before))
          : '<span class="dim">—</span>';
        return "<tr><td>" + kind + '<span class="dim">' + esc(i.type) + "</span></td>" +
          '<td class="mono">' + esc(i.fingerprint) + "</td>" +
          "<td>" + esc(i.key_id || "—") + "</td><td>" + exp + "</td></tr>";
      }).join("") + "</tbody></table>";
  }).catch(function(e){
    $("#agentline").innerHTML = '<span class="err">ssh-agent 無法使用：' + esc(e.message) + "</span>";
    $("#ids").innerHTML = '<div class="empty err">' + esc(e.message) + "</div>";
  });
}

function renderResult(list){
  $("#result").innerHTML = list.map(function(r, n){
    var status = r.error
      ? '<span class="err">ERROR</span>'
      : (r.exit_code === 0 ? '<span class="ok">exit 0</span>'
                           : '<span class="warn">exit ' + r.exit_code + "</span>");
    var reuse = r.reused_connection
      ? '<span class="badge ok">reused</span>'
      : '<span class="badge warn">new handshake</span>';
    var html = '<div style="margin-bottom:' + (n < list.length - 1 ? "14px" : "0") + '">' +
      "<div>" + reuse + status +
      ' <span class="dim">' + esc(r.user) + "@" + esc(r.host) + "</span></div>" +
      '<div class="stat"><span>dial <b>' + r.dial_ms + 'ms</b></span>' +
      "<span>exec <b>" + r.exec_ms + "ms</b></span>" +
      (r.server_version ? "<span>" + esc(r.server_version) + "</span>" : "") +
      (r.truncated ? '<span class="warn">輸出已截斷</span>' : "") + "</div>";
    if (r.error) html += '<pre class="err">' + esc(r.error) + "</pre>";
    if (r.stdout) html += "<pre>" + esc(r.stdout) + "</pre>";
    if (r.stderr) html += '<pre class="warn">' + esc(r.stderr) + "</pre>";
    if (!r.error && !r.stdout && !r.stderr) html += '<pre class="dim">(無輸出)</pre>';
    return html + "</div>";
  }).join("");
}

function run(times){
  var t = target();
  if (!t.host)    { alert("請輸入 IP / Host"); return; }
  if (!t.command) { alert("請輸入指令"); return; }

  var btns = document.querySelectorAll("button");
  btns.forEach(function(b){ b.disabled = true; });
  $("#result").innerHTML = '<div class="empty">執行中…</div>';

  var results = [];
  var chain = Promise.resolve();
  for (var i = 0; i < times; i++) {
    chain = chain.then(function(){
      return api("/api/run", t).then(function(r){
        results.push(r);
        renderResult(results);
      });
    });
  }
  chain.catch(function(e){
    $("#result").innerHTML = '<pre class="err">' + esc(e.message) + "</pre>";
  }).then(function(){
    btns.forEach(function(b){ b.disabled = false; });
    loadConns();
  });
}

function loadConns(){
  api("/api/conns").then(function(d){
    var c = d.connections || [];
    if (!c.length) { $("#conns").innerHTML = '<div class="empty">尚無連線</div>'; return; }
    $("#conns").innerHTML = "<table><thead><tr><th>連線</th><th>Server</th>" +
      "<th>建立於</th><th>最後使用</th><th>執行次數</th></tr></thead><tbody>" +
      c.map(function(x){
        return '<tr><td class="mono">' + esc(x.key) + "</td>" +
          '<td class="dim">' + esc(x.server) + "</td>" +
          "<td>" + esc(x.opened_ago) + " 前</td>" +
          "<td>" + esc(x.last_used_ago) + " 前</td>" +
          "<td><b>" + x.runs + "</b></td></tr>";
      }).join("") + "</tbody></table>";
  }).catch(function(){});
}

$("#run").addEventListener("click", function(){ run(1); });
$("#run3").addEventListener("click", function(){ run(3); });
$("#refresh").addEventListener("click", loadConns);
$("#closeconn").addEventListener("click", function(){
  api("/api/close", target()).then(function(){ loadConns(); });
});
$("#cmd").addEventListener("keydown", function(e){
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") run(1);
});

loadIdentities();
loadConns();
setInterval(function(){ if (!document.hidden) loadConns(); }, 5000);
</script>
</body>
</html>`
