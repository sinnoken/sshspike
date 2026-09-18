# ssh spike

最小驗證樣本。只做三件事：

1. **SSH Client 用憑證登入** — 私鑰不進程式，全部走 `ssh-agent`
2. **HTML Server 控制程式** — 內建單頁，無框架、無 npm、無建置步驟
3. **UI 輸入 IP 與指令** — 送出後顯示 stdout / stderr / exit code / 耗時

```
go.mod
main.go                        SSH client + HTTP server
ui.go                          內嵌 HTML（const 字串）
main_test.go                   14 個測試
.github/workflows/ci.yml       測試 + 跨平台編譯 + 煙霧測試
.github/workflows/release.yml  打 tag 時發佈
```

只有一個第三方依賴：`golang.org/x/crypto`。

---

## 本機建置

```bash
go mod tidy          # 產生 go.sum，記得一起 commit
go build -o sshspike .
go test ./...
```

## 執行

```bash
# 1. 啟動 ssh-agent 並載入金鑰（有憑證會一併載入）
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519
ssh-add -l                                   # 確認 agent 看得到

# 2. 記下目標主機的 host key
ssh-keyscan -H 10.0.0.1 >> ~/.ssh/known_hosts

# 3. 啟動
./sshspike
```

開 <http://127.0.0.1:8080>。

還沒收 host key 時可以先用 `./sshspike -insecure-host-key`，啟動會印警告。

### 參數

| 參數 | 預設 | 說明 |
|---|---|---|
| `-listen` | `127.0.0.1:8080` | 控制台位址 |
| `-known-hosts` | `~/.ssh/known_hosts` | Host key 驗證來源 |
| `-insecure-host-key` | `false` | **跳過 host key 驗證**，只給實驗機 |
| `-user` | `$USER` | UI 預設帶入的使用者名稱 |
| `-max-output` | `1048576` | 單一串流最多保留的位元組 |

---

## GitHub Actions

### `ci.yml` — push / PR 觸發

三個 job，`build` 等 `test` 過了才跑：

**test**
- `go mod tidy` 後比對 `go.mod`，沒 tidy 就擋下
- `gofmt -l`、`go vet`
- `go test`
- `go test -race` — 連線池被多個 HTTP handler 共用，這裡的 race 是真 bug
- coverage 摘要，並上傳 `coverage.out`

**vuln**
- `govulncheck ./...`，跟 test 平行跑

**build**
- 矩陣：`linux/amd64`、`linux/arm64`、`darwin/arm64`
- `CGO_ENABLED=0` + `-trimpath`，這是單一可攜執行檔的關鍵
- **煙霧測試**（只在 linux/amd64，因為只有它能在 runner 上跑）：
  - 啟動 server，輪詢等它 ready
  - `/` 回得出 console
  - `/api/conns` 回空連線池
  - `/api/identities` 在沒有 agent 時回 **503**，不是 crash
  - `/api/run` 缺 host 回 **400**
  - `/api/run` 用 GET 回 **405**
- 上傳三個平台的 binary，保留 14 天

### `release.yml` — 打 `v*` tag 觸發

先跑 `go vet` + `go test`，過了才建置 4 個平台（多一個 `darwin/amd64`），產出 `SHA256SUMS`，發 GitHub Release。

```bash
git tag v0.1.0 && git push origin v0.1.0
```

### 注意

- **`go.sum` 要 commit**，否則 `actions/setup-go` 的 cache 會抓不到 key。
- `permissions` 已收斂：ci 只要 `contents: read`，release 才給 `contents: write`。
- 同分支連續 push 會取消前一次還在跑的 run（`concurrency`）。

---

## 要驗證什麼

### 憑證登入

頁面最上方列出 `ssh-agent` 裡的身分。`cert` 標記代表憑證，會顯示 Key ID 與有效期限。過期憑證標紅，而且**不會**被拿去嘗試登入。

這一區空的代表 `ssh-add` 沒做，或 `SSH_AUTH_SOCK` 沒帶進來。

### 持久連線

這是整套系統最關鍵的假設：**連線常駐，所以每個指令只是開一個 channel，不是重新握手。**

按「連續執行 3 次」，看：

- 第 1 次：`new handshake`，dial 通常數十到數百 ms
- 第 2、3 次：`reused`，dial 應該是 **0 ms 或個位數**

下方連線池會顯示這條連線開了多久、用了幾次。如果第 2 次還是 `new handshake`，代表連線沒留住，後面的容量推算全部要重來。

### 指令執行

- Exit code 非 0 照實顯示，不當成錯誤
- stdout / stderr 分開呈現
- 超過 `-max-output` 會截斷並標示，不會吃光記憶體
- Timeout 送 SIGKILL 關掉 session，但**連線保留**給下一個指令

`Ctrl/Cmd + Enter` 可直接送出。

---

## 安全說明

這個樣本**刻意**讓 UI 可以輸入任意指令，因為要驗證的就是這條路徑。這跟正式規格書的裁決是相反的——正式版 UI 只能觸發設定檔裡預先定義的 Job。

所以：

- 預設綁 `127.0.0.1`，**不要改成 `0.0.0.0`**
- 沒有登入、沒有 HTTPS、沒有稽核
- 任何連得到這個 port 的人，都能用你的 SSH 身分在目標機器執行任意指令
- 只在自己機器上、對實驗機使用

---

## 已知限制

1. **未編譯驗證** — 產出環境沒有 Go 工具鏈，外網也連不出去。做了括號平衡、import 使用、方法定義與呼叫點對照、`x/crypto` API 符號比對，但沒實際跑過 `go build`。第一次建置若有小錯請直接修。
2. 連線只在「開 session 失敗」時才重建，沒有背景 keepalive。實驗機閒置太久，連線可能已死但池子還留著——按「關閉此連線」再重試。
3. 沒有併發上限、沒有佇列、沒有排程。
4. 單一 host 只維持一條連線，沒有 session 數量限制。

---

## 下一步

1. Keepalive（確認連線真的活著，而不是等失敗才發現）
2. 節點清單改從 YAML 讀，不是 UI 輸入
3. 指令改成預先定義的 Job，UI 只能選
4. 任務佇列與排程
5. HTTPS + 登入
