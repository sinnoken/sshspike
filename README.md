# ssh spike

最小驗證樣本。只做三件事：

1. **SSH Client 用憑證登入** — 私鑰不進程式，全部走 `ssh-agent`
2. **HTML Server 控制程式** — 內建單頁，無框架、無 npm、無建置步驟
3. **UI 輸入 IP 與指令** — 送出後顯示 stdout / stderr / exit code / 耗時

檔案只有 4 個：

```
go.mod
main.go        SSH client + HTTP server
ui.go          內嵌 HTML（const 字串）
main_test.go   兩個小測試
```

---

## 建置

```bash
cd sshspike
go mod tidy          # 抓 golang.org/x/crypto
go build -o sshspike .
```

只有一個第三方依賴：`golang.org/x/crypto`。

## 執行

```bash
# 1. 啟動 ssh-agent 並載入金鑰（有憑證會一併載入）
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519

# 2. 確認 agent 看得到憑證
ssh-add -l

# 3. 先把目標主機的 host key 記下來
ssh-keyscan -H 10.0.0.1 >> ~/.ssh/known_hosts

# 4. 啟動
./sshspike
```

開 <http://127.0.0.1:8080>。

### 參數

| 參數 | 預設 | 說明 |
|---|---|---|
| `-listen` | `127.0.0.1:8080` | 控制台位址 |
| `-known-hosts` | `~/.ssh/known_hosts` | Host key 驗證來源 |
| `-insecure-host-key` | `false` | **跳過 host key 驗證**，只給實驗機 |
| `-user` | `$USER` | UI 預設帶入的使用者名稱 |
| `-max-output` | `1048576` | 單一串流最多保留的位元組 |

還沒把 host key 加進 `known_hosts` 時，可以先用：

```bash
./sshspike -insecure-host-key
```

啟動時會印出警告。這個旗標只適合丟棄式的實驗機。

---

## 要驗證什麼

### 憑證登入

頁面最上方會列出 `ssh-agent` 裡的身分，`cert` 標記代表那是憑證，並顯示 Key ID 與有效期限。過期的憑證會標紅，而且不會被拿去嘗試登入。

如果這一區是空的，代表 `ssh-add` 沒做或 `SSH_AUTH_SOCK` 沒帶進來。

### 持久連線

這是整個系統最關鍵的假設：**連線常駐，所以每個指令只是開一個 channel，不是重新握手。**

按「連續執行 3 次」，觀察：

- 第 1 次：`new handshake`，`dial` 通常數十到數百 ms
- 第 2、3 次：`reused`，`dial` 應該是 **0 ms 或個位數**

下方「連線池」會顯示這條連線開了多久、用了幾次。如果第 2 次還是 `new handshake`，代表連線沒被留住，後面的容量推算都要重來。

### 指令執行

- Exit code 非 0 會照實顯示，不當成錯誤
- stdout / stderr 分開呈現
- 超過 `-max-output` 會截斷並標示，不會把記憶體吃光
- Timeout 會送 SIGKILL 關掉 session，但**連線保留**給下一個指令

`Ctrl/Cmd + Enter` 可以直接在指令框送出。

---

## 測試

```bash
go test ./...
```

只測了兩件事：輸出截斷的邊界、連線池 key 有沒有把 user 和 port 算進去（算錯會拿到別人身分的連線）。

---

## 安全說明

這個樣本**刻意**讓 UI 可以輸入任意指令，因為要驗證的就是這條路徑。這跟正式規格書的裁決是相反的——正式版本 UI 只能觸發設定檔裡預先定義的 Job。

所以：

- 預設綁 `127.0.0.1`，**不要改成 `0.0.0.0`**
- 沒有登入驗證，沒有 HTTPS，沒有稽核
- 任何能連到這個 port 的人，都能以你的 SSH 身分在目標機器上執行任意指令
- 只在自己機器上、對實驗機使用

正式版要補的東西：HTTPS、登入、Job 白名單、稽核紀錄。

---

## 已知限制

1. **未編譯驗證** — 產出環境沒有 Go 工具鏈，外網也連不出去。我做了括號平衡、import 使用、方法定義與呼叫點的靜態檢查，但沒實際跑過 `go build`。第一次建置若有小錯請直接修。
2. 連線只在「開 session 失敗」時才會重建，沒有背景 keepalive。實驗機閒置太久連線可能已經死掉但池子還留著——按「關閉此連線」再重試即可。
3. 沒有併發上限，沒有佇列，沒有排程。這些是下一步。
4. 單一 host 只維持一條連線，沒有 session 數量限制。

---

## 下一步

驗證通過後，依序加：

1. Keepalive（確認連線真的活著，而不是等失敗才發現）
2. 節點清單改從 YAML 讀，不是 UI 輸入
3. 指令改成預先定義的 Job，UI 只能選
4. 任務佇列與排程
5. HTTPS + 登入
