# ctf-writeups

CTF 解题记录 + 一组自己写的小型安全工具。

工具用 **Python 3.9+** 编写，每个都是单文件，读起来也方便，既是工具也是学习材料。

- `pwcheck`、`hashid`、`logscan` 只用标准库，拷到任何一台机器（包括比赛里拿到的靶机 shell）都能直接跑；
- `vault` 需要 `cryptography`（`pip install -r requirements.txt`），原因见[第 4 节](#4-vault--本地加密密码保险库)。

```
.
├── tools/
│   ├── pwcheck/pwcheck.py     # 密码强度检测器
│   ├── hashid/hashid.py       # 哈希类型识别 + 小字典验证
│   ├── logscan/
│   │   ├── logscan.py         # 日志敏感信息扫描器
│   │   └── sample.log         # 演示用的假日志（全部为虚构/官方示例数据）
│   └── vault/vault.py         # 本地加密密码保险库
├── tests/                     # 单元测试
├── requirements.txt
└── writeups/                  # 解题记录，见 TEMPLATE.md
```

运行测试：

```bash
python3 -m unittest discover -s tests -v
```

---

## 1. pwcheck — 密码强度检测器

### 设计意图

很多"密码强度条"只看是否包含大小写、数字、符号，于是 `P@ssw0rd` 会被判成"强"。但攻击者跑字典时，这种密码在第一轮就会被命中。

pwcheck 的思路是**从攻击者视角估算强度**：

1. **理论熵**：`长度 × log2(字符集大小)`，代表纯暴力穷举的上限；
2. **模式扣减**：识别人类常见套路，并把对应部分的熵扣掉：
   - 常见弱口令（含 leet 还原，`P@ssw0rd → password`）
   - 字典词（可用 `--wordlist` 加入公司名、项目名、姓名拼音等）
   - 键盘序列 / 字母数字连续（`qwerty`、`1qaz2wsx`、`abcd`、`4321`）
   - 重复片段（`aaa`、`abcabc`）
   - 日期与年份（生日是社工字典的标配）
   - "首字母大写 + 单词 + 数字 + 符号"这种典型套路（`Summer2026!`）
3. **有效熵 → 0~4 分**，并估算在离线快速哈希（约 1e10 次/秒，单张 GPU 跑 MD5 的量级）下的破解时间，同时给出改进建议。

安全方面的取舍：

- 默认用 `getpass` 读取，**不回显、不进 shell 历史**；
- 完全离线，不调用任何在线接口（例如不会把密码发去查泄露库）；
- 批量模式的输出中**不打印明文**，只按序号输出结果。

> 这是启发式估算，不是严格证明。它的价值在于快速发现"看起来复杂、实际很弱"的密码。需要更严格的评估时可以参考 zxcvbn 的思路。

### 使用场景

- 自查个人密码，或者给团队讲"为什么 `P@ssw0rd` 不安全"
- 渗透测试 / 安全审计中，对拿到的明文密码样本做批量强度统计
- 作为注册流程密码策略的原型，或在脚本里用 `--min-score` 做门禁
- CTF 中分析出题人的密码习惯，辅助生成针对性字典

### 用法

```bash
# 交互输入（不回显）
python3 tools/pwcheck/pwcheck.py

# 批量审计：每行一个密码
python3 tools/pwcheck/pwcheck.py --stdin < passwords.txt

# 加入自定义字典词；任一密码低于 3 分时返回码为 1
python3 tools/pwcheck/pwcheck.py --stdin --wordlist company_words.txt --min-score 3 < pw.txt

# JSON 输出，便于统计
echo 'Summer2026!' | python3 tools/pwcheck/pwcheck.py --stdin --json
```

示例输出：

```
强度: █░░░░ 0/4 极弱
长度: 11    字符集: 95
熵: 理论 72.3 bit / 有效 25.2 bit
离线暴破估计(1e10 次/秒): 瞬间
问题:
  - 包含字典词：summer（leet 替换如 @→a、0→o 无法掩盖）
  - 包含年份，常与生日/入学年份相关
  - 符合'首字母大写+单词+数字+符号'的典型套路
```

---

## 2. hashid — 哈希识别工具

### 设计意图

CTF 和渗透中经常会拿到一串哈希：数据库 dump、`/etc/shadow`、secretsdump 输出、配置文件等。下一步通常是爆破，而第一个问题就是**"这是什么算法，hashcat 用哪个 `-m`？"**

hashid 分两层识别：

1. **结构化格式优先**：`$2b$`（bcrypt）、`$6$`（sha512crypt）、`$argon2id$`、`$P$`（WordPress）、`pbkdf2_sha256$`（Django）、`*`+40 hex（MySQL）、`$krb5tgs$`（Kerberoasting）、NetNTLMv2、JWT 等。这类格式有明确前缀，识别结果基本唯一；
2. **纯十六进制按长度推断**：32 位可能是 MD5 / NTLM / MD4 / LM……这时**无法唯一确定**，所以结果按常见程度排序，并把每个候选的 hashcat 模式号和 John 格式名都列出来。

为了在"同长度多种可能"时更进一步，hashid 支持**本地验证**：用 `--try` 给出候选明文，或用 `-w` 跑一个小字典，对每个可验证的候选算法都计算一次，命中即可同时确定算法和明文。CTF 里 `md5("admin")`、NTLM 弱口令这类题经常一步出结果。

其他细节：

- 新版 OpenSSL 默认禁用了 MD4，`hashlib` 可能无法计算 NTLM，所以内置了一个纯 Python 的 MD4 实现（已用 RFC 1320 测试向量验证）；
- 兼容 `user:hash` 形式的行，可以直接喂 shadow 文件或 dump 结果；
- 识别不出时会尝试 Base64 解码，检查是否是"Base64 包装后的原始摘要"。

### 使用场景

- CTF Crypto / Misc / Web 题拿到哈希后，快速确定算法并验证猜测
- 渗透测试中，在把 dump 交给 hashcat 之前先分类整理
- 学习常见口令存储格式（哪些加盐、哪些是慢哈希）

> 大字典请直接用 hashcat / john，本工具的 `-w` 只适合几千行以内的小字典。

### 用法

```bash
python3 tools/hashid/hashid.py 5f4dcc3b5aa765d61d8327deb882cf99

# 同时验证候选明文
python3 tools/hashid/hashid.py 8846f7eaee8fb117ad06bdd830b7586c --try admin --try password

# 批量识别文件（支持 user:hash），并跑小字典
python3 tools/hashid/hashid.py -f hashes.txt -w top1000.txt

# 管道输入 + JSON
cat shadow | python3 tools/hashid/hashid.py --json
```

示例输出：

```
[*] 8846f7eaee8fb117ad06bdd830b7586c
    [最可能] MD5  (hashcat -m 0, john --format=raw-md5)
    [可能  ] NTLM  (hashcat -m 1000, john --format=nt)
             Windows 本地账户；= MD4(UTF-16LE(p))
    ...
    [+] 命中! NTLM: 'password'
```

---

## 3. logscan — 日志敏感信息扫描器

### 设计意图

日志是最常见的"意外泄露"渠道：调试时打印了完整请求头、连接串里带着密码、用户注册信息被原样写进 INFO 日志……这些日志随后会被采集到 ELK、发到工单里，或者被打包发给第三方。

logscan 用来在日志、配置文件、导出数据中找出这类信息，设计上重点解决两个问题：

**1. 降低误报**——纯正则扫描最大的问题是噪音太多，没人愿意看：

- 身份证号要通过 **GB 11643 校验位**，银行卡号要通过 **Luhn 校验**，随便一串 16 位订单号不会被报出来；
- 密码字段会过滤占位值：`password=******`、`${DB_PASSWORD}`、`<redacted>`、`changeme` 都会跳过；
- 同一段文本只报告最严重的那条规则（例如 Bearer 头里的 JWT 只报一次）；
- 支持 `--ignore` 正则白名单和 `--min-severity` 按级别过滤。

**2. 报告本身不能成为新的泄露源**——默认对命中值和整行上下文都**打码**（`AKIA************MPLE`），扫描报告可以放心贴进工单或群聊。只有显式加上 `--show-raw` 才输出原文。

覆盖的规则（`--list-rules` 查看）：

| 级别 | 内容 |
| --- | --- |
| critical | 私钥、AWS AK/SK、阿里云 AccessKey、GitHub/GitLab Token、Stripe Live Key |
| high | Slack Token/Webhook、Google API Key、JWT、Bearer/Basic 认证头、URL 内嵌密码、明文密码字段、身份证号、银行卡号 |
| medium | 通用 api_key / token 字段、手机号 |
| low | 邮箱、内网 IP |

其他特性：目录递归扫描（自动跳过 `.git`、`node_modules` 和二进制文件），直接读取 `.gz` 轮转日志，支持标准输入；**有命中时返回码为 1**，可以直接接入 CI 或 pre-commit。

### 使用场景

- **蓝队 / 运维**：定期扫描应用日志，发现开发误打的敏感字段，推动脱敏
- **合规自查**：在日志、数据导出中查找身份证、手机号、银行卡等个人信息
- **代码提交前**：防止把密钥、测试账号推到公开仓库（包括这个 writeup 仓库本身）
- **CTF / 应急响应**：在题目附件或被入侵主机的大量日志中快速定位凭据和 flag 线索

### 用法

```bash
# 扫描演示日志
python3 tools/logscan/logscan.py tools/logscan/sample.log

# 递归扫描目录，只看 .log 和 .gz，只报 high 及以上
python3 tools/logscan/logscan.py /var/log/myapp --ext .log,.gz --min-severity high

# 管道 + JSON（交给 jq 或其他系统处理）
kubectl logs deploy/api | python3 tools/logscan/logscan.py --json

# 白名单：忽略测试邮箱；关闭内网 IP 规则
python3 tools/logscan/logscan.py app.log --ignore '@example\.com' --exclude-rules internal-ip

# CI 中使用：有命中即失败
python3 tools/logscan/logscan.py src/ config/ --min-severity high || exit 1
```

示例输出：

```
tools/logscan/sample.log:3: [CRITICAL] AWS Secret Access Key (aws-secret-key): wJal****************EKEY
    2026-11-01 10:00:03 DEBUG loaded config aws_secret_access_key=wJal****************EKEY
tools/logscan/sample.log:7: [HIGH] 中国居民身份证号 (cn-id-card): 1101**********002X
    2026-11-01 10:00:06 INFO  register name=张三 idcard=1101**********002X phone=13*******78 ...
```

### 局限

- 基于正则，无法识别"没有固定格式"的密钥（例如随机 32 位字符串且没有 `key=` 之类的上下文）。需要更全面的覆盖时，可以配合熵检测类工具（如 gitleaks、trufflehog）；
- 只处理文本和 gzip，不解析数据库文件、压缩包或二进制格式。

---

## 4. vault — 本地加密密码保险库

### 设计意图

前面三个工具都在回答"密码哪里不安全"，vault 回答的是"那应该怎么管"：给每个网站一个随机生成的长密码，只需要记住一个强主密码。

它的定位是一个**能读懂的密码管理器**：核心逻辑约 300 行，每个安全决策都写在代码注释里，适合用来学习"一个密码保险库最少需要做对哪些事"。

#### 加密方案

```
主密码 ──scrypt(N=2^17, r=8, p=1, 16 字节随机盐)──▶ 256 位密钥
条目库 JSON ──AES-256-GCM(96 位随机 nonce，文件头作为附加认证数据)──▶ 密文
```

| 决策 | 原因 |
| --- | --- |
| **scrypt** 派生密钥 | 内存困难型 KDF，每次尝试需要约 128MB 内存、约 0.3 秒，GPU/ASIC 很难并行暴破。参数参考 OWASP 建议。标准库 `hashlib.scrypt` 即可实现 |
| **AES-256-GCM** | 认证加密：同时保证机密性和完整性。主密码错误、文件被改了一个比特，都会解密失败，而不是解出一堆乱码 |
| **文件头作为 AAD** | 格式版本、KDF 参数、盐虽然是明文，但被绑定进认证标签，无法单独篡改 |
| **拒绝过低的 KDF 参数** | 防止攻击者把文件里的 `N` 改小，诱导你用低成本参数重新保存（降级攻击） |
| **每次保存换 nonce，改主密码时换盐** | GCM 绝对不能重用 (key, nonce)；换盐让旧密钥彻底作废 |
| **整库加密** | 连条目名、用户名、网址都看不到，文件里只能看出"这是个保险库" |
| **依赖 `cryptography`** | 标准库没有 AES。自己实现分组密码是密码学大忌，这是本仓库唯一一个不坚持零依赖的工具 |

#### 工程细节

- **原子写入**：临时文件 → `fsync` → `os.replace`，并保留上一版本 `.bak`，写到一半断电也不会把库写坏；
- **文件权限 0600**，只有当前用户可读；
- **取密码默认走剪贴板**，N 秒后自动清空。清空前会比对剪贴板内容的哈希，不会误删你之后复制的其他东西。传给后台清理进程的是哈希而不是明文，`ps` 也看不到；
- **主密码强度门槛**：复用 `pwcheck`，低于 3/4 分会拒绝（可用 `--allow-weak` 强制）；
- **密码生成**用 `secrets`（操作系统 CSPRNG），保证每类字符至少出现一次，可排除易混淆字符；
- **`audit` 体检**：用 `pwcheck` 找出弱密码、多个条目共用的密码、与历史密码重复、长期未更换的密码；
- 修改条目密码时保留最近 5 个历史密码，改错了还能找回。

### 使用场景

- 个人或 CTF 战队管理比赛平台账号、靶机凭据、VPN 账号
- 学习应用密码学：KDF、AEAD、nonce 管理、降级攻击、原子写入这些概念在这里都有可以直接运行的实现
- 作为渗透测试中"本地凭据存储"的参考：拿到别人的保险库文件后，能做什么、不能做什么

### 用法

```bash
pip install -r requirements.txt
alias vault='python3 tools/vault/vault.py'   # 或用 -f / $VAULT_FILE 指定库文件，默认 ~/.ctfvault.json

vault init                                  # 创建保险库，设置主密码
vault add github -u alice --url https://github.com -g 24   # 自动生成 24 位密码
vault add ctfd -u team -p                   # 手动输入密码（不回显，弱密码会提示）
vault list                                  # 列出全部；vault list git 按名称/用户名/网址搜索
vault get github                            # 复制到剪贴板，20 秒后清空
vault get github --show                     # 直接打印
vault get github --field username
vault info github                           # 查看详情，密码打码
vault edit github -g                        # 换一个新的随机密码（旧密码进历史）
vault audit                                 # 体检；有问题时返回码为 1
vault passwd                                # 修改主密码
vault rm ctfd
vault gen 32 --no-ambiguous                 # 只生成密码，不需要保险库
```

### 威胁模型与局限

**能防住的：**

- 保险库文件被盗（丢笔记本、误传到网盘或 Git）：攻击者只能离线暴破主密码，每次尝试都要付出 scrypt 的成本。主密码足够强时不可行；
- 文件被篡改：GCM 认证会直接报错。

**防不住的：**

- **本机已被入侵**：键盘记录器可以拿到主密码，恶意进程可以读剪贴板或进程内存。任何本地密码管理器都防不住这一点；
- **Python 无法可靠地清零内存**：字符串不可变，主密码和明文条目在进程退出前会留在内存里。这是用 Python 实现的固有限制；
- **弱主密码**：KDF 只能拖慢暴破，不能拯救 `123456`，所以有强度门槛；
- **没有并发锁**：两个终端同时修改，后保存的会覆盖先保存的；
- **主密码无法找回**：没有后门，这是设计目标而不是缺陷。请自行备份库文件。

> 这是学习项目，没有经过独立安全审计。日常的重要账号请使用 Bitwarden、KeePassXC 等成熟的密码管理器。

---

## 使用须知

这些工具用于**学习、CTF 比赛和授权范围内的安全测试**。请勿用于未授权的系统或他人数据。

仓库中的示例数据全部为虚构值或厂商官方文档中的示例值（如 `AKIAIOSFODNN7EXAMPLE`）。测试中需要的平台 Token 在运行时拼接生成，避免触发 GitHub 的密钥扫描。
