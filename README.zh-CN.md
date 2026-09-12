# cpa-key-policy（中文说明）

面向 [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) 的**下游 API Key 策略插件**。

用人话说：你可以给客户发自己的 `cpa_…` 钥匙。每把钥匙只能用你允许的模型，还能限速、限额，并转到 CPA 真实上游（Codex、Claude、openai-compatibility 通道等）。CPA 自带的 `api-keys` 仍可留给管理员；**不要把插件下发的 key 再写进 `api-keys`**，否则会绕过本插件策略。

| | |
|---|---|
| **仓库** | [origin652/cpa-plugin-key-policy](https://github.com/origin652/cpa-plugin-key-policy) |
| **协议** | MIT |
| **安装** | [CLIProxyAPI 插件商店](https://github.com/router-for-me/CLIProxyAPI-Plugins-Store) 或自行编译 |
| **English** | [README.md](./README.md) |

---

## 它能干什么

1. **发钥匙** — 批量创建下游 key，每把绑定可用模型 / 别名。  
2. **做映射** — 客户端写 `model: fast`，插件转到例如 `codex` + `gpt-5.4-mini`。  
3. **做限制** — 单 key 的 RPM、最大在途请求并发、可选每日/每周美元额度，并可限制某个 auth 文件的全局受控并发。
4. **凭证分档 / 归类** — 请求可以钉死在 Codex free/team 等内置档，或你自定义的归类组，**不会串到别的凭证文件**。  
5. **多目标别名** — 一个别名挂多个后端（优先 或 轮询）。  
6. **会话亲和** — 同一会话优先复用同一 auth；满载时只在允许账号池内切换。
7. **网页管理与自助查询** — 管理员配置策略，key 持有人只读查看自己的用量。

---

## 核心概念

### 下游 Key

插件自己发的密钥（`cpa_…`），只由本插件鉴权。上面可以配置：

- 允许的 **模型** 和/或 **别名**
- RPM
- 最大并发中的模型请求数（单进程）
- 可选的 session affinity
- 每日 / 每周美元上限（可选）
- 是否允许主端口访问 `/v1/models`（见下文）

### 别名（全局映射表）

可复用的名字，例如 `fast`，展开成一条或多条 **目标**：

| 字段 | 含义 |
|------|------|
| `provider` | CPA 提供商标识（`codex`、`claude`，或 openai-compatibility 的 **name**，如 `cerebras`） |
| `target_model` | 上游真实模型 id |
| `group` | 可选，限制用哪一类凭证（见下节） |
| `dispatch` | `priority`（始终尝试第一个）或 `round-robin`（轮询） |
| 计费 | `tokens`（百万 token 单价）或 `per_call`（每次固定金额） |

Key 可以**引用**别名，不必重复填目标。多目标别名会展开成多条同名规则；**同一次请求**里鉴权与路由共用同一次选择，保证 `group` 与真实目标一致。

### 凭证组：内置档位 + 自定义归类

| 类型 | 选择器里长什么样 | 写进映射的 group |
|------|------------------|------------------|
| **内置档**（Codex `plan_type`、Antigravity `tier`） | 如「免费档 / Team」 | 裸名：`free`、`team`、`supported` |
| **自定义归类** | 如 **「自定义 · vip」** | 带前缀：`classify:vip` |

**运行时规则：** 映射里写了 group，调度就**只**在该组凭证里选文件。没有可用文件 → 直接失败（`auth_not_found`），**绝不**偷偷落到其他档。

**调度：** 插件先应用全部账号约束，再保留交集中 `Priority` 最高的一层并执行池内策略：

- 权重来自 CPA 凭证配置，插件兼容候选的 `Weight`、`Attributes.weight` 和 `Metadata.weight`。
- 未配置或无法解析时按 `1` 处理；非正数表示暂停接收新请求；最大按 `1000000` 处理。
- 调度状态按下游 key + provider + model + group + Priority 隔离；绑定不同账号池的 key 不共用游标。
- 低 `Priority` 凭证仅在更高优先级凭证全部不可用或权重非正时参与。
- CPA 没有转发前端鉴权 metadata 时，插件会用 Header key、`requested_model` 和最终 provider/model 恢复唯一 group。信息缺失或目标歧义时直接失败，不会退回全池。
- `global_weighted_round_robin: true` 只保留未绑定插件 key 的旧有“忽略 group”行为；显式 `account_binding` 及其目标 group 永远优先。

### 失败关闭的账号绑定

每个 key 可配置 `account_binding.allow`，使用 Go `path.Match` 对 CPA 凭证候选 ID 做大小写敏感的 glob 匹配。字段存在但 allow 为空表示“不允许任何账号”，不等于未配置绑定。

```yaml
account_binding:
  allow: ["codex-team-*.json", "openai-compatibility:corp:*"]
  strategy: weighted-round-robin # weighted-round-robin | round-robin | fill-first | quota-fill-first
```

调度器依次取账号绑定、唯一目标 group、provider、状态、正权重与最高 Priority 的交集。交集为空返回 `auth_not_bound`，不会 `Handled:false`，也不会委托 CPA 全局池。受绑定请求必须把配置的 key 放在 Header；仅 query 传 key 或 Header 凭证冲突会在访问上游前终止。

CPA 原生 key 默认完全不受影响；只有显式以 `native: true` 导入后才接管其账号绑定。导入只保存普通 key hash 与 CPA 的不可逆 `caller_scope`，不会保存或回显第二份明文。原生 key 仍由宿主鉴权和模型路由，但绑定由本插件强制执行。只有未被绑定接管的原生 key 才继续使用宿主 session affinity；插件自己返回 AuthID 的 RR/WRR 不会自动继承亲和性。

### 并发限制与会话亲和

- `max_concurrent_requests` 限制某个受控 key 同时在途的模型执行；`0` 表示不限。
- `auth_concurrency_limits` 用**精确 auth ID**配置某个凭证的最大受控并发，跨插件 key、跨模型汇总；未配置表示不限。
- 普通 HTTP 与 SSE 都从请求准入占位到完成、失败、拒绝或取消时释放。满载立即返回 `429`，不排队。
- session affinity 缺省关闭。启用后使用宿主提供的 canonical/derived session id，在内存中优先复用上次成功准入的 auth。
- 若亲和 auth 已满、冷却、不可用或已不在绑定内，会按原 WRR/RR/fill-first 策略改选**同一允许池**里的账号；池内全部满载才返回 429，绝不跨池。
- 并发名额与亲和缓存都是单进程内存状态，不在多 CPA 实例之间共享。热更新降低上限不会驱逐已有请求，只会阻止新请求。
- image/video 的 `per_call` 补偿计费改为并发准入成功后扣除一次；后续上游失败仍无法退款。

### Codex 额度感知 Fill First 与周期维护

- 选择 `quota-fill-first` 后，插件仍先应用账号绑定、group、provider、状态、Priority、正权重和 auth 并发；只在最终合法池内读取内存额度缓存。
- 已知可用账号按**周/月长窗口最早重置**优先；5 小时窗口只判断是否可用，不参与排序。Ready 亲和账号不会仅因另一个账号更早重置而迁移。
- 无有效额度缓存时，在合法池内按原 Fill First 稳定降级；明确耗尽的账号不会因 TTL 或 reset 到点自动恢复，必须看到更新的正面证据。
- `quota_check_interval` 与 `quota_cache_ttl` 独立，默认均为 `30m`。正常业务响应的额度信号优先，后台只补查缺失、过期、跨 reset 或待验证状态。
- 自动激活默认关闭。开启后可选 `managed-pools` 或 `all-codex`；后者也覆盖只被 CPA 原生 key 使用和暂未使用的有效 Codex OAuth auth，但**绝不扩大任何 key 的业务允许池**。
- 激活使用严格的懒窗口基线、很小的 `gpt-5.4-mini` compact 请求和后验 GET 验证；与受控业务共享 auth 并发上限，但不消耗用户 key 的 RPM/账本。未接管的原生请求仍不计入插件并发，因此该上限不是全宿主物理并发硬限制。
- 额度与激活运行状态保存在 `<state_file>.quota-runtime.json`；Docker 应挂载 `state_file` 所在整个目录。

**运行边界：** 这是纯插件控制。账号绑定流量必须保持插件启用且健康，也不能使用 CPA Home 模式，因为 Home 会在普通插件 scheduler 之前完成选择。若插件被卸载或熔断，仍留在 CPA `api-keys` 中的原生 key 会重新只受宿主全局账号池控制。若要求插件被移除时也尽量失败关闭，请使用插件签发的 key，并且绝不要把它重复放进 CPA `api-keys`。

**自定义归类**（网页 → 映射 → 凭证归类）：

- 用正则匹配凭证字段（`filename`、`provider`、`plan_type`、`tier` 等）。
- 规则上保存你起的**组名**（裸名）。
- 目录与映射使用 `classify:组名`，避免和内置的 `free`/`team` 撞名。
- 一个文件可命中**多个**自定义组（选择器里每组都会出现）。
- 没命中自定义规则 → Codex/Antigravity 走内置档；其它 auth-file 渠道默认扁平（无组）。
- openai-compat / API Key 类通道保持**扁平**，不拆组。

一般在网页或管理 API 配置即可，不必手改 state JSON。

### openai-compatibility 通道

CPA 里配置的兼容通道，映射时 `provider` 填通道 **name**。插件路由时会对应到主机内部的 `openai-compatible-<name>`。通道配置里的 **models 列表要写全**，否则主机会报「该模型无可用 auth」。

---

## 插件能力一览

| 钩子 | 作用 |
|------|------|
| 前端鉴权 | 识别插件 key；校验别名、RPM、额度；写入路由与 group 元数据 |
| 模型路由 | 别名 → provider + 目标模型 |
| 请求拦截 | 校验受控请求身份，并原子占用 key 并发名额 |
| 请求生命周期 | auth 并发最终准入；HTTP/SSE 完成、失败、拒绝或取消时幂等释放 |
| 调度 | 取 key 绑定与目标 group 的交集，再按容量、session affinity、WRR/RR/fill-first 选择 |
| 响应拦截 | 非流式 JSON：把顶层 `model` 改回别名 |
| 用量 | token / 按次计费写入 state |
| 管理 API + 内嵌网页 | Key、别名、归类、状态 |

---

## 编译

Linux `.so` 需要 cgo：

```bash
make test
make build-linux          # 先编前端，再编 linux amd64/arm64 .so
# 或
make web-build
GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -buildvcs=false -tags cshared \
  -buildmode=c-shared -o dist/cpa-key-policy_linux_amd64.so ./cmd/cpa-key-policy
```

Windows 上请用 WSL/Linux 编 `.so`。`go test ./...` 可用非 cgo stub，不依赖动态库工具链。

把 `.so` 放进 CPA 的 `plugins.dir`，并在配置里启用插件。

---

## 配置

最小形态（完整示例见 [`config.example.yaml`](./config.example.yaml)）：

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    cpa-key-policy:
      enabled: true
      priority: 10
      state_file: "cpa-key-policy-state.json"
      global_weighted_round_robin: true
      session_affinity_idle_ttl_seconds: 3600
      session_affinity_max_entries: 10000
      auth_concurrency_limits:
        "codex-team-a.json": 4
      quota_check_interval: "30m"
      quota_cache_ttl: "30m"
      quota_activation_enabled: false
      quota_activation_scope: "managed-pools" # 或 all-codex
```

说明：

- 若已有 `state_file`，则以其中的 keys / 别名 / 归类 / 用量为准。
- `global_weighted_round_robin: true` 只会让未绑定的插件 key 忽略目标 group；显式账号绑定始终保持限制。默认为 `false`。
- `quota_activation_enabled` 默认为 `false`。若要维护宿主全部有效 Codex OAuth auth，请在面板确认风险后显式选择 `all-codex`。
- 日常请用**网页**或管理 API 建 key 和别名；YAML 种子数据主要用于首次启动。
- 公开文档里不要写真实管理密钥、主机名或凭证内容。

---

## 网页管理界面

插件内嵌。加载后访问：

```text
http://<你的-cpa-主机>:<api端口>/v0/resource/plugins/cpa-key-policy/index.html
```

用 CPA **管理密钥**登录（`remote-management.secret-key` 或管理密码）。密钥只放在内存，不写 `localStorage`；刷新页面需重新登录。

Key 持有人无需管理密钥，可访问：

```text
http://<你的-cpa-主机>:<api端口>/v0/resource/plugins/cpa-key-policy/lookup
```

自助页只使用 `Authorization: Bearer <自己的 key>` 查询当前 key，展示插件计价下的 UTC 自然日/现有 7 日窗口用量、调用/Token 汇总和当前 key 并发。它不接受 URL 中的 key 或 `key_id`，也不会显示账号绑定、auth 文件、hash 或其他 key 的信息。导入的 CPA 原生 key 目前没有模型/价格账本，因此会明确提示不支持用量查询。

| 区域 | 用途 |
|------|------|
| Keys | 创建/编辑/轮换/删除 key；绑模型或别名；RPM 与额度 |
| 映射 → 别名 | 全局多目标别名、调度方式、定价 |
| 映射 → 凭证归类 | 自定义分组规则与命中预览 |
| 选模型 | 提供商目录；内置档 / **自定义 · …** 子组 |

不重编 `.so` 时开发前端：

```bash
cd web
npm install
VITE_CPA_BASE=http://127.0.0.1:8317 npm run dev
```

---

## 管理 API 摘要

路径为精确匹配。鉴权：CPA 管理 Bearer。

**Key：** `GET/POST/PATCH/DELETE …/keys`，以及 `rotate` / `reset-rpm` / `usage` / `status`  

**运行时设置：** `GET/PATCH …/settings`（全局 WRR、auth 并发、亲和 TTL/容量）

**别名：** `GET/POST/DELETE …/aliases`  

**归类：**  

- `…/classify-rules`（含 reorder）  
- `POST …/classify-preview` — 预览组 → 凭证 id（组名为规则裸名）  
- `POST …/catalog` — 前端提交 auth-file + 模型列表，返回带 `classify:` 的选择器条目  

创建 key（`plain_key` **只返回一次**）：

```bash
curl -X POST "$CPA/v0/management/plugins/cpa-key-policy/keys" \
  -H "Authorization: Bearer $MANAGEMENT_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "team-a",
    "name": "Team A",
    "rpm": 60,
    "max_concurrent_requests": 4,
    "session_affinity": true,
    "account_binding": {
      "allow": ["codex-team-*.json"],
      "strategy": "weighted-round-robin"
    },
    "models": [
      {"alias":"fast","provider":"codex","target_model":"gpt-5.4-mini","group":"free"}
    ]
  }'
```

导入已有 CPA 原生 key 做账号绑定（该 key 仍须存在于 CPA `api-keys`；响应不会回显它）：

```bash
curl -X POST "$CPA/v0/management/plugins/cpa-key-policy/keys" \
  -H "Authorization: Bearer $MANAGEMENT_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "native-team-a",
    "native": true,
    "key": "existing-cpa-api-key",
    "account_binding": {
      "allow": ["openai-compatibility:corp:*"],
      "strategy": "round-robin"
    }
  }'
```

多目标别名示例：

```bash
curl -X POST "$CPA/v0/management/plugins/cpa-key-policy/aliases" \
  -H "Authorization: Bearer $MANAGEMENT_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "alias": "cheap-chat",
    "dispatch": "priority",
    "billing_mode": "tokens",
    "targets": [
      {"provider":"cerebras","target_model":"gpt-oss-120b"},
      {"provider":"codex","target_model":"gpt-5.4-mini","group":"free"}
    ]
  }'
```

---

## 客户端请求行为

| 情况 | 结果 |
|------|------|
| 认识的 key + 允许的别名 | 鉴权通过 → 路由 → 可选 group 过滤 → 上游 |
| 不允许的模型名 | 鉴权失败 |
| 超 RPM / 额度 | 拒绝 |
| 写了 group 但组内无可用凭证 | `auth_not_found` / 不可用（不串档） |
| 账号绑定在宿主候选中没有可用账号 | `auth_not_bound` / 不可用，不回退全池 |
| 绑定 key 仅放 query，或 Header 凭证冲突 | 访问上游前拒绝 |
| 不认识的 key | 插件放弃，CPA 可尝试原生 `api-keys` |
| 非流式对话响应 | 顶层 `model` 改回别名 |
| 流式 | v1 不改写 body |

### 主端口的 `/v1/models`

每 key 的 `allow_models_endpoint` 是**开关**：拒绝（401）或看**全局完整列表**。主端口无法按插件 key 过滤列表。


---

## 上手清单

1. 编译/安装 `.so` 到 CPA `plugins.dir`。  
2. 启用 `plugins` 与 `cpa-key-policy`，配置 `state_file`。  
3. 用管理密钥打开网页 UI。  
4. （可选）配置**凭证归类**规则。  
5. 建**别名**（多目标/定价）和/或给 key 勾选模型（含档位或「自定义 · …」）。  
6. 创建 key，按需配置账号绑定 glob，保存一次性 `plain_key`，发给客户。
7. 客户：OpenAI 兼容 base URL = CPA；`Bearer cpa_…`；`model` = 别名。  
8. openai-compat 通道务必声明 models，否则会「无 auth」。

---

## 测试

```bash
go test ./...
cd web && npm test && npm run build
```
