# Go 权限组件设计

## 1. 目标与范围

本文是设计方案，不表示相关接口已经实现。

目标是将分散在业务 Service、DAO 和 handler 中的权限规则集中到 `internal/permission`，为社区版和企业版提供相同的调用契约。两版使用不同文件实现同名策略方法，业务调用方不判断版本。

设计原则：

- 权限组件直接依赖 DAO，不依赖业务 Service，避免循环依赖。
- 身份认证、权限判断、业务有效性检查分别负责，不混成一个万能校验。
- 单对象访问、列表、统计、检索使用一致的权限规则。
- 社区版不依赖企业版权限表，不添加无实际用途的企业版空接口。
- 完成迁移后删除原有重复检查，不长期保留两套权限路径。

## 2. 身份与租户

### 2.1 字段语义

| 字段 | 含义 | 可信来源 |
| --- | --- | --- |
| `UserID` | 谁发起操作 | 登录身份或 API Token 对应用户 |
| `Subject.TenantID` | 操作所在的租户范围 | 请求上下文中的租户，并由服务端验证 |
| `MemberID` | 用户在该租户的成员记录 ID | 根据 UserID + TenantID 查询 UserTenant |
| 资源的 `TenantID` | 资源所属租户 | 资源及其所属关系的数据库记录 |
| `CreatedBy` | 资源创建用户 | 资源数据库记录 |

`UserID` 与 `TenantID` 不能互相替代。个人租户中二者经常相等，但不能仅凭相等就推断任意租户的所有者权限。租户所有者由有效成员关系及 owner 角色确定，资源创建者与租户所有者也分别判断。

业务写入新资源时，`CreatedBy` 记录实际发起操作的 `Subject.UserID`；资源的 `TenantID` 记录资源所属租户，子资源从数据库中的父资源解析所属租户。不要把 `TenantID` 复制到 `CreatedBy`，也不要接受请求体提供的 `CreatedBy`。如果操作由系统自动触发且没有用户发起人，必须使用明确的受限系统身份，而不是把租户 ID 当作用户 ID。

租户字段统一命名为 TenantID，不使用 OwnerTenantID。通过所属对象区分语义：Subject.TenantID 是操作租户，资源或模型的 TenantID 是所属租户。二者分别从可信上下文和资源数据取得，不能互相覆盖；企业版检查它们相等。

共同调用身份：

```go
type Subject struct {
    UserID   string
    TenantID string
}

type ResourceRef struct {
    Kind ResourceKind
    ID   string
}
```

成员 ID、角色、管理员身份、用户组和部门由权限组件读取可信数据，不由前端提交后直接采用。资源的所属租户、创建者和父资源也从数据库读取。

### 2.2 当前租户与资源租户

- 社区版按共享规则确定可访问的资源范围；企业版当前租户和资源所属租户必须一致，禁止跨租户调用。
- 不允许通过覆盖 Subject.TenantID 来绕过租户隔离或授权。
- 普通团队访问需要有效成员资格，但成员资格本身不代表拥有所有资源权限。
- 企业版即使用户同时属于多个租户，也不能在租户 A 的执行上下文使用租户 B 的资源；选择租户 B 后必须重新建立上下文并校验 B 内的权限。
- 只有资源 ID 的接口，应先解析资源归属，再按接口明确的访问规则建立和校验租户上下文。
- invite 状态的成员不能因为记录 status 有效就取得正式成员权限。

### 2.3 后台任务

后台任务保留发起人：谁发起任务，谁就是 UserID。异步执行不能丢掉用户身份，空 UserID 不能作为权限绕过条件。

```text
用户请求
  → 校验权限
  → 持久化 UserID、TenantID
  → 入队
  → Worker 恢复身份并重新校验权限
  → 执行任务
```

- 自动派生的库级编译任务继承来源任务发起人的身份。
- 重试、恢复和跨服务消息传递都保留该身份。
- 若多个来源事件合并，保留各事件的发起人，逐事件校验，不能任选一个用户代表全部事件。
- 排队期间发生成员移除或授权撤销，执行时应拒绝已失效的访问。
- 撤销不能保证即时中断已经发出的外部调用；长任务应在关键阶段重新校验，授权快照不能永久有效。
- 真正无人发起的系统定时任务另行定义明确、受限的系统身份，不通过空 UserID 隐式放行。

## 3. 权限维度

企业版现有实现包含两套不同语义的权限，必须分别建模。

### 3.1 功能权限

角色决定是否开放某个功能，以及是否允许功能操作。企业版现有功能包括 Dataset、Chat、Agent、Search、File、Team、Memory、ModelProvider。

角色操作使用 Enable / Read / Write / Share 位掩码。操作检查同时要求功能 Enable 和对应操作位。社区版对已经支持的功能不增加角色限制，但不放行未定义的功能或操作。

### 3.2 资源权限

判断对具体知识库、文档、对话、Agent、搜索应用、文件、Memory、模型、MCP 等资源可以执行什么操作。

| 规则 | 社区版 | 企业版 |
| --- | --- | --- |
| 所有者 | 按现有资源所有者规则 | 所有者及资源创建者规则，按资源类型确定 |
| 共享 | 共享给用户后，对该资源的操作权限与 tenant owner 相同 | 成员、用户组、部门及祖先部门授权，可区分等级 |
| 依赖访问 | 用户与共享资源 tenant owner 的可访问范围取交集 | 只允许当前租户内明确授权的依赖，不借用 owner 权限 |
| 不支持共享的资源 | 不增加共享授权限制，例如模型使用 | 可以增加模型等资源的明确授权限制 |
| 文档 | 按社区版知识库、文件访问规则 | 文档独立授权，不能默认继承知识库可读权限 |

企业版现有资源等级为 None=0、Read=1、Write=2、Manage=4、Owner=7，按等级比较。它不是角色操作位掩码，不能按同一种方式计算。

公开接口使用实际 Operation，如 Read、Update、Delete、Share、Run、Use；版本策略内部将操作映射为相应的授权要求。不能认为 Write 自动允许所有删除或管理操作。

功能与资源分别检查：能够使用 Agent 功能，不代表可以运行任意 Agent；资源所有者也不默认绕过角色功能限制。

管理员、超级管理员也不能通过普通资源访问和执行接口绕过企业版租户隔离。独立管理接口的能力需单独定义，不作为资源执行的隐式授权。

### 3.3 社区版的两条核心规则

本节是社区版目标规则，不以现有代码中可能残留的 owner-only 分支为准。

**规则一：共享资源的操作权限相同，依赖资源的访问范围取交集。**

资源已经有效共享给当前用户，该用户对这个资源的操作能力与该资源 tenant owner 相同，不另外划分只读、可编辑、可删除的共享等级。共享不会让用户成为租户 owner，也不会授予租户管理权限。

资源执行期间访问其他资源时，只能访问当前用户和该资源 tenant owner 都能访问的资源：

```text
共享资源本身的操作能力 = tenant owner 对该资源的操作能力
共享资源可用的依赖范围 = 用户可访问范围 ∩ tenant owner 可访问范围
```

例如 Agent A 共享给用户 B：

- B 对 A 的操作权限与 A 的 tenant owner 相同。
- A 引用知识库 K，只有 B 和 A 的 tenant owner 都能访问 K 时，运行才允许使用 K。
- 不能因为 A 已共享，就使用 owner 的身份读取 owner 未共享给 B 的知识库。
- 也不能使用只有 B 能访问、owner 不能访问的知识库。
- 原始发起人的 UserID 始终保留，不用 owner 身份替换它；owner 只是依赖权限计算的另一方。
- 嵌套调用和后台执行继续携带已确定的执行范围，不能切换身份或进入下一层时丢掉上层限制。

**规则二：是否检查共享，取决于资源类型是否支持共享。**

- 支持共享的资源：访问自己拥有的资源，或有效共享给自己的资源；加入租户本身不会自动开放该租户的所有此类资源。
- 不支持共享的资源：不要求额外的共享记录，例如社区版模型使用；在已验证的租户访问范围内可用，不因为缺少共享字段就拒绝。
- “不要求共享”不等于跨任意租户访问，也不等于返回模型密钥；租户边界、操作类型、资源状态及业务有效性仍需检查。
- 各资源是否支持共享由资源策略集中定义；文档、chunk 等从属资源按父资源规则处理，不能因自身没有共享字段就当成无限制资源。

社区版由此保持简单：共享对象不细分权限等级，支持共享的依赖检查双方交集，不支持共享的依赖不增加共享限制。企业版在相同接口下增加精细授权。

### 3.4 企业版的两条核心规则

**规则一：默认拒绝，只有明确具有对应权限才能访问或执行。**

- 功能操作和具体资源操作均按明确策略校验，缺少授权、授权失效或没有配置操作规则时拒绝。
- 仅登录、加入租户或能打开入口资源，不代表能访问它引用的其他资源。
- owner、创建者、管理员的能力必须是明确的策略规则，不能从社区版共享规则推导或隐式放行。
- 模型也需要明确的使用权限，不能因为模型不支持共享就默认允许。
- 资源执行时校验实际发起人对每项依赖的权限，不以入口资源 owner 的权限替代用户权限。

**规则二：租户完全独立，禁止跨租户调用。**

```text
执行租户 = 入口资源租户 = 所有依赖资源租户
允许操作 = 租户一致 ∧ 功能操作允许 ∧ 资源操作明确允许
```

隔离覆盖详情、列表、统计、检索、模型调用、Agent/Chat/pipeline 依赖及后台任务。用户属于两个租户、资源存在授权记录、模型被配置为角色默认值，都不是跨租户调用的例外。

角色、成员、用户组、部门授权必须在目标租户内计算，不能将另一个租户的身份或授权混入当前结果。跨租户配置应在配置写入时拒绝，运行时仍再次校验，避免旧数据或绕过配置入口导致越界。

企业版现有 Python 路径中允许跨租户角色默认模型的行为，仅作为现状参考，不属于本设计的目标行为，应在 Go 实现中收敛到租户隔离规则。

## 4. 共同接口

以下是拟议方法签名：

```go
func (c *Checker) CheckFeature(ctx context.Context, subject Subject, feature Feature, action Action) error
func (c *Checker) CheckTenant(ctx context.Context, subject Subject, tenantID string, requirement TenantRequirement) error
func (c *Checker) CheckResource(ctx context.Context, subject Subject, resource ResourceRef, operation Operation) error
func (c *Checker) CheckDependency(ctx context.Context, subject Subject, entry ResourceRef, dependency ResourceRef, entryOperation, dependencyOperation Operation) error

func (c *Checker) ResolveAccess(ctx context.Context, subject Subject, resource ResourceRef) (Access, error)
func (c *Checker) Scope(ctx context.Context, subject Subject, query ScopeQuery) (Scope, error)
func (c *Checker) FilterResources(ctx context.Context, subject Subject, resources []ResourceRef, operation Operation) ([]ResourceRef, error)
```

| 方法 | 共同语义 |
| --- | --- |
| CheckFeature | 检查角色层面的功能及操作权限，不代替资源授权 |
| CheckTenant | 检查指定租户中的有效成员、管理员或所有者身份 |
| CheckResource | 检查具体资源的指定操作，使用 ResolveAccess 的同一套规则 |
| CheckDependency | 检查资源执行时的依赖访问；社区版计算用户与 owner 的交集，企业版检查同租户内的明确授权 |
| ResolveAccess | 返回实际允许操作和授权来源，供操作按钮及授权解释使用 |
| Scope | 生成列表、统计和检索所需的权限范围 |
| FilterResources | 批量检查给定候选资源，返回允许访问的子集 |

CheckTenant 的 tenantID 是需要检查的目标租户；Subject.TenantID 是当前操作上下文，二者语义不能混淆。

Access 返回允许的操作及来源，不强迫社区版伪造企业版权限记录。检查所需等级、共享继承、所有者规则由资源策略确定，不由调用方临时拼装。

当前社区版实现通过 `Source` 注入规范化事实，不绑定具体 DAO 或业务实体：成员状态与角色；资源的 `TenantID`、owner UserID、有效状态、可见范围、owner 可执行操作及共享目标；以及查询范围内的候选资源 ID。`GetResources` 支持批量加载，范围计算在单次求值中复用已加载的成员和资源事实。业务接入时再由对应 DAO 适配这些事实。

CheckResource 处理直接操作目标资源；CheckDependency 处理通过 Agent、Chat、Search、pipeline 等资源使用另一个资源。入口资源的 owner 由数据库解析，且先校验用户可以操作入口资源，不能由客户端指定任意 owner。

ScopeQuery 在资源执行场景包含入口资源引用，使 Scope 按版本策略计算依赖范围：社区版为双方交集，企业版为当前租户内明确授权范围。嵌套执行通过服务端内部执行上下文保留限制，不重复从前端输入构造授权范围。CheckDependency 与 Scope 必须使用同一套策略，防止详情检查严格、实际检索却使用更宽范围。

对于创建资源、授权管理等没有现成目标资源的操作，组合功能检查和租户检查，不传空资源 ID 让 CheckResource 自动放行。

### 4.1 批量查询与检索范围

Scope 明确区分：

```text
指定 ID 集合允许 / 全部拒绝
```

当前通用实现只返回明确筛选后的 ID 集合，不推断“所有资源都允许”。范围始终限定租户和父资源边界；后续若需要无 ID 的 SQL 权限谓词，应在不扩大授权范围的前提下另行增加可验证的范围表达。

- 空 ID 集合不能同时表示“不限制”和“无权限”。
- SQL 查询在分页和统计之前应用权限条件，不能查完一页后过滤。
- 大规模资源列表优先使用数据库条件或子查询，避免把全部授权 ID 加载到内存。
- ES/Infinity 检索将文档范围转换为对应过滤条件；全部拒绝时直接返回空结果，不能退回无过滤查询。
- 引用、下载、原文和知识编译产物访问也使用同一份文档授权边界。
- 库级聚合产物涉及多个来源文档时，不能仅凭 dataset_id 放行。需要根据来源文档过滤，无法安全拆分的混合产物应拒绝返回。
- FilterResources 是候选批量筛选，不替代列表查询的权限范围；实现应避免逐条重复查询成员、用户组和部门。

### 4.2 错误契约

区分未认证、非有效成员、功能未开放、资源无权限、资源不存在以及数据库错误。数据库错误不能吞掉后伪装成 false。

权限组件不返回 HTTP 响应；handler 将权限错误统一映射成 API 错误。是否将无权限资源对外隐藏为 Not Found，由统一 API 策略决定，内部保留真实原因。

## 5. 社区版与企业版实现切换

```text
internal/permission/
    types.go
    checker.go
    policy_ce.go
    policy_ee.go
    checker_test.go
    policy_ce_test.go
    policy_ee_test.go
```

- types.go 定义共同契约，checker.go 定义公开入口、基础验证和错误处理。
- policy_ce.go 与 policy_ee.go 定义同名私有 policy 类型和同名策略方法，如 checkFeature、checkTenant、resolveAccess、scope。
- 两版 policy 可以持有不同 DAO；共同 Checker 不要求社区版持有企业版 DAO。
- Router/启动装配创建 Checker 并注入业务组件，不在每次调用时创建。

使用互斥构建标签：

```go
// policy_ce.go
//go:build !enterprise
```

```go
// policy_ee.go
//go:build enterprise
```

`_ee.go` 文件名本身没有版本选择能力。企业版构建必须通过统一构建入口启用 enterprise 标签；社区版代码仍可不携带企业版私有策略文件。

两版方法签名、错误分类和外部调用路径相同，具体授权规则不同。业务代码不增加 if enterprise 分支，也不保留两套 Service 包装。

## 6. 各层职责

| 层 | 职责 |
| --- | --- |
| 认证中间件 | 建立可信用户身份，处理登录及 API Token |
| handler / 路由 | 声明功能操作要求、处理 API 错误映射 |
| 业务 Service | 在实际业务入口调用资源及租户检查，防止非 HTTP 调用绕过 |
| permission | 成员解析、功能策略、资源授权及范围计算 |
| DAO | 数据读取、授权条件查询与事务支持 |
| ModelFactory | 解析模型身份、检查模型使用权限、创建实例 |
| Worker | 恢复任务发起人身份，在执行与关键阶段检查权限 |

资源状态、模型类别、驱动能力、配置是否有效、业务流程前置条件仍由所属业务组件检查。

更新、删除等敏感操作的检查与执行尽量使用同一事务。Checker 应支持事务绑定的 DAO/数据库会话，不能校验时读全局 DB、执行时用另一个事务。

## 7. 模型权限与默认模型

模型使用路径统一为：

```text
UserID + TenantID + modelRef
  → 解析真实模型及模型的 TenantID
  → 检查 Model / Use 权限
  → 创建模型实例
  → 执行模型调用
```

- 模型列表与调用使用一致的授权规则，不能列表不可见但知道 ID 就可以调用。
- 社区版模型属于不增加共享限制的资源；模型检查不能凭空要求一个 model 共享记录。经共享资源调用模型时仍保留执行上下文和明确的租户边界。
- 能使用模型不代表可以读取 API Key、修改实例或管理 Provider；这些是不同操作。
- 角色默认模型的选择属于模型解析，不属于 permission；解析后仍需校验使用权限。
- 企业版角色默认模型必须属于当前租户且用户明确具有使用权限。旧数据指向其他租户时拒绝使用，不能切换租户或借用模型 owner 身份调用。
- 企业版现有部分 LLM 授权以 factory/provider 名称作为 resource_id。迁移 Go 模型 ID 时必须明确 Provider、实例、模型的授权映射，不能假定旧数据已经是模型 ID。
- 现有默认模型优先级不因抽取权限组件而改变；需要调整优先级时另行明确行为。

## 8. 企业版管理能力

授权修改与运行时权限检查分开。企业版权限管理组件提供 SetGrants、RevokeGrants、ListGrants、ListGrantChanges 等能力，角色、用户组和部门管理仍由对应组件负责。

- 修改前检查管理权限及目标所属租户，不能越权给自己或他人提权。
- 授权变更和审计记录在同一事务内提交。
- 审计保留操作用户、成员 ID、租户、目标、资源、原权限、新权限和原因。
- 社区版不实现无意义的授权表写入或成功空响应。

## 9. 缓存与一致性

- 优先复用一次请求或一个执行阶段内的成员、组、部门查询结果。
- 不永久缓存允许结果；授权撤销、成员移除、角色变更需要失效机制。
- 不仅以 UserID 为缓存键，还必须包含租户、资源及操作等必要维度。
- 对敏感操作保留事务内重新检查，不用旧缓存结果代替。

## 10. 落地顺序与验证

1. 固定共同身份、资源、操作和范围契约，盘点当前各资源实际规则。
2. 实现社区版策略及共同测试：共享资源操作能力与 tenant owner 相同，依赖范围取双方交集；不把租户成员资格当成所有资源均已共享。
3. 迁移 Dataset、Document、File、Agent、Chat、Search、Memory、Model 的真实调用入口。
4. 同步迁移列表、统计和检索过滤，删除重复 DAO/Service 权限分支。
5. 为任务消息和记录补齐并传递 UserID、TenantID，包括派生和合并事件。
6. 企业版实现角色、成员、用户组、部门授权及文档独立范围，复用共同调用方。
7. 企业版完成授权管理、审计、缓存失效和角色默认模型授权。

共同测试至少覆盖：

- UserID 与 TenantID 不同的正常成员操作；非成员、invite、失效成员拒绝。
- 社区版共享用户与 tenant owner 对共享资源的操作能力相同，但共享用户不获得租户管理权限。
- 依赖仅用户可访问、仅 owner 可访问、双方均可访问三种情况；只有双方均可访问才允许使用。
- 社区版模型等不支持共享的资源不要求共享记录，从属资源不能因没有共享字段绕过父资源规则。
- 嵌套执行、后台任务及检索保留同一交集范围，不切换为 owner 身份。
- 功能允许但资源拒绝，以及资源允许但功能拒绝。
- 企业版成员、组、部门和祖先部门授权合并、撤销。
- 知识库可读但部分文档不可读；文档范围为空时检索必须为空。
- 分页、统计、详情、下载和检索的权限一致性。
- 模型可用与配置可管理分离，企业版缺少模型使用授权时拒绝。
- 企业版跨租户角色默认模型、嵌套依赖、检索及后台任务均拒绝，即使用户同时加入两个租户或存在跨租户授权记录。
- 后台任务身份继承、合并事件逐来源身份校验和执行前授权撤销。
- 数据库故障不被伪装为普通拒绝；事务内检查使用同一数据库会话。
- 社区版与企业版构建分别通过，策略文件不同时参与编译。

## 11. 现有实现参考

社区版 Go：

- `internal/service/team_permission.go`
- `internal/service/dataset/permission.go`
- `internal/service/file_permission.go`
- `internal/service/model_factory.go`
- `internal/dao/user_tenant.go`
- `internal/dao/tenant.go`

企业版现有规则参考（`/home/infiniflow/ragflow_enterprise`）：

- `common/role_util.py`：角色功能操作权限。
- `api/utils/permission_utils.py`：资源、成员、组、部门及文档授权。
- `api/db/services/permission_service.py`：授权查询、批量范围计算。
- `api/db/__init__.py`：权限枚举及数值语义。
- `api/db/db_models.py`：权限、审计和角色默认模型表。
- `api/db/joint_services/tenant_model_service.py`：角色默认模型解析。

以上 Python 路径仅用于核对已有业务语义；落地实现与新增测试都在 Go 中，不新增 Python 权限路径。
