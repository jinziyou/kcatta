# kcatta 商标政策

本文说明 **「kcatta」** 名称及相关标识（logo、图标、视觉识别元素，合称 **Marks**）的使用规则。  
**Marks 由 kcatta 项目 Leadership 持有或管理，与源代码许可证相互独立。**

> 源代码许可证（见根目录 [`LICENSE`](LICENSE)，当前为 Apache-2.0）授予你使用、修改与再分发**代码**的权利；  
> **并不**授予你使用 kcatta Marks 暗示官方背书、合作或隶属关系的权利。

## 1. 官方身份

以下由 Project Leadership 认定为 **官方** kcatta 渠道（清单可随项目发展更新）：

| 类型 | 官方地址 |
| --- | --- |
| 源代码仓库 | `https://github.com/jinziyou/kcatta` |
| 安全通告 | 本仓库 [`SECURITY.md`](SECURITY.md) 所列渠道 |
| 发布产物 | 由 Project Leadership 在本仓库 **Releases** 或官方文档中明确标注的构建物与容器镜像 |

任何未在上表或 Project Leadership 书面公告中列出的网站、SaaS、安装包、市场条目或社交媒体账号，**均非官方**，即使其代码来自本仓库 fork。

## 2. 允许的使用（无需额外授权）

在**不造成混淆**的前提下，你可以：

1. **如实描述**  
   说明你的软件「基于 kcatta 开源项目（Community Edition）」或「forked from jinziyou/kcatta」，并链接至官方仓库。

2. **学术与技术讨论**  
   在文章、演讲、课程中引用 kcatta 名称以指代本项目或其技术。

3. **运行与修改 CE 代码**  
   在遵守 [`LICENSE`](LICENSE) 的前提下自托管、内部使用或再分发**已改名的**衍生版本（见下文第 4 节）。

4. **贡献 upstream**  
   向官方仓库提交 PR、在 commit message 或贡献者署名中使用 kcatta 项目名称。

**要求：** 上述使用不得暗示 Project Leadership 对你的 fork、托管服务或产品提供担保、认证或官方支持。

## 3. 禁止的使用

未经 Project Leadership **事先书面许可**，不得：

1. 在产品名、域名、仓库名、Docker 镜像名、SaaS 产品名或市场列表中使用 **kcatta** 或与之混淆的近似名称（如 `kcatta-cloud-official`、`official-kcatta`），若可能使 reasonable user 误认为官方服务。

2. 使用 kcatta **logo / 图标** 作为你方产品的主标识，或修改后作为商业服务商标。

3. 声称或暗示与 Project Leadership 存在 **赞助、合伙、雇佣、认证或「官方发行版」** 关系。

4. 在营销材料中使用 **「Official kcatta」**、**「kcatta 官方版」**、**「Authorized kcatta Partner」** 等表述（Project Leadership 书面授权除外）。

5. 将 **Enterprise Edition（EE）** 或商业功能描述为开源 CE 的一部分，或冒用 EE 品牌。

## 4. Fork 与衍生版本的命名

若你 fork 或基于 CE 发布衍生产品，请 **重新命名**，并与官方 Marks 显著区分：

| 建议 | 示例 |
| --- | --- |
| ✅ 带前缀/后缀的独立名称 | `Acme-SOC Platform (based on kcatta)` |
| ✅ 组织命名空间 | `github.com/your-org/your-blue-team-platform` |
| ❌ 易混淆名称 | `kcatta`、`kcatta-pro`、`kcatta-official`、`jinziyou-kcatta`（作为产品名） |

README 中 **建议** 包含醒目说明，例如：

```markdown
This is an independent fork of the open-source kcatta project.
It is not affiliated with or endorsed by the kcatta Project Leadership.
Upstream: https://github.com/jinziyou/kcatta
```

## 5. 与许可证的关系（常见误解）

| 问题 | 答案 |
| --- | --- |
| Apache-2.0 允许我改代码商用吗？ | 允许（在许可证条款内），但仍须遵守本商标政策 |
| 我可以把 fork 仍叫作 kcatta 吗？ | **不可以**用于产品/服务命名若会导致官方混淆；技术讨论中「based on kcatta」除外 |
| 商标政策能否阻止我 fork？ | 不能阻止 fork **代码**；仅限制 **Marks 的使用方式** |
| EE 客户能否使用 kcatta 名称？ | 仅在其与 Project Leadership 签订的 **商业许可** 允许范围内 |

## 6. 商标授权申请

如需在以下场景使用 Marks，请通过 [GitHub Issues](https://github.com/jinziyou/kcatta/issues) 发起联系（选择不公开细节时可说明「Trademark inquiry」并请维护者提供私密联系方式）：

- 经 Project Leadership 批准的 **下游发行版** 或 **合作集成** 使用 kcatta logo
- 会议、媒体或教育用途的 **官方 logo** 展示
- **兼容性与认证** 计划（如「kcatta Compatible」类标识）

Project Leadership 保留拒绝任何请求的权限，且不得因拒绝而影响你在 CE 许可证下使用源代码的权利。

## 7. 政策修订

本政策可由 Project Leadership 修订；修订通过官方仓库 PR 合并后生效。  
与 [`GOVERNANCE.md`](GOVERNANCE.md) 冲突时，以 Project Leadership 对 **Marks** 问题的最新书面解释为准。

## 8. 免责声明

本文件为项目政策说明，**不构成法律意见**。  
若你所在司法辖区对商标使用有额外要求，请咨询专业律师。
