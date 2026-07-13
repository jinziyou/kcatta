# Form public JSON Schemas

这些文件由 `form-export-schemas` 生成，定义 Form 对 Admin、Agent 和外部导入方
暴露的公共边界；Form 与 Analyzer 之间另走私有 HTTP 契约。不要手工编辑。

```bash
cd form
uv run form-export-schemas
```
