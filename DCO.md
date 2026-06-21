# Developer Certificate of Origin (DCO)

kcatta 使用 [Developer Certificate of Origin 1.1](https://developercertificate.org/)（**DCO**）管理贡献者声明。  
向本仓库提交 Pull Request 即表示你同意下列条款，并在 **每个 commit** 中包含 `Signed-off-by` 行。

---

## 如何使用（贡献者必读）

1. **仅提交你有权贡献的内容**（自有原创，或许可证允许你再贡献的第三方代码）。
2. 创建 commit 时加 `-s` 参数，Git 会自动追加签核行：

   ```bash
   git commit -s -m "feat(analyzer): add example endpoint"
   ```

3. 签核行格式（须与 commit 作者一致）：

   ```
   Signed-off-by: Zhang San <zhangsan@example.com>
   ```

4. **每个 commit 各有一条** `Signed-off-by`；PR 中若 rebase/squash，请确保最终 commit 仍保留签核。
5. 若 PR 缺少 DCO 签核，Maintainer 可能要求你 amend 或 rebase 后 force-push。

**代理提交：** 若你代表雇主或客户贡献，签核仍使用 **你个人** 姓名与邮箱，并确保你已获其授权（见 DCO 正文第 (c) 条）。

---

## Developer Certificate of Origin 1.1

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

---

## 中文摘要（非法律译文，仅供参考）

通过向 kcatta 贡献代码，你声明：

- **(a)** 贡献为你原创或你有权在仓库所示开源许可证下提交；或  
- **(b)** 贡献基于已有开源作品，且你有权在同许可证下提交你的修改；或  
- **(c)** 贡献来自已做 (a)(b)(c) 声明的他人，且你未再修改（若已修改则适用 (a) 或 (b)）；且  
- **(d)** 你理解贡献公开，签核信息可被长期保存与再分发。

---
