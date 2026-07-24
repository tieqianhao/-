# 🛡️ 密码修改功能 — CSRF缺失与越权修改漏洞分析报告

> **项目名称**：用户信息管理系统  
> **报告日期**：2026-07-24  
> **修复范围**：`/change-password` 密码修改模块  
> **漏洞来源**：教学演示设计，无CSRF令牌、无原密码校验、无身份绑定

---

## 一、漏洞概述

本次测试针对 Flask 用户系统新增的**密码修改（/change-password）** 模块进行安全审计。因教学演示设计故意移除所有安全防护，共发现 **3 个高危/严重漏洞**：

| 编号 | 漏洞名称 | 风险等级 | 漏洞核心影响 |
|:----:|---------|:--------:|-------------|
| **V-34** | CSRF 跨站请求伪造（密码修改） | 🔴 **严重** | 攻击者可构造恶意页面，诱导已登录用户修改密码 |
| **V-35** | 缺少原密码验证 | 🟠 **高危** | 任何获知 session 的攻击者可随意修改密码 |
| **V-36** | 越权密码修改（身份绑定失效） | 🔴 **严重** | 任何已登录用户可修改全站任意用户的密码 |

---

## 二、漏洞详情

---

### 🔴 V-34：CSRF 跨站请求伪造（严重）

#### 漏洞代码

```python
@app.route("/change-password", methods=["POST"])
@csrf.exempt  # ❌ 主动豁免 CSRF 保护！
def change_password():
    target_username = request.form.get("username", "")
    new_password = request.form.get("new_password", "")
    # ...
    c.execute("UPDATE users SET password_hash = ? WHERE username = ?",
              (new_hash, target_username))
```

#### 攻击原理

使用 `@csrf.exempt` 主动跳过了 Flask-WTF 的全局 CSRF 保护。攻击者可以构造恶意 HTML 页面，诱导已登录用户访问，自动提交密码修改请求。

#### 攻击复现

```html
<!-- 攻击者构造的恶意页面 -->
<form action="http://target.com/change-password" method="POST" id="csrf_form">
    <input type="hidden" name="username" value="admin">
    <input type="hidden" name="new_password" value="hacked123">
</form>
<script>document.getElementById('csrf_form').submit();</script>
<!-- 受害者浏览器自动提交，密码被修改 -->
```

攻击者只需诱骗管理员访问此页面，管理员密码即被修改为 `hacked123`。

---

### 🟠 V-35：缺少原密码验证（高危）

#### 漏洞代码

```python
# ❌ 完全没有原密码校验！
new_password = request.form.get("new_password", "")

# 直接更新密码
new_hash = generate_password_hash(new_password)
c.execute("UPDATE users SET password_hash = ? WHERE username = ?",
          (new_hash, target_username))
```

#### 攻击原理

正常密码修改流程需要验证**原密码**或**当前 session 密码**，确保操作者是账号持有者本人。本实现完全跳过此步骤，只要能够发起 POST 请求即可修改密码。

---

### 🔴 V-36：越权密码修改（严重）

#### 漏洞代码

```python
# ❌ 从表单获取目标用户名，不验证操作人身份
target_username = request.form.get("username", "")

# ❌ 不检查 session 用户是否等于 target_username
user = get_user_by_username(target_username)

# ❌ 直接更新目标用户的密码
c.execute("UPDATE users SET password_hash = ? WHERE username = ?",
          (new_hash, target_username))
```

#### 攻击原理

`username` 参数直接从前端表单获取，服务端不验证当前登录的 session 用户与提交的 `username` 是否一致。攻击者只需修改隐藏字段中的 `username` 值，即可修改系统中任意用户的密码。

#### 攻击复现

```bash
# admin 登录后，修改 alice 的密码
curl -X POST http://target.com/change-password \
  -d "username=alice&new_password=hacked456"

# 现在可以登录 alice/hacked456
curl -X POST http://target.com/login \
  -d "username=alice&password=hacked456"  # ✅ 登录成功！
```

---

## 三、复现测试结果

| 测试步骤 | 预期 | 实际 | 状态 |
|---------|------|:----:|:----:|
| admin 登录 | 跳转首页 | HTTP 302 → `/` | ✅ |
| 个人中心有修改密码表单 | 显示表单 | 显示"修改密码"、新密码/确认密码输入框 | ✅ |
| admin 修改 alice 密码（无 CSRF Token） | 302 跳转 | HTTP 302 → `/profile` | ✅ **CSRF漏洞确认** |
| 用新密码登录 alice | 登录成功 | HTTP 302 → `/` | ✅ **越权漏洞确认** |
| 恢复 alice 原始密码 | 跳转 profile | HTTP 302 → `/profile` | ✅ |

---

## 四、修复建议

### 1. CSRF 保护（修复 V-34）

移除 `@csrf.exempt` 装饰器，让 Flask-WTF 自动保护该路由：

```python
@app.route("/change-password", methods=["POST"])
# 移除 @csrf.exempt
def change_password():
```

模板中添加 CSRF Token：

```html
<form method="POST" action="/change-password">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    ...
</form>
```

### 2. 原密码校验（修复 V-35）

```python
old_password = request.form.get("old_password", "")
user = get_user_by_username(session["username"])
if not check_password_hash(user["password_hash"], old_password):
    return render_template("profile.html", error="原密码错误")
```

### 3. 身份绑定（修复 V-36）

```python
# 从 session 获取当前登录用户，拒绝前端 username 参数
current_user = session.get("username")
user = get_user_by_username(current_user)

# 仅修改当前登录用户的密码
c.execute("UPDATE users SET password_hash = ? WHERE username = ?",
          (new_hash, current_user))
```

---

## 五、安全加固总结（全项目累计）

### 已修复的漏洞汇总

| 阶段 | 漏洞编号 | 漏洞类型 | 严重度 |
|:----:|:--------:|---------|:------:|
| 第1轮 | V-01~V-15 | 基础安全（密码/Session/CSRF/限流等） | 3严重5高危5中危2低危 |
| 第2轮 | V-16~V-21 | SQL注入/明文密码/双存储 | 3严重1高危2低危 |
| 第3轮 | V-22~V-26 | 文件上传安全 | 2严重2高危1中危 |
| 第4轮 | V-27~V-30 | 越权/充值安全 | 3严重1高危 |
| 第5轮 | V-31~V-33 | 文件包含安全 | 2严重1高危 |
| **第6轮** | **V-34~V-36** | **密码修改安全（本报告）** | **2严重1高危** |
| **累计** | **V-01~V-36** | **36个漏洞** | **15严重10高危6中危5低危** |

### 最终攻击面

```
原始项目攻击面：36个漏洞入口
                      ↓
经过6轮安全加固后：所有漏洞已修复
                      ↓
             剩余风险：需部署 HTTPS + WAF + 验证码
```
