# Flask新增个性化页面功能——SSTI漏洞分析与修复

## 一、项目背景

本项目为 Flask 用户管理系统，近期新增了两个个性化页面：

- **`/welcome`**：欢迎页，从 URL 参数 `?name=` 获取用户姓名并展示个性化问候
- **`/feedback`**：反馈页，用户可提交姓名和留言，提交后展示反馈结果

两个页面均使用 `render_template_string` 渲染模板，但由于实现方式不当，引入了 **SSTI（服务端模板注入）** 漏洞。

---

## 二、新增功能完整实现代码（存在漏洞版本）

### 2.1 app.py 漏洞代码

```python
from flask import Flask, request, render_template_string, render_template

app = Flask(__name__)
# ==========原有业务代码保持不变==========

# 1. 新增 /welcome GET路由
@app.route('/welcome', methods=["GET"])
def welcome():
    name = request.args.get("name", "")
    if not name:
        name = "亲爱的用户"
    # ⚠️ f-string直接拼接用户可控输入至模板字符串 — 产生SSTI漏洞
    html = f'''
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
</head>
<body>
<nav>
    <a href="/">首页</a>
    <a href="/welcome">欢迎页</a>
    <a href="/feedback">反馈</a>
</nav>
<h1>欢迎你，{name}！</h1>
</body>
</html>
'''
    return render_template_string(html)


# 2. 新增 /feedback 支持GET、POST
@app.route('/feedback', methods=["GET", "POST"])
def feedback():
    if request.method == "GET":
        form_html = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
</head>
<body>
<nav>
    <a href="/">首页</a>
    <a href="/welcome">欢迎页</a>
    <a href="/feedback">反馈</a>
</nav>
<form method="POST">
    姓名：<input name="name"><br>
    留言：<textarea name="message"></textarea><br>
    <button type="submit">提交</button>
</form>
</body>
</html>
'''
        return render_template_string(form_html)
    else:
        # ⚠️ POST接收反馈数据，直接拼接用户输入 — 产生SSTI漏洞
        name = request.form.get("name", "")
        message = request.form.get("message", "")
        res_html = f'''
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
</head>
<body>
<nav>
    <a href="/">首页</a>
    <a href="/welcome">欢迎页</a>
    <a href="/feedback">反馈</a>
</nav>
<h2>{name} 的反馈：</h2>
<p>{message}</p>
</body>
</html>
'''
        return render_template_string(res_html)
```

### 2.2 templates/base.html 导航栏修改片段

```html
<nav>
    <a href="/">首页</a>
    <a href="/welcome">欢迎页</a>
    <a href="/feedback">反馈</a>
</nav>
```

---

## 三、漏洞分析：SSTI 服务端模板注入（Server-Side Template Injection）

### 3.1 漏洞编号与分类

| 项目 | 内容 |
|------|------|
| 漏洞类型 | SSTI（服务端模板注入） |
| CWE 编号 | CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine |
| OWASP Top 10 | A03:2021 – Injection（注入攻击） |
| 影响引擎 | Jinja2 (Python Flask) |
| 危险等级 | **高危**（CVSS 3.x: 9.8） |

### 3.2 漏洞成因

**核心危险代码特征：**
使用 Python **f-string** 将用户可控输入**直接拼接进模板源代码**，再交给 `render_template_string()` 渲染。

```
用户输入 → f-string 拼接 → 模板源代码 → Jinja2编译执行
```

**执行流程演示：**

1. 用户传入 Payload：`name={{7*7}}`
2. f-string 拼接生成模板源码：
   ```
   <h1>欢迎你，{{7*7}}！</h1>
   ```
3. `render_template_string` 将字符串作为 Jinja2 模板编译执行
4. Jinja2 识别 `{{ }}` 标记，执行内部 Python 表达式 `7*7`
5. 最终输出：`<h1>欢迎你，49！</h1>`

**⚠️ 关键区分（面试常考）：**

| 写法 | 是否安全 | 说明 |
|------|---------|------|
| `render_template_string(f"内容{user_input}")` | ❌ **危险** | 用户输入参与模板源码构造，产生 SSTI |
| `render_template_string("内容{{name}}", name=user_input)` | ✅ **安全** | 用户输入仅作为模板变量传入，有自动转义 |

### 3.3 漏洞触发位置

| 路由 | 方法 | 可控参数 | 漏洞行 |
|------|------|---------|--------|
| `/welcome` | GET | `name`（URL查询参数） | `f"<h1>欢迎你，{name}！</h1>"` |
| `/feedback` | POST | `name`, `message`（表单参数） | `f"<h2>{name} 的反馈：</h2><p>{message}</p>"` |

### 3.4 漏洞复现 Payload

#### 3.4.1 基础检测 — 数学表达式验证

> **请求：**
> ```
> GET /welcome?name={{7*7}}
> ```
>
> **响应：** `<h1>欢迎你，49！</h1>`
>
> **结论：** `7*7=49` 被服务端 Jinja2 引擎成功执行，**确认存在 SSTI 漏洞**。

#### 3.4.2 信息收集 Payload

> **检测 Flask 配置泄露：**
> ```
> GET /welcome?name={{config}}
> ```
> 可泄露 `SECRET_KEY`、数据库配置等敏感信息。

> **检测 Python 运行环境：**
> ```
> GET /welcome?name={{''.__class__.__mro__[1].__subclasses__()|length}}
> ```
> 返回子类数量，判断 Python 版本和可利用 Gadget 数量。

#### 3.4.3 高危利用 — 远程命令执行（RCE）

> **执行系统命令 `whoami`：**
> ```
> GET /welcome?name={{''.__class__.__mro__[1].__subclasses__()[138].__init__.__globals__['popen']('whoami').read()}}
> ```
>
> **读取服务器文件 `/etc/passwd`：**
> ```
> GET /welcome?name={{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read()}}
> ```
>
> **写入 Webshell（完全控制服务器）：**
> ```
> GET /welcome?name={{lipsum.__globals__['os'].popen('echo "<?php system($_GET[\\'cmd\\']); ?>" > /var/www/html/shell.php').read()}}
> ```

#### 3.4.4 Feedback 路由同样存在漏洞

```
POST /feedback
Body: name={{cycler.__init__.__globals__.os.popen('id').read()}}&message={{config}}
```

### 3.5 漏洞危害

| 危害类型 | 说明 |
|---------|------|
| 🚨 **远程命令执行** | 在服务器上执行任意系统命令 |
| 🔓 **数据泄露** | 读取 SECRET_KEY、数据库密码、源代码等敏感文件 |
| 🕸️ **内网渗透** | 以服务器为跳板攻击内网其他服务 |
| 🔐 **权限提升** | 获取服务器控制权，植入后门 |
| 💣 **拒绝服务** | 执行消耗性操作导致服务不可用 |

---

## 四、漏洞修复代码（安全版本）

### 4.1 修复原理

**核心思路：模板固定，变量通过参数传递。**

```
❌ 危险：render_template_string(f"模板{用户输入}")
✅ 安全：render_template_string("模板{{变量}}", 变量=用户输入)
```

修复后的代码中，即使攻击者传入 `{{7*7}}`，Jinja2 也会将其自动 HTML 转义为 `&lbrace;&lbrace;7*7&rbrace;&rbrace;`，不会被执行。

### 4.2 修复代码

```python
from flask import Flask, request, render_template_string, render_template

app = Flask(__name__)
# ==========原有业务代码保持不变==========

@app.route('/welcome', methods=["GET"])
def welcome():
    name = request.args.get("name", "")
    if not name:
        name = "亲爱的用户"
    # ✅ 修复：模板字符串固定，不再 f-string 拼接用户输入
    #    用户数据通过 render_template_string 的变量参数传入
    html = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
</head>
<body>
<nav>
    <a href="/">首页</a>
    <a href="/welcome">欢迎页</a>
    <a href="/feedback">反馈</a>
</nav>
<h1>欢迎你，{{ name }}！</h1>
</body>
</html>
'''
    return render_template_string(html, name=name)


@app.route('/feedback', methods=["GET", "POST"])
def feedback():
    if request.method == "GET":
        form_html = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
</head>
<body>
<nav>
    <a href="/">首页</a>
    <a href="/welcome">欢迎页</a>
    <a href="/feedback">反馈</a>
</nav>
<form method="POST">
    姓名：<input name="name"><br>
    留言：<textarea name="message"></textarea><br>
    <button type="submit">提交</button>
</form>
</body>
</html>
'''
        return render_template_string(form_html)
    else:
        name = request.form.get("name", "")
        message = request.form.get("message", "")
        # ✅ 修复：模板固定，数据通过参数传入
        res_html = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
</head>
<body>
<nav>
    <a href="/">首页</a>
    <a href="/welcome">欢迎页</a>
    <a href="/feedback">反馈</a>
</nav>
<h2>{{ name }} 的反馈：</h2>
<p>{{ message }}</p>
</body>
</html>
'''
        return render_template_string(res_html, name=name, message=message)


if __name__ == '__main__':
    app.run(debug=False)  # ✅ 安全：生产环境关闭 debug 模式
```

### 4.3 修复前后对比

| 方面 | 漏洞版本 | 修复版本 |
|------|---------|---------|
| **模板构造方式** | `f"<h1>{name}</h1>"` | `"<h1>{{ name }}</h1>"` |
| **数据传递** | f-string 直接拼接 | `render_template_string(..., name=name)` |
| **用户输入处理** | 无转义，参与模板源码构造 | Jinja2 自动 HTML 转义 |
| **`{{7*7}}` 效果** | 执行 → 输出 49 | 转义 → 输出 `{{7*7}}` |
| **Jinja2 `|safe` 过滤器** | 不需要 | 如需要原样输出才使用（不推荐） |

---

## 五、安全开发总结

### 5.1 漏洞本质

| 项目 | 内容 |
|------|------|
| 漏洞名称 | SSTI（服务端模板注入，Server-Side Template Injection） |
| 根本诱因 | 可控外部数据 **直接拼接构造模板源代码** |
| 影响框架 | Flask + Jinja2（同理适用于任何模板引擎） |

### 5.2 标准防御方案

1. **模板与数据分离**（首要措施）
   - 模板文本预先固定，外部变量通过模板参数传入
   - 杜绝 `render_template_string(f"模板{用户输入}")` 这类写法

2. **输入验证**（辅助措施）
   - 对用户输入做长度、格式、类型校验
   - 例如姓名仅允许中文字符和字母，限制 20 字以内

3. **最小权限原则**
   - 生产环境关闭 `debug=True`
   - 使用非 root 用户运行 Web 服务
   - 限制应用可访问的文件系统范围

4. **模板沙箱**
   - Jinja2 的 `SandboxedEnvironment` 可限制模板中可访问的 Python 内置函数
   - 但沙箱不是万能的，已有多个绕过案例

### 5.3 无效防御提醒

以下防御措施**无法有效阻止** SSTI（容易被绕过）：

| 无效措施 | 绕过方式 |
|---------|---------|
| 前端 JavaScript 过滤 `{{ }}` | 攻击者直接发送 HTTP 请求，不经过浏览器 |
| 简单替换 `{{` 为空 | 可使用 `{%` 标签绕过，或 URL 编码 |
| 仅限制 `__class__` | 可使用 `|attr()` 过滤器、拼接 `__cla'~'ss__` 绕过 |

### 5.4 安全开发 Checklist

- [ ] 是否使用 `render_template_string(f"...{user_input}...")` 危险写法？
- [ ] 所有用户输入是否仅通过模板变量传递？
- [ ] 生产环境 `debug=False`？
- [ ] CSRF Token 是否启用？
- [ ] 是否做过完整的渗透测试？

### 5.5 修复验证

修复后，以下测试应全部通过（使用 `pytest` 或 Flask `test_client`）：

```python
def test_ssti_fixed():
    client = app.test_client()
    
    # 正常功能正常
    r = client.get('/welcome?name=张三')
    assert b'欢迎你，张三' in r.data
    
    # SSTI 注入被转义（不执行）
    r = client.get('/welcome?name=%7B%7B7*7%7D%7D')  # {{7*7}}
    assert b'49' not in r.data  # 7*7 不应该被执行
    assert b'{{7*7}}' in r.data or b'&lbrace;' in r.data  # 被转义
    
    # /feedback POST SSTI 同样被防御
    r = client.post('/feedback', data={
        'name': '{{7*7}}', 'message': '{{config}}', 'csrf_token': token
    })
    assert b'49' not in r.data
    assert b'测试用户' in client.post('/feedback', data={
        'name': '测试用户', 'message': '您好', 'csrf_token': token
    }).data
```

---

## 六、参考资料

| 资源 | 链接 |
|------|------|
| OWASP SSTI | https://owasp.org/www-community/attacks/Server_Side_Template_Injection |
| PortSwigger SSTI Cheat Sheet | https://portswigger.net/web-security/server-side-template-injection |
| Jinja2 文档 | https://jinja.palletsprojects.com/ |
| CWE-1336 | https://cwe.mitre.org/data/definitions/1336.html |
| Flask render_template_string | https://flask.palletsprojects.com/api/#flask.render_template_string |

---

> **报告日期：** 2026年7月25日
> **修复人员：** [你的学号/姓名]
> **应用名称：** Flask 用户管理系统
> **漏洞版本：** 新增 `/welcome` 和 `/feedback` 路由后的版本
> **修复版本：** 采用模板变量传参方式后的版本
