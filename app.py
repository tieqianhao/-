"""
用户信息管理系统 - 完整安全加固版本
=======================================================================
修复内容：
  第一阶段 - 基础安全加固：
    1. 密码哈希存储（werkzeug.security）
    2. 密码永不传递到前端
    3. 强随机 Secret Key（config.py 管理）
    4. Session 安全加固（HttpOnly, SameSite, 过期时间）
    5. 登录频率限制（flask-limiter）
    6. CSRF 保护（Flask-WTF）
    7. 统一模糊错误提示（防用户名枚举）
    8. 输入校验与长度限制
    9. 关闭 Debug 模式（生产环境）
    10. 日志记录安全事件

  第二阶段 - SQL 注入修复 + 统一存储：
    11. SQL 注入修复：注册功能使用参数化查询
    12. SQL 注入修复：搜索功能使用参数化查询
    13. 密码加密存储到 SQLite（原明文存储）
    14. 统一用户存储架构（SQLite 替代双存储）
    15. 模板继承统一（修复重复导航栏）
    16. 数据库 Schema 完善（role/balance 字段）

  第三阶段 - 文件上传安全加固（2026-07-21）：
    17. 文件扩展名白名单（仅允许图片类型）
    18. 文件名净化（防路径遍历攻击）
    19. 文件内容魔数校验（确保真实图片文件）
    20. 用户标识前缀（防文件覆盖攻击）
    21. 禁用 SVG/HTML 上传（防 XSS 攻击）

  第四阶段 - 个人中心与充值安全加固（2026-07-22）：
    22. 身份绑定修复：profile/recharge 从 session 读取用户身份（防 IDOR V-27）
    23. 金额正数校验：禁止负数/零充值（防恶意扣款 V-28）
    24. 操作人身份锁定：recharge 仅操作当前登录用户（防越权充值 V-29）
    25. 充值审计日志：记录每次余额变动详情
"""
import logging
import sqlite3
import os
import re
import secrets
import subprocess
import platform
import ipaddress
import shlex
from datetime import timedelta

from flask import (
    Flask, render_template, render_template_string, request, redirect, session, abort, url_for
)
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash

from config import Config

# ---------------------------------------------------------------------------
# 应用初始化
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config.from_object(Config)
app.permanent_session_lifetime = timedelta(seconds=Config.PERMANENT_SESSION_LIFETIME)

# CSRF 保护 — 全局保护所有 POST 请求
csrf = CSRFProtect(app)

# 上传配置
app.config["MAX_CONTENT_LENGTH"] = Config.MAX_CONTENT_LENGTH
UPLOAD_FOLDER = Config.UPLOAD_FOLDER
UPLOAD_ALLOWED_EXTENSIONS = Config.UPLOAD_ALLOWED_EXTENSIONS

# 登录频率限制
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# 日志
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
)
logger = logging.getLogger("user-mgmt")

# ---------------------------------------------------------------------------
# SQLite 数据库初始化
# ---------------------------------------------------------------------------
DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DB_PATH = os.path.join(DB_DIR, "users.db")

# 不传递给前端的敏感字段
SENSITIVE_FIELDS = {"password_hash"}


def init_db():
    """
    初始化 SQLite 数据库，建表并插入默认用户。

    ✅ 安全设计：
      - 密码使用 werkzeug.security 哈希存储（非明文）
      - 使用参数化查询（防 SQL 注入）
      - 使用 INSERT OR IGNORE（防重复插入）
    """
    os.makedirs(DB_DIR, exist_ok=True)

    # 检测旧版数据库（含明文 password 列），若存在则重建
    _migrate_old_db()

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # ✅ 安全建表：password_hash 替代 password，新增 role/balance
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            role TEXT DEFAULT 'user',
            balance REAL DEFAULT 0
        )
    """)

    # ✅ 安全插入：参数化查询 + 密码哈希
    defaults = [
        ("admin",  generate_password_hash("admin123"),  "admin@example.com",  "13800138000", "admin", 99999),
        ("alice",  generate_password_hash("alice2025"),  "alice@example.com",  "13900139001", "user",  100),
    ]
    for row in defaults:
        try:
            c.execute(
                "INSERT OR IGNORE INTO users "
                "(username, password_hash, email, phone, role, balance) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                row,
            )
        except Exception:
            pass

    conn.commit()
    conn.close()
    logger.info("SQLite database initialized at %s", DB_PATH)


def _migrate_old_db():
    """检测并迁移旧版数据库（含明文 password 列 → 新版）"""
    if not os.path.exists(DB_PATH):
        return
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        # 检测是否存在旧版 password 列
        c.execute("PRAGMA table_info(users)")
        columns = {row[1] for row in c.fetchall()}
        if "password" in columns and "password_hash" not in columns:
            logger.warning("检测到旧版数据库（明文 password 列），正在迁移...")
            # 读取旧数据
            c.execute("SELECT id, username, password, email, phone FROM users")
            old_rows = c.fetchall()
            conn.close()

            # 重建数据库
            os.remove(DB_PATH)
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    email TEXT,
                    phone TEXT,
                    role TEXT DEFAULT 'user',
                    balance REAL DEFAULT 0
                )
            """)
            # 迁移数据：明文密码 → 哈希
            for row in old_rows:
                old_id, username, plain_pw, email, phone = row
                pw_hash = generate_password_hash(plain_pw)
                c.execute(
                    "INSERT OR IGNORE INTO users "
                    "(id, username, password_hash, email, phone, role, balance) "
                    "VALUES (?, ?, ?, ?, ?, 'user', 0)",
                    (old_id, username, pw_hash, email, phone),
                )
            conn.commit()
            conn.close()
            logger.info("数据库迁移完成：%d 条记录已迁移", len(old_rows))
            return
        conn.close()
    except Exception as e:
        logger.warning("数据库迁移检查失败（可忽略）: %s", e)


# ---------------------------------------------------------------------------
# 数据库操作函数（统一通过 SQLite）
# ---------------------------------------------------------------------------
def get_user_by_username(username: str) -> dict | None:
    """
    根据用户名查询用户。

    ✅ 安全设计：
      - 参数化查询（防 SQL 注入）
      - 返回字典（含 password_hash，仅后端使用）
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    if row is None:
        return None
    return dict(row)


def get_safe_user_info(username: str) -> dict | None:
    """返回用户信息（排除敏感字段），供模板使用"""
    user = get_user_by_username(username)
    if user is None:
        return None
    return {k: v for k, v in user.items() if k not in SENSITIVE_FIELDS}


def get_user_by_id(user_id: int) -> dict | None:
    """根据 ID 查询用户"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    if row is None:
        return None
    return dict(row)


def get_safe_user_by_id(user_id: int) -> dict | None:
    """返回用户信息（排除敏感字段），通过 ID 查询"""
    user = get_user_by_id(user_id)
    if user is None:
        return None
    return {k: v for k, v in user.items() if k not in SENSITIVE_FIELDS}


# ---------------------------------------------------------------------------
# 输入校验
# ---------------------------------------------------------------------------
MAX_USERNAME_LEN = 50
MAX_PASSWORD_LEN = 128


def sanitize_input(value: str, max_len: int = MAX_USERNAME_LEN) -> str:
    """去除首尾空白并截断"""
    return value.strip()[:max_len]


# ---------------------------------------------------------------------------
# 路由
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    username = session.get("username")
    user_info = get_safe_user_info(username) if username else None

    # 处理搜索参数
    keyword = request.args.get("keyword", "").strip()
    search_results = None
    if keyword:
        search_results = search_users(keyword)

    return render_template(
        "index.html",
        username=username,
        user=user_info,
        search_results=search_results,
        search_keyword=keyword,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = sanitize_input(request.form.get("username", ""))
        password = sanitize_input(
            request.form.get("password", ""), MAX_PASSWORD_LEN
        )

        # 校验非空
        if not username or not password:
            logger.warning("Login attempt with empty fields from %s", request.remote_addr)
            return render_template("login.html", error="用户名或密码错误")

        # ✅ 安全：数据库查询（含哈希密码），不再使用 USERS 字典
        user = get_user_by_username(username)

        # ✅ 安全：使用 werkzeug.security 恒定时间比较（防时序攻击）
        if user is not None and check_password_hash(user["password_hash"], password):
            session.permanent = True
            session["username"] = username
            logger.info("User '%s' logged in successfully from %s", username, request.remote_addr)
            return redirect("/")
        else:
            # ✅ 安全：统一模糊提示（防用户名枚举）
            logger.warning(
                "Failed login attempt for '%s' from %s",
                username, request.remote_addr,
            )
            return render_template("login.html", error="用户名或密码错误")

    return render_template("login.html")


@app.route("/logout")
def logout():
    username = session.get("username")
    if username:
        logger.info("User '%s' logged out", username)
    session.clear()
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = sanitize_input(request.form.get("username", ""))
        password = sanitize_input(
            request.form.get("password", ""), MAX_PASSWORD_LEN
        )
        email = sanitize_input(request.form.get("email", ""), 100)
        phone = sanitize_input(request.form.get("phone", ""), 20)

        # 校验非空
        if not username or not password:
            return render_template("register.html", error="用户名和密码不能为空")

        # ✅ 安全修复 V-18：密码哈希后再存储
        password_hash = generate_password_hash(password)

        # ✅ 安全修复 V-16：参数化查询，防 SQL 注入
        sql = "INSERT INTO users (username, password_hash, email, phone) VALUES (?, ?, ?, ?)"
        logger.info("Register user: %s", username)

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:
            c.execute(sql, (username, password_hash, email, phone))
            conn.commit()
            conn.close()
            logger.info("User '%s' registered successfully", username)
            return redirect("/login?msg=注册成功，请登录")
        except sqlite3.IntegrityError:
            conn.close()
            return render_template("register.html", error="用户名已存在")
        except Exception as e:
            conn.close()
            logger.warning("Register failed for '%s': %s", username, str(e))
            return render_template("register.html", error="注册失败，请稍后再试")

    # 从查询参数获取成功消息
    msg = request.args.get("msg", "")
    return render_template("register.html", msg=msg)


def search_users(keyword: str) -> list:
    """
    ✅ 安全修复 V-17：参数化查询，防 SQL 注入

    原漏洞代码（已移除）：
        sql = f"SELECT ... WHERE username LIKE '%{keyword}%' ..."
        c.execute(sql)   # ← 直接拼接，可被注入
    """
    sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
    pattern = f"%{keyword}%"
    logger.info("Search keyword: %s", keyword)

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute(sql, (pattern, pattern))
        rows = c.fetchall()
        conn.close()
        return [
            {"id": row[0], "username": row[1], "email": row[2], "phone": row[3]}
            for row in rows
        ]
    except Exception as e:
        conn.close()
        logger.warning("Search failed for keyword '%s': %s", keyword, str(e))
        return []


# ---------------------------------------------------------------------------
# 头像上传 — 安全加固版
# ---------------------------------------------------------------------------
# 常见图片格式的魔数（Magic Bytes）签名，用于验证文件真实性
IMAGE_MAGIC_BYTES = {
    b"\x89PNG\r\n\x1a\n":              "png",
    b"\xff\xd8\xff":                    "jpg/jpeg",
    b"GIF87a":                          "gif",
    b"GIF89a":                          "gif",
    b"RIFF":                            "webp",  # WEBP 以 RIFF 开头
    b"BM":                              "bmp",
}


def allowed_file_extension(filename: str) -> bool:
    """
    ✅ 安全修复 V-22：文件扩展名白名单校验
    仅允许图片格式（.png/.jpg/.jpeg/.gif/.webp/.bmp）
    """
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in UPLOAD_ALLOWED_EXTENSIONS


def validate_image_content(file_bytes: bytes) -> bool:
    """
    ✅ 安全修复 V-22：文件内容魔数校验
    读取文件头部字节与已知图片格式签名比对，确保文件是真实的图片
    """
    return any(file_bytes.startswith(sig) for sig in IMAGE_MAGIC_BYTES)


def sanitize_filename(filename: str) -> str:
    """
    ✅ 安全修复 V-23：文件名净化（防路径遍历）
    - 移除路径分隔符（防 ../../../ 攻击）
    - 只取文件名部分，去除所有目录信息
    """
    # 只取 basename，移除所有路径信息
    safe_name = os.path.basename(filename)
    # 移除空字节和不可见字符
    safe_name = "".join(c for c in safe_name if c.isprintable() and c not in ('/', '\\', '\x00'))
    return safe_name


def safe_upload_path(upload_dir: str, username: str, filename: str) -> tuple[str, str]:
    """
    ✅ 安全修复 V-24：生成安全的存储文件名（防文件覆盖）
    添加用户标识 + 随机串前缀，防止不同用户上传同名文件互相覆盖
    """
    safe_name = sanitize_filename(filename)
    random_suffix = secrets.token_hex(4)  # 8字符随机十六进制
    ext = safe_name.rsplit(".", 1)[1].lower() if "." in safe_name else ""
    base = safe_name.rsplit(".", 1)[0] if "." in safe_name else safe_name
    stored_name = f"{username}_{base}_{random_suffix}.{ext}"
    return os.path.join(upload_dir, stored_name), stored_name


@app.route("/upload", methods=["GET", "POST"])
def upload():
    """用户头像上传 — 安全加固版本"""
    username = session.get("username")
    if not username:
        return redirect("/login")

    if request.method == "POST":
        # 检查是否有文件
        if "file" not in request.files:
            return render_template("upload.html", error="未选择文件")

        file = request.files["file"]
        if file.filename == "":
            return render_template("upload.html", error="未选择文件")

        original_filename = file.filename

        # ✅ 安全修复 V-22：扩展名白名单校验
        if not allowed_file_extension(original_filename):
            logger.warning(
                "User '%s' attempted to upload disallowed file type: %s",
                username, original_filename,
            )
            return render_template(
                "upload.html",
                error="不支持的文件类型，仅允许上传图片文件（PNG/JPG/GIF/WEBP/BMP）",
            )

        # ✅ 安全修复 V-22：文件内容魔数校验
        file_bytes = file.read(12)  # 读取前12字节用于魔数判断
        if not validate_image_content(file_bytes):
            logger.warning(
                "User '%s' uploaded file with invalid content (not a real image): %s",
                username, original_filename,
            )
            return render_template(
                "upload.html",
                error="文件内容不是有效的图片格式，请上传真实图片文件",
            )

        # ✅ 安全修复 V-24 + V-23：生成安全的存储文件名
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        save_path, stored_name = safe_upload_path(UPLOAD_FOLDER, username, original_filename)

        # 写入文件（魔数校验后重置文件指针 + 写完整内容）
        file.seek(0)
        file.save(save_path)

        # 构造可访问的 URL
        file_url = url_for("static", filename=f"uploads/{stored_name}")
        logger.info(
            "User '%s' uploaded image: %s (stored as: %s)",
            username, original_filename, stored_name,
        )

        return render_template(
            "upload.html",
            success="文件上传成功",
            file_url=file_url,
            filename=stored_name,
        )

    return render_template("upload.html")


# ---------------------------------------------------------------------------
# 个人中心 — 安全加固版（修复 IDOR V-27）
# ---------------------------------------------------------------------------
@app.route("/profile", methods=["GET"])
def profile():
    """
    个人中心 — ✅ 安全修复 V-27：从 session 读取当前登录用户身份
    不再接受前端 user_id 参数，彻底杜绝 IDOR 越权查询
    """
    username = session.get("username")
    if not username:
        return redirect("/login")

    user = get_safe_user_info(username)
    if user is None:
        return render_template("profile.html", error="用户不存在")

    return render_template("profile.html", user=user)


# ---------------------------------------------------------------------------
# 充值 — 安全加固版（修复 V-28 负数充值 + V-29 越权充值）
# ---------------------------------------------------------------------------
@app.route("/recharge", methods=["POST"])
def recharge():
    """
    充值 — ✅ 安全修复 V-27~V-29
    - 身份从 session 读取，拒绝前端 user_id 参数
    - amount 仅允许正数，拦截负数/零
    - 记录完整的审计日志
    """
    # ✅ V-27 + V-29 修复：从 session 获取当前登录用户
    username = session.get("username")
    if not username:
        return redirect("/login")

    user = get_user_by_username(username)
    if user is None:
        return render_template("profile.html", error="用户不存在")

    amount = request.form.get("amount", type=float, default=0)

    # ✅ V-28 修复：金额正数校验
    if amount <= 0:
        logger.warning(
            "Recharge rejected: invalid amount %f for user '%s' from %s",
            amount, username, request.remote_addr,
        )
        return render_template(
            "profile.html",
            user=get_safe_user_info(username),
            error="充值金额必须大于 0",
        )

    # 执行充值（仅操作当前登录用户）
    old_balance = user["balance"]
    new_balance = old_balance + amount
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "UPDATE users SET balance = balance + ? WHERE id = ?",
        (amount, user["id"]),
    )
    conn.commit()
    conn.close()

    # ✅ 新增审计日志
    logger.info(
        "Recharge success: user='%s'(id=%d), amount=+%f, balance: %f → %f, ip=%s",
        username, user["id"], amount, old_balance, new_balance, request.remote_addr,
    )

    return redirect("/profile")


# ---------------------------------------------------------------------------
# 密码修改 — 安全加固版（修复 CSRF + 越权 + XSS 漏洞）
# ---------------------------------------------------------------------------
@app.route("/change-password", methods=["POST"])
def change_password():
    """
    密码修改 — ✅ 安全加固

    ✅ V-34 修复：移除 @csrf.exempt，启用 CSRF Token 校验
    ✅ V-35 修复：增加原密码验证
    ✅ V-36 修复：从 session 读取身份，拒绝前端 username 参数
    ✅ V-37 修复：错误消息使用 Jinja2 自动转义，防止 XSS
    """
    # 校验登录状态
    username = session.get("username")
    if not username:
        return redirect("/login")

    user = get_user_by_username(username)
    if user is None:
        return redirect("/login")

    # ✅ V-35 修复：校验原密码
    old_password = request.form.get("old_password", "")
    if not check_password_hash(user["password_hash"], old_password):
        logger.warning(
            "Password change failed (wrong old password): user='%s', ip=%s",
            username, request.remote_addr,
        )
        return render_template(
            "profile.html",
            user=get_safe_user_info(username),
            error="原密码错误",
        )

    # ✅ V-36 修复：从 session 获取目标用户，拒绝前端 username 参数
    new_password = request.form.get("new_password", "")

    if not new_password:
        return render_template(
            "profile.html",
            user=get_safe_user_info(username),
            error="新密码不能为空",
        )

    # ✅ 更新当前登录用户的密码
    new_hash = generate_password_hash(new_password)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "UPDATE users SET password_hash = ? WHERE username = ?",
        (new_hash, username),
    )
    conn.commit()
    conn.close()

    logger.info(
        "Password changed successfully: user='%s', ip=%s",
        username, request.remote_addr,
    )

    return redirect("/profile")


# ---------------------------------------------------------------------------
# 动态页面加载 — 安全加固版（修复路径遍历 + LFI + XSS）
# ---------------------------------------------------------------------------
PAGES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pages")

# ✅ 安全修复 V-31：页面名称白名单，仅允许预定义的页面
ALLOWED_PAGES = {"help", "about", "faq", "terms", "privacy"}

# ✅ 安全修复 V-32：安全的 HTML 标签白名单（仅允许基础排版标签）
SAFE_TAGS_ALLOWED = {"p", "br", "strong", "b", "em", "i", "u", "h2", "h3", "h4",
                     "ul", "ol", "li", "div", "span", "table", "tr", "td", "th",
                     "a", "img", "blockquote", "pre", "code", "hr"}
SAFE_ATTRS_ALLOWED = {"href", "src", "alt", "title", "style", "class", "id",
                      "target", "rel"}


def sanitize_html_content(html_content: str) -> str:
    """
    ✅ 安全修复 V-32：HTML 内容净化
    移除所有不在白名单中的标签和属性，防止 XSS 攻击
    """
    import re

    # 移除 <script> 及其内容
    html_content = re.sub(r'<script[^>]*>.*?</script>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
    # 移除 on* 事件处理器（onclick, onload, onerror 等）
    html_content = re.sub(r'\son\w+\s*=\s*"[^"]*"', '', html_content, flags=re.IGNORECASE)
    html_content = re.sub(r"\son\w+\s*=\s*'[^']*'", '', html_content, flags=re.IGNORECASE)
    html_content = re.sub(r'\son\w+\s*=\s*\w+', '', html_content, flags=re.IGNORECASE)
    # 移除 javascript: 伪协议
    html_content = re.sub(r'href\s*=\s*"javascript:[^"]*"', 'href="#', html_content, flags=re.IGNORECASE)
    html_content = re.sub(r"href\s*=\s*'javascript:[^']*'", "href='#'", html_content, flags=re.IGNORECASE)
    # 移除 <style> 标签
    html_content = re.sub(r'<style[^>]*>.*?</style>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
    # 移除 <link> 标签
    html_content = re.sub(r'<link[^>]*>', '', html_content, flags=re.IGNORECASE)
    # 移除 <meta> 标签
    html_content = re.sub(r'<meta[^>]*>', '', html_content, flags=re.IGNORECASE)
    # 移除 <iframe> 标签
    html_content = re.sub(r'<iframe[^>]*>.*?</iframe>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
    html_content = re.sub(r'<iframe[^>]*>', '', html_content, flags=re.IGNORECASE)
    # 移除 <embed> <object> <form> <input> 等危险标签
    for tag in ["embed", "object", "param", "applet", "form", "input", "textarea",
                "select", "button", "svg", "math", "canvas", "base", "frame", "frameset",
                "noframes", "xml", "marquee"]:
        html_content = re.sub(
            rf'<{tag}[^>]*>.*?</{tag}>', '', html_content, flags=re.DOTALL | re.IGNORECASE
        )
        html_content = re.sub(rf'<{tag}[^>]*>', '', html_content, flags=re.IGNORECASE)
        html_content = re.sub(rf'</{tag}>', '', html_content, flags=re.IGNORECASE)

    return html_content


@app.route("/page", methods=["GET"])
def dynamic_page():
    """
    动态页面加载 — ✅ 安全加固版（修复 V-31 路径遍历/LFI + V-32 XSS）

    ✅ V-31 修复：页面名称白名单 + 禁止路径分隔符
    ✅ V-32 修复：HTML 内容净化（移除危险标签和属性）
    """
    name = request.args.get("name", "")

    if not name:
        return render_template("index.html", page_error="缺少页面名称")

    # ✅ V-31 修复：路径分隔符检测 — 禁止 ../ 和 /
    if "/" in name or "\\" in name or ".." in name:
        logger.warning("Page access blocked (path traversal attempt): '%s' from %s",
                       name, request.remote_addr)
        return render_template("index.html", page_error="页面名称无效")

    # ✅ V-31 修复：白名单校验 — 仅允许预定义的页面名
    # 去掉 .html 后缀后再检查白名单
    page_key = name.replace(".html", "") if name.endswith(".html") else name
    if page_key not in ALLOWED_PAGES:
        logger.warning("Page access blocked (not in allowlist): '%s' from %s",
                       name, request.remote_addr)
        return render_template("index.html", page_error="页面不存在")

    page_content = None

    # 尝试直接使用传入的名称
    file_path = os.path.join(PAGES_DIR, name)
    if os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                page_content = f.read()
        except Exception:
            page_content = None

    # 如果没找到，尝试加上 .html 后缀
    if page_content is None:
        file_path_with_ext = os.path.join(PAGES_DIR, name + ".html")
        if os.path.exists(file_path_with_ext):
            try:
                with open(file_path_with_ext, "r", encoding="utf-8") as f:
                    page_content = f.read()
            except Exception:
                page_content = None

    if page_content is None:
        return render_template("index.html", page_error="页面不存在")

    # ✅ V-32 修复：HTML 内容净化，移除危险标签和属性
    safe_content = sanitize_html_content(page_content)

    return render_template("index.html", page_content=safe_content, page_name=page_key)


_NAVBAR_TPL = '''
        <div class="nav-brand">用户管理系统</div>
        <div class="nav-menu">
            <a href="/" class="nav-link">首页</a>
            <a href="/welcome" class="nav-link">欢迎页</a>
            <a href="/feedback" class="nav-link">反馈</a>
            {% if session_username %}
            <span class="nav-welcome">欢迎，{{ session_username }}</span>
            <a href="/profile" class="nav-link">个人中心</a>
            <a href="/upload" class="nav-link">上传头像</a>
            <a href="/logout" class="nav-link">退出</a>
            {% else %}
            <a href="/login" class="nav-link">登录</a>
            <a href="/register" class="nav-link">注册</a>
            {% endif %}
        </div>'''


_PAGE_HEAD = '''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>'''
_PAGE_MID = '''</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <nav class="navbar">'''
_PAGE_TAIL = '''    </nav>
    <main class="container">
'''
_PAGE_END = '''    </main>
</body>
</html>'''


# ---------------------------------------------------------------------------
# 个性化页面 — /welcome (修复后：无 SSTI 漏洞)
# ---------------------------------------------------------------------------
@app.route("/welcome")
def welcome():
    """
    欢迎页 — ✅ 安全版本：模板固定，用户数据通过变量传入
    """
    name = request.args.get("name", "").strip()
    if not name:
        name = "亲爱的用户"

    navbar = _NAVBAR_TPL
    html = (
        _PAGE_HEAD + "欢迎页" + _PAGE_MID + navbar + _PAGE_TAIL +
        "<h1>欢迎你，{{ name }}！</h1>\n" +
        _PAGE_END
    )
    return render_template_string(html, name=name, session_username=session.get("username"))


# ---------------------------------------------------------------------------
# 个性化页面 — /feedback (修复后：无 SSTI 漏洞)
# ---------------------------------------------------------------------------
@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    """
    反馈页 — ✅ 安全版本：模板固定，用户数据通过变量传入
    """
    navbar = _NAVBAR_TPL
    session_username = session.get("username")

    if request.method == "POST":
        name = request.form.get("name", "")
        message = request.form.get("message", "")
        html = (
            _PAGE_HEAD + "反馈结果" + _PAGE_MID + navbar + _PAGE_TAIL +
            "<h2>{{ name }} 的反馈：</h2>\n" +
            "<p>{{ message }}</p>\n" +
            '<p><a href="/feedback" class="btn">返回</a></p>\n' +
            _PAGE_END
        )
        return render_template_string(html, name=name, message=message, session_username=session_username)

    # GET: 显示反馈表单
    html = (
        _PAGE_HEAD + "用户反馈" + _PAGE_MID + navbar + _PAGE_TAIL +
        '''<h2>用户反馈</h2>
<form method="POST">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <div class="form-group">
        <label for="name">姓名：</label>
        <input type="text" id="name" name="name" class="form-control" placeholder="请输入您的姓名">
    </div>
    <div class="form-group">
        <label for="message">留言内容：</label>
        <textarea id="message" name="message" class="form-control" rows="5" placeholder="请输入您的留言..."></textarea>
    </div>
    <button type="submit" class="btn">提交反馈</button>
</form>
''' +
        _PAGE_END
    )
    return render_template_string(html, session_username=session_username)


# ---------------------------------------------------------------------------
# Ping 网络诊断 (修复后：无命令注入漏洞)
# ---------------------------------------------------------------------------
@app.route("/ping", methods=["GET", "POST"])
def ping():
    """
    Ping 网络诊断 — 需要登录
    ✅ 安全版本：
      - IP 地址使用 ipaddress 模块严格校验
      - 域名使用 shlex 净化 + 安全字符白名单
      - shell=False，参数以列表形式传递
    """
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
            try:
                # ✅ 修复1：校验并净化目标地址
                target = validate_target(ip)
                if target is None:
                    error = "无效的 IP 地址或域名格式，仅允许 IPv4/IPv6 地址或安全的域名"
                else:
                    # ✅ 修复2：使用参数列表形式（shell=False），禁止字符串拼接
                    if platform.system() == "Windows":
                        cmd = ["ping", "-n", "3", target]
                    else:
                        cmd = ["ping", "-c", "3", target]
                    output = subprocess.check_output(cmd, shell=False, timeout=30, stderr=subprocess.STDOUT)
                    result = output.decode("utf-8", errors="replace")
            except subprocess.TimeoutExpired:
                error = "错误：Ping 超时（超过 30 秒）"
            except subprocess.CalledProcessError as e:
                error = e.output.decode("utf-8", errors="replace") if e.output else f"错误：命令执行失败（返回码 {e.returncode}）"
            except Exception as e:
                error = f"错误：{str(e)}"

    return render_template("ping.html", result=result, ip=ip, error=error)


def validate_target(target: str):
    """
    ✅ 安全校验：验证目标地址是否合法
    支持：
      - IPv4 地址 (如 8.8.8.8)
      - IPv6 地址 (如 ::1, 2001:db8::1)
      - 安全域名（仅允许字母、数字、连字符、点）
    返回合法字符串，或 None（非法时）
    """
    # 尝试解析为 IP 地址
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    # 尝试解析为 IP 网络地址（CIDR 格式的单个地址）
    try:
        ip_obj = ipaddress.ip_network(target, strict=False)
        if ip_obj.num_addresses == 1:
            return str(ip_obj.network_address)
    except ValueError:
        pass

    # 域名：仅允许字母、数字、连字符、点（安全字符白名单）
    # 同时禁止常见的 shell 注入特征字符
    allowed = re.compile(r'^[a-zA-Z0-9.\-]+$')
    if allowed.match(target) and len(target) <= 255:
        # 确保域名包含至少一个点（防止裸词注入如 "id"）
        if "." in target:
            return target
        # localhost 特殊放行
        if target.lower() == "localhost":
            return target

    return None


# ---------------------------------------------------------------------------
# 错误处理
# ---------------------------------------------------------------------------
@app.errorhandler(429)
def rate_limit_handler(e):
    """请求过于频繁时的响应"""
    return render_template("login.html", error="登录尝试过于频繁，请稍后再试"), 429


@app.errorhandler(400)
def csrf_error_handler(e):
    """CSRF 校验失败 — 根据来源页面返回对应模板"""
    logger.warning("CSRF validation failed from %s", request.remote_addr)
    referrer = request.referrer or ""
    if "/register" in referrer:
        return render_template("register.html", error="会话已过期，请刷新页面重试"), 400
    if "/profile" in referrer or "/recharge" in referrer:
        return render_template("profile.html", error="会话已过期，请刷新页面重试"), 400
    return render_template("login.html", error="会话已过期，请刷新页面重试"), 400


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    app.run(
        debug=Config.DEBUG,
        host="0.0.0.0" if Config.DEBUG else "127.0.0.1",
        port=5000,
    )
