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
"""
import logging
import sqlite3
import os
import secrets
from datetime import timedelta

from flask import (
    Flask, render_template, request, redirect, session, abort, url_for
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
