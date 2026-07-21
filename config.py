"""
config.py - 安全配置模块
从环境变量加载敏感配置，提供默认值用于开发环境
"""
import os


class Config:
    """应用安全配置"""

    # Secret key：优先从环境变量读取，开发环境使用生成的值
    SECRET_KEY = os.environ.get(
        "SECRET_KEY",
        "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6A7B8C9D0"
    )

    # Session 安全配置
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("ENABLE_HTTPS", "false").lower() == "true"
    SESSION_PERMANENT = True
    PERMANENT_SESSION_LIFETIME = 1800  # 30 分钟

    # 密码哈希轮数（越大越安全，但也越慢）
    BCRYPT_ROUNDS = 12

    # 登录限制
    LOGIN_MAX_ATTEMPTS = 5          # 最大尝试次数
    LOGIN_LOCKOUT_MINUTES = 15      # 锁定时间（分钟）

    # 最大上传文件大小
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB

    # 允许上传的文件扩展名（仅图片类型，防止上传恶意脚本）
    UPLOAD_ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "bmp"}

    # 上传目录（相对于项目根目录 static/uploads/）
    UPLOAD_FOLDER = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "static", "uploads"
    )

    # 调试模式：生产环境必须设为 False
    DEBUG = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

    # 允许的主机
    ALLOWED_HOSTS = os.environ.get("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
