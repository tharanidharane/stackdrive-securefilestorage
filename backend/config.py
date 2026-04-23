import os
import platform

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

def get_db_path():
    # Priority 1: Environment variable override
    env_db = os.environ.get('DATABASE_URL')
    if env_db:
        return env_db
    
    # Priority 2: Detect WSL and use Linux home directory for performance
    # Check for WSL environment variables or platform indicators
    is_wsl = 'wsl' in platform.release().lower() or os.environ.get('WSL_DISTRO_NAME')
    
    if is_wsl:
        # We target the user's home directory in Ubuntu specifically for ext4 performance
        linux_home = os.environ.get('HOME', '/home/tharani')
        # SQLite URI requires 3 slashes for absolute path: sqlite:////path
        # os.path.join will lead to /home/tharani/stackdrive.db
        # So we prepend sqlite:/// to the absolute path
        return f"sqlite:///{os.path.join(linux_home, 'stackdrive.db')}"
    
    # Priority 3: Default to BASE_DIR (Windows or standard Linux)
    return f"sqlite:///{os.path.join(BASE_DIR, 'stackdrive.db')}"

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'stackdrive-secret-key-change-in-production')
    SQLALCHEMY_DATABASE_URI = get_db_path()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'jwt-super-secret-key-2026')
    JWT_ACCESS_TOKEN_EXPIRES = 86400  # 24 hours in seconds
    JWT_TOKEN_LOCATION = ['headers', 'query_string']
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'storage', 'quarantine')
    SECURE_FOLDER = os.path.join(BASE_DIR, 'storage', 'secure')
    MAX_CONTENT_LENGTH = 500 * 1024 * 1024  # 500MB
    ALLOWED_EXTENSIONS = {'zip'}

