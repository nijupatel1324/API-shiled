import os

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'api_shield.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"connect_args": {"timeout": 30}}

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true"

    MAX_SCAN_DURATION = int(os.environ.get("MAX_SCAN_DURATION", "600"))
    MAX_ENDPOINTS_PER_SCAN = int(os.environ.get("MAX_ENDPOINTS_PER_SCAN", "50"))
    MAX_CONCURRENT_SCANS = int(os.environ.get("MAX_CONCURRENT_SCANS", "3"))
    DEFAULT_RATE_LIMIT_TEST_REQUESTS = int(
        os.environ.get("DEFAULT_RATE_LIMIT_TEST_REQUESTS", "25")
    )
    REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", "15"))
    MAX_PAYLOAD_SIZE = int(os.environ.get("MAX_PAYLOAD_SIZE", str(1024 * 1024)))

    ALLOWED_TARGET_HOSTS = os.environ.get(
        "ALLOWED_TARGET_HOSTS",
        "127.0.0.1, localhost, ::1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12",
    )

    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
    LOG_FILE = os.path.join(BASE_DIR, "logs", "api_shield.log")

    REPORT_OUTPUT_DIR = os.path.join(BASE_DIR, "reports", "output")

    OWASP_API_TOP_10 = {
        "API1": "Broken Object Level Authorization",
        "API2": "Broken Authentication",
        "API3": "Broken Object Property Level Authorization",
        "API4": "Unrestricted Resource Consumption",
        "API5": "Broken Function Level Authorization",
        "API6": "Unrestricted Access to Sensitive Business Flows",
        "API7": "Server Side Request Forgery",
        "API8": "Security Misconfiguration",
        "API9": "Improper Inventory Management",
        "API10": "Unsafe Consumption of APIs",
    }