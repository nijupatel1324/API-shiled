"""Fake data for the training test API.

Everything here is synthetic. No real users, credentials or secrets.

Test accounts (training environment only):
    admin  / admin123
    user   / user123
    guest  / guest123
"""

SEED_USERNAMES = {"admin", "user", "guest", "alice", "bob"}

USERS = [
    {
        "id": 1,
        "username": "admin",
        "password": "admin123",
        "role": "admin",
        "email": "admin@example.test",
        "phone": "+1-555-0100",
        "api_key": "sk_live_admin_00000000000000000000000001",
        "password_hash": "pbkdf2:sha256:150000$fakehashadmin1$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    },
    {
        "id": 2,
        "username": "user",
        "password": "user123",
        "role": "user",
        "email": "user@example.test",
        "phone": "+1-555-0101",
        "api_key": "sk_live_user_0000000000000000000000000002",
        "password_hash": "pbkdf2:sha256:150000$fakehashuser000$bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    },
    {
        "id": 3,
        "username": "guest",
        "password": "guest123",
        "role": "guest",
        "email": "guest@example.test",
        "phone": "+1-555-0102",
        "api_key": "sk_live_guest_000000000000000000000000003",
        "password_hash": "pbkdf2:sha256:150000$fakehashguest00$cccccccccccccccccccccccccccccccc",
    },
    {
        "id": 4,
        "username": "alice",
        "password": "alice123",
        "role": "user",
        "email": "alice@example.test",
        "phone": "+1-555-1010",
        "api_key": "sk_live_alice_0000000000000000000000000004",
        "password_hash": "pbkdf2:sha256:150000$fakehashalice00$dddddddddddddddddddddddddddddddd",
    },
    {
        "id": 5,
        "username": "bob",
        "password": "bob123",
        "role": "user",
        "email": "bob@example.test",
        "phone": "+1-555-2020",
        "api_key": "sk_live_bob_00000000000000000000000000005",
        "password_hash": "pbkdf2:sha256:150000$fakehashbob0000$eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    },
]

PRODUCTS = [
    {"id": 1, "name": "Wireless Mouse", "category": "electronics", "price": 19.99},
    {"id": 2, "name": "Mechanical Keyboard", "category": "electronics", "price": 89.99},
    {"id": 3, "name": "USB-C Hub", "category": "accessories", "price": 39.99},
    {"id": 4, "name": "27in Monitor", "category": "electronics", "price": 249.0},
    {"id": 5, "name": "Laptop Stand", "category": "accessories", "price": 29.5},
]

ORDERS = [
    {"id": 1, "user_id": 2, "product_id": 1, "qty": 2, "total": 39.98},
    {"id": 2, "user_id": 4, "product_id": 3, "qty": 1, "total": 39.99},
    {"id": 3, "user_id": 2, "product_id": 5, "qty": 1, "total": 29.50},
]

ADMIN_NOTES = [
    {"id": 1, "service": "user_service", "internal_host": "10.1.2.3", "debug": True},
    {"id": 2, "service": "payment_gateway", "internal_host": "10.1.2.4", "debug": True},
]

INTERNAL_CONFIG = {
    "app_name": "test_api",
    "environment": "development",
    "debug": True,
    "db_host": "127.0.0.1",
    "db_name": "test_api.db",
    "db_user": "test_api_user",
    "internal_api": "http://10.1.2.5:8080/internal",
    "version": "0.1.0",
}


def public_user(u):
    """Return a safe copy of a user record (still intentionally leaky)."""
    return {k: v for k, v in u.items() if k not in ("password",)}


def find_user_by_username(username):
    for u in USERS:
        if u["username"] == username:
            return u
    return None


def find_user_by_id(uid):
    for u in USERS:
        if u["id"] == uid:
            return u
    return None