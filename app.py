import os
import time
import uuid
import hmac
import hashlib
from functools import wraps

import jwt
import pymysql

from flask import (
    Flask,
    request,
    jsonify,
    g,
    make_response
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

app = Flask(__name__, static_folder="static")

app.config["MAX_CONTENT_LENGTH"] = 32 * 1024

JWT_SECRET = os.environ["JWT_SECRET"]
CSRF_SECRET = os.environ["CSRF_SECRET"]
PUBLIC_ORIGIN = os.environ["PUBLIC_ORIGIN"]

COOKIE_NAME = "__Host-access_token"
TOKEN_LIFETIME = 900
NONCE_LIFETIME = 120

SLOT = os.getenv("SLOT", "unknown")
BUILD_VERSION = os.getenv("BUILD_VERSION", "local")


# ==========================================
# 1. Database Connection
# ==========================================

def connect_db():
    return pymysql.connect(
        host=os.environ["DB_HOST"],
        port=3306,
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        database=os.environ["DB_NAME"],
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
        connect_timeout=5,
        read_timeout=5,
        write_timeout=5
    )


def get_db():
    if "db" not in g:
        g.db = connect_db()

    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)

    if db is not None:
        db.close()


# ==========================================
# 2. Database Initialization
# ==========================================

def init_db():

    for attempt in range(30):

        try:
            connection = connect_db()
            break

        except pymysql.MySQLError:
            print(
                f"Waiting for DB: {attempt + 1}/30",
                flush=True
            )
            time.sleep(2)

    else:
        raise RuntimeError("Database connection failed")

    try:
        with connection.cursor() as cursor:

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(100) NOT NULL UNIQUE,
                    password_hash VARCHAR(255) NOT NULL,
                    full_name VARCHAR(100) NOT NULL,
                    github_id VARCHAR(100) NOT NULL
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS memos (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    title VARCHAR(200) NOT NULL,
                    content TEXT NOT NULL,
                    created_at TIMESTAMP
                        DEFAULT CURRENT_TIMESTAMP,

                    FOREIGN KEY (user_id)
                        REFERENCES users(id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS used_nonces (
                    nonce_id VARCHAR(36) PRIMARY KEY,
                    expires_at BIGINT NOT NULL,

                    INDEX idx_expires_at (expires_at)
                )
            """)

            password_hash = generate_password_hash(
                os.environ["TEST_PASSWORD"]
            )

            cursor.execute("""
                INSERT INTO users (
                    username,
                    password_hash,
                    full_name,
                    github_id
                )
                VALUES (%s, %s, %s, %s)

                ON DUPLICATE KEY UPDATE
                    full_name = VALUES(full_name),
                    github_id = VALUES(github_id)
            """, (
                os.environ["TEST_USERNAME"],
                password_hash,
                os.environ["CANDIDATE_NAME"],
                os.environ["CANDIDATE_GITHUB"]
            ))

        print("Database initialization complete", flush=True)

    finally:
        connection.close()


# ==========================================
# 3. JWT Authentication
# ==========================================

def create_access_token(user_id):

    now = int(time.time())

    payload = {
        "sub": str(user_id),
        "jti": str(uuid.uuid4()),
        "iss": "secure-memo",
        "aud": "memo-access",
        "iat": now,
        "exp": now + TOKEN_LIFETIME
    }

    return jwt.encode(
        payload,
        JWT_SECRET,
        algorithm="HS256"
    )


def auth_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        token = request.cookies.get(COOKIE_NAME)

        if not token:
            return jsonify(
                error="Authentication required"
            ), 401

        try:

            g.claims = jwt.decode(
                token,
                JWT_SECRET,
                algorithms=["HS256"],
                issuer="secure-memo",
                audience="memo-access",
                options={
                    "require": [
                        "sub", "jti", "iat", "exp"
                    ]
                }
            )

            g.user_id = int(g.claims["sub"])

        except (jwt.InvalidTokenError, ValueError):

            return jsonify(
                error="Invalid or expired token"
            ), 401

        return function(*args, **kwargs)

    return wrapper


# ==========================================
# 4. CSRF Protection
# ==========================================

def create_csrf_token(session_id):

    return hmac.new(
        CSRF_SECRET.encode(),
        session_id.encode(),
        hashlib.sha256
    ).hexdigest()


def valid_origin():

    return request.headers.get("Origin") == PUBLIC_ORIGIN


def csrf_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if not valid_origin():
            return jsonify(
                error="Invalid origin"
            ), 403

        received = request.headers.get(
            "X-CSRF-Token", ""
        )

        expected = create_csrf_token(
            g.claims["jti"]
        )

        if not hmac.compare_digest(received, expected):

            return jsonify(
                error="CSRF validation failed"
            ), 403

        return function(*args, **kwargs)

    return wrapper


# ==========================================
# 5. Response Security
# ==========================================

@app.after_request
def security_headers(response):

    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"

    return response


# ==========================================
# 6. Main Page & Health Check
# ==========================================

@app.get("/")
def index():
    return app.send_static_file("index.html")


@app.get("/health")
def health():

    try:
        with get_db().cursor() as cursor:
            cursor.execute("SELECT 1")

        return jsonify(
            status="healthy",
            database="connected",
            slot=SLOT,
            version=BUILD_VERSION
        )

    except pymysql.MySQLError:

        return jsonify(
            status="unhealthy"
        ), 503


# ==========================================
# 7. Login
# ==========================================

@app.post("/api/login")
def login():

    if not valid_origin():
        return jsonify(error="Invalid origin"), 403

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify(error="JSON required"), 400

    username = data.get("username", "")
    password = data.get("password", "")

    if not isinstance(username, str):
        return jsonify(error="Invalid input"), 400

    if not isinstance(password, str):
        return jsonify(error="Invalid input"), 400

    if not username or not password:
        return jsonify(error="Missing credentials"), 400

    if len(username) > 100 or len(password) > 256:
        return jsonify(error="Invalid input length"), 400

    with get_db().cursor() as cursor:

        cursor.execute("""
            SELECT id, password_hash
            FROM users
            WHERE username = %s
        """, (username,))

        user = cursor.fetchone()

    if not user or not check_password_hash(
        user["password_hash"],
        password
    ):
        return jsonify(
            error="Invalid username or password"
        ), 401

    token = create_access_token(user["id"])

    response = make_response(
        jsonify(message="Login successful")
    )

    response.set_cookie(
        COOKIE_NAME,
        token,
        httponly=True,
        secure=True,
        samesite="Strict",
        max_age=TOKEN_LIFETIME,
        path="/"
    )

    return response


# ==========================================
# 8. User Profile & CSRF Token
# ==========================================

@app.get("/api/session")
@auth_required
def session_info():

    with get_db().cursor() as cursor:

        cursor.execute("""
            SELECT username, full_name, github_id
            FROM users
            WHERE id = %s
        """, (g.user_id,))

        user = cursor.fetchone()

    if not user:
        return jsonify(error="User not found"), 401

    return jsonify(
        user=user,
        csrf_token=create_csrf_token(
            g.claims["jti"]
        )
    )


# ==========================================
# 9. One-Time Request Token
# ==========================================

@app.get("/api/nonce")
@auth_required
def issue_nonce():

    now = int(time.time())

    payload = {
        "sub": str(g.user_id),
        "session": g.claims["jti"],
        "jti": str(uuid.uuid4()),
        "action": "create_memo",
        "iss": "secure-memo",
        "aud": "memo-request",
        "iat": now,
        "exp": min(
            now + NONCE_LIFETIME,
            g.claims["exp"]
        )
    }

    nonce = jwt.encode(
        payload,
        JWT_SECRET,
        algorithm="HS256"
    )

    return jsonify(request_token=nonce)


# ==========================================
# 10. Read Memos
# ==========================================

@app.get("/api/memos")
@auth_required
def get_memos():

    with get_db().cursor() as cursor:

        cursor.execute("""
            SELECT id, title, content, created_at
            FROM memos
            WHERE user_id = %s
            ORDER BY id DESC
        """, (g.user_id,))

        memos = cursor.fetchall()

    for memo in memos:

        memo["created_at"] = (
            memo["created_at"].strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )

    return jsonify(memos)


# ==========================================
# 11. Create Memo
# ==========================================

@app.post("/api/memos")
@auth_required
@csrf_required
def create_memo():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify(error="JSON required"), 400

    title = data.get("title", "")
    content = data.get("content", "")

    if not isinstance(title, str):
        return jsonify(error="Invalid title"), 400

    if not isinstance(content, str):
        return jsonify(error="Invalid content"), 400

    title = title.strip()
    content = content.strip()

    if not title or not content:
        return jsonify(error="Missing fields"), 400

    if len(title) > 200 or len(content) > 5000:
        return jsonify(error="Input too long"), 400

    request_token = request.headers.get(
        "X-Request-Token", ""
    )

    # Validate one-time request token

    try:

        nonce = jwt.decode(
            request_token,
            JWT_SECRET,
            algorithms=["HS256"],
            issuer="secure-memo",
            audience="memo-request",
            options={
                "require": [
                    "sub",
                    "jti",
                    "iat",
                    "exp",
                    "session",
                    "action"
                ]
            }
        )

        if (
            nonce["sub"] != str(g.user_id)
            or nonce["session"] != g.claims["jti"]
            or nonce["action"] != "create_memo"
        ):
            return jsonify(
                error="Invalid request token"
            ), 403

    except jwt.InvalidTokenError:

        return jsonify(
            error="Invalid or expired request token"
        ), 403

    connection = get_db()

    try:

        connection.begin()

        with connection.cursor() as cursor:

            # Primary key prevents concurrent replay

            cursor.execute("""
                INSERT INTO used_nonces (
                    nonce_id,
                    expires_at
                )
                VALUES (%s, %s)
            """, (
                nonce["jti"],
                nonce["exp"]
            ))

            # Parameterized query prevents SQL injection

            cursor.execute("""
                INSERT INTO memos (
                    user_id,
                    title,
                    content
                )
                VALUES (%s, %s, %s)
            """, (
                g.user_id,
                title,
                content
            ))

            memo_id = cursor.lastrowid

        connection.commit()

    except pymysql.err.IntegrityError as error:

        connection.rollback()

        if error.args[0] == 1062:

            return jsonify(
                error="Replay attack detected"
            ), 409

        raise

    except Exception:

        connection.rollback()
        raise

    return jsonify(
        message="Memo created",
        id=memo_id
    ), 201


# ==========================================
# 12. Logout
# ==========================================

@app.post("/api/logout")
@auth_required
@csrf_required
def logout():

    response = make_response(
        jsonify(message="Logout successful")
    )

    response.delete_cookie(
        COOKIE_NAME,
        path="/",
        secure=True,
        httponly=True,
        samesite="Strict"
    )

    return response


if __name__ == "__main__":

    init_db()

    app.run(
        host="0.0.0.0",
        port=8000
    )