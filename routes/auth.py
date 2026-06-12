"""
Blueprint за authentication endpoints.

-> Регистрация на нови потребители (POST /api/auth/register)
-> Login на съществуващи потребители (POST /api/auth/login)
-> Информация за текущия потребител (GET /api/auth/me)

Защита на данните:
-> Паролите се хешират с bcrypt преди записване в базата
-> Authentication се прави чрез JWT (JSON Web Tokens)
"""

import re
import bcrypt
from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, get_jwt
from mysql.connector import Error, IntegrityError
from database.connection import get_connection
from functools import wraps


# Създаваме Blueprint с url_prefix
# url_prefix="/api/auth" означава, че всички endpoint-и в този Blueprint автоматично започват с /api/auth/...
# @auth_bp.route("/register") = /api/auth/register
auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

# Помощни функции за валидация
def is_valid_email(email):
    """Валидация на email чрез regex."""
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, email) is not None


def is_valid_password(password):
    """Валидация на паролата."""
    if len(password) < 8:
        return False, "Паролата трябва да е поне 8 символа"
    if not re.search(r"[A-Za-z]", password):
        return False, "Паролата трябва да съдържа поне една буква"
    if not re.search(r"\d", password):
        return False, "Паролата трябва да съдържа поне една цифра"
    return True, None


def is_valid_username(username):
    """Валидация на username."""
    if len(username) < 3 or len(username) > 50:
        return False, "Username трябва да е между 3 и 50 символа"
    if not re.match(r"^[a-zA-Z0-9._-]+$", username):
        return False, "Username може да съдържа само букви, цифри, точки, тирета и долни черти"
    return True, None


# Endpoint: POST /api/auth/register
@auth_bp.route("/register", methods=["POST"])
def register():
    """Регистрира нов потребител в системата."""
    data = request.get_json()
    
    if not data:
        return jsonify({
            "status": "error",
            "message": "Липсва JSON тяло на заявката"
        }), 400
    
    username = data.get("username", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    
    # Проверка дали всички полета са попълнени
    if not username or not email or not password:
        return jsonify({
            "status": "error",
            "message": "Полетата username, email и password са задължителни"
        }), 400
    
    # Валидация на username
    valid, error_msg = is_valid_username(username)
    if not valid:
        return jsonify({"status": "error", "message": error_msg}), 400
    
    # Валидация на email
    if not is_valid_email(email):
        return jsonify({
            "status": "error",
            "message": "Невалиден email адрес"
        }), 400
    
    # Валидация на парола
    valid, error_msg = is_valid_password(password)
    if not valid:
        return jsonify({"status": "error", "message": error_msg}), 400
    
    # Хеширане на паролата с bcrypt
    # bcrypt.gensalt() генерира случаен salt
    # bcrypt.hashpw() прави хеш от паролата + salt-а
    password_bytes = password.encode("utf-8")
    password_hash = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    
    # Записване в базата данни
    try:
        connection = get_connection()
        cursor = connection.cursor()
        
        # Записваме потребителя; role е "user" по подразбиране
        insert_query = """
            INSERT INTO users (username, email, password_hash, role)
            VALUES (%s, %s, %s, 'user')
        """
        cursor.execute(insert_query, (username, email, password_hash.decode("utf-8")))
        connection.commit()
        
        # Взимаме ID-то на новосъздадения потребител
        user_id = cursor.lastrowid
        
        cursor.close()
        connection.close()
        
    except IntegrityError as e:
        # IntegrityError се случва при нарушение на UNIQUE constraint
        # (username или email вече съществуват)
        error_str = str(e).lower()
        if "username" in error_str:
            return jsonify({
                "status": "error",
                "message": "Този username вече е зает"
            }), 409
        elif "email" in error_str:
            return jsonify({
                "status": "error",
                "message": "Този email вече е регистриран"
            }), 409
        else:
            return jsonify({
                "status": "error",
                "message": "Username или email вече съществуват"
            }), 409
            
    except Error as e:
        return jsonify({
            "status": "error",
            "message": "Грешка при записване в базата",
            "details": str(e)
        }), 500
    
    # Създаване на JWT токен
    # identity е каквото искаме да "опаковаме" в токена
    # Използваме user_id и role – ще ни трябват за authorization
    access_token = create_access_token(
        identity=str(user_id),
        additional_claims={"role": "user", "username": username}
    )
    
    # Връщане на успешен отговор
    return jsonify({
        "status": "ok",
        "message": "Регистрацията е успешна",
        "user": {
            "id": user_id,
            "username": username,
            "email": email,
            "role": "user"
        },
        "access_token": access_token
    }), 201

# Endpoint: POST /api/auth/login
@auth_bp.route("/login", methods=["POST"])
def login():
    """Логва съществуващ потребител и връща JWT токен."""
    data = request.get_json()
    
    if not data:
        return jsonify({
            "status": "error",
            "message": "Липсва JSON тяло на заявката"
        }), 400
    
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    
    if not email or not password:
        return jsonify({
            "status": "error",
            "message": "Полетата email и password са задължителни"
        }), 400
    
    # Намираме потребителя в базата
    try:
        connection = get_connection()
        # dictionary=True връща резултатите като dict вместо tuple
        # Така можем да достъпваме колоните по име: user["username"]
        cursor = connection.cursor(dictionary=True)
        
        cursor.execute(
            "SELECT id, username, email, password_hash, role FROM users WHERE email = %s",
            (email,)
        )
        user = cursor.fetchone()
        
        cursor.close()
        connection.close()
        
    except Error as e:
        return jsonify({
            "status": "error",
            "message": "Грешка при достъп до базата",
            "details": str(e)
        }), 500
    
    # Проверка дали потребителят съществува
    if user is None:
        return jsonify({
            "status": "error",
            "message": "Грешен email или парола"
        }), 401
    
    # Сравняваме паролата с хеша
    # bcrypt.checkpw приема два байтови низа:
    # - изпратената парола (от потребителя)
    # - хеша от базата
    # Връща True ако съвпадат, False ако не
    password_bytes = password.encode("utf-8")
    stored_hash_bytes = user["password_hash"].encode("utf-8")
    
    if not bcrypt.checkpw(password_bytes, stored_hash_bytes):
        return jsonify({
            "status": "error",
            "message": "Грешен email или парола"
        }), 401
    
    # Създаваме нов JWT токен
    access_token = create_access_token(
        identity=str(user["id"]),
        additional_claims={
            "role": user["role"],
            "username": user["username"]
        }
    )

    # Връща отговор при успешно влизане в системата
    return jsonify({
        "status": "ok",
        "message": "Успешен login",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"]
        },
        "access_token": access_token
    }), 200

# Endpoint: GET /api/auth/me
# Защитен endpoint – изисква валиден JWT токен
@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def get_current_user():
    """Връща информация за текущия логнат потребител."""
    # Извличаме user_id от токена
    # get_jwt_identity() връща стойността, която сложихме в create_access_token(identity=...)
    # При нас това беше str(user_id)
    user_id = get_jwt_identity()
    
    # Извличаме допълнителните claims (role, username)
    # get_jwt() връща целия payload на токена
    claims = get_jwt()
    
    # Взимаме данни от базата
    try:
        connection = get_connection()
        cursor = connection.cursor(dictionary=True)
        
        cursor.execute(
            "SELECT id, username, email, role, created_at FROM users WHERE id = %s",
            (user_id,)
        )
        user = cursor.fetchone()
        
        cursor.close()
        connection.close()
        
    except Error as e:
        return jsonify({
            "status": "error",
            "message": "Грешка при достъп до базата",
            "details": str(e)
        }), 500
    
    # Проверка дали потребителят още съществува
    if user is None:
        return jsonify({
            "status": "error",
            "message": "Потребителят не съществува"
        }), 404
    
    return jsonify({
        "status": "ok",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "created_at": user["created_at"].isoformat() if user["created_at"] else None
        }
    }), 200


# Декоратор: admin_required
def admin_required(fn):
    """Декоратор за endpoint-и, които изискват admin role."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        claims = get_jwt()
        if claims.get("role") != "admin":
            return jsonify({
                "status": "error",
                "message": "Достъпът е разрешен само за администратори"
            }), 403
        return fn(*args, **kwargs)
    return wrapper
