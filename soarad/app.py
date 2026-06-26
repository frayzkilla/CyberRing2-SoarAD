import base64
import datetime
import functools
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import re
import logging 
import sys

import jwt
from flask import (
    Flask,
    g,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
    flash,
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

logger.info("Starting SOAR Platform application...")

app = Flask(__name__)
app.config["SECRET_KEY"] = "supersecretflaskkey"

JWT_SECRET = "secret"
JWT_ALGORITHM = "HS256"

DATABASE = "/app/data/soar.db"

AVAILABLE_SCRIPTS = {
    "collect_processes": {"name": "Сбор запущенных процессов", "params": ["target_ip"]},
    "isolate_host": {"name": "Изоляция хоста", "params": ["target_ip"]},
    "run_antivirus": {"name": "Запуск антивирусной проверки", "params": ["target_ip","scan_path"]},
    "block_account": {"name": "Блокировка учётной записи", "params": ["target_ip","account_name"]},
    "find_modified_files": {"name": "Поиск недавно изменённых файлов", "params": ["target_ip", "search_dir"]},
    "collect_services": {"name": "Сбор информации о сервисах", "params": ["target_ip"]},
    "collect_commands": {"name": "Сбор последних команд", "params": ["target_ip"]},
    "check_sudoers": {"name": "Проверка sudoers", "params": ["target_ip"]},
    "check_ports": {"name": "Проверка открытых портов", "params": ["target_ip"]},
}


def get_db():
    if "db" not in g:
        os.makedirs(os.path.dirname(DATABASE), exist_ok=True)
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            username     TEXT    UNIQUE NOT NULL,
            password     TEXT    NOT NULL,
            organization TEXT    NOT NULL,
            role         TEXT    NOT NULL DEFAULT 'user',
            created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS tickets (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            title               TEXT    NOT NULL,
            summary             TEXT    DEFAULT '',
            description         TEXT    DEFAULT '',
            confidential_data   TEXT    DEFAULT '',
            status              TEXT    DEFAULT 'open',
            priority            TEXT    DEFAULT 'medium',
            owner_id            INTEGER NOT NULL,
            organization        TEXT    NOT NULL,
            created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (organization) REFERENCES users(organization) ON DELETE CASCADE
        );
        
        CREATE TABLE IF NOT EXISTS script_results (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id   INTEGER NOT NULL,
            script_name TEXT    NOT NULL,
            parameters  TEXT    DEFAULT '',
            output      TEXT    DEFAULT '',
            organization TEXT   NOT NULL,
            executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE,
            FOREIGN KEY (organization) REFERENCES users(organization) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS organization_settings (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            organization TEXT    NOT NULL UNIQUE,
            ip           TEXT    DEFAULT '',
            port         INTEGER DEFAULT 0,
            api_key      TEXT    DEFAULT '',
            created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (organization) REFERENCES users(organization) ON DELETE CASCADE
        );
    """)
    pw = hashlib.sha256(b"admin").hexdigest()
    try:
        db.execute(
            "INSERT INTO users (username, password, role, organization) VALUES (?, ?, ?, ?)",
            ("admin", pw, "admin", "MainOrg"),
        )
        db.execute(
            "INSERT INTO users (username, password, role, organization) VALUES (?, ?, ?, ?)",
            ("org_admin", pw, "org_admin", "MainOrg"),
        )
        db.commit()
    except sqlite3.IntegrityError:
        pass


def create_token(user_id, username, role, organization):
    payload = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "organization": organization,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.InvalidTokenError:
        return None


def get_current_user():
    token = None
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
    if not token:
        token = request.cookies.get("token")
    if not token:
        return None
    return decode_token(token)


def login_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            if request.path.startswith("/api/"):
                return json_response({"error": "Authentication required"}), 401
            return redirect(url_for("login_page"))
        g.current_user = user
        return f(*args, **kwargs)

    return wrapper


def admin_required(f):
    @functools.wraps(f)
    @login_required
    def wrapper(*args, **kwargs):
        if g.current_user.get("role") != "admin":
            return json_response({"error": "Admin access required"}), 403
        return f(*args, **kwargs)

    return wrapper

def org_admin_required(f):
    @functools.wraps(f)
    @login_required
    def wrapper(*args, **kwargs):
        if g.current_user.get("role") != "org_admin" and g.current_user.get("role") != "local_org_admin":
            return json_response({"error": "Organization admin access required"}), 403
        return f(*args, **kwargs)

    return wrapper


@app.route("/")
def index():
    if get_current_user():
        return redirect(url_for("tickets"))
    return redirect(url_for("login_page"))

@app.route("/tickets")
@login_required
def tickets():
    db = get_db()
    
    if g.current_user.get("role") != "admin":
        tickets = db.execute("""
            SELECT t.id, t.title, t.priority, t.status, t.created_at, 
                   u.username as owner_name
            FROM tickets t
            JOIN users u ON t.owner_id = u.id
            WHERE t.owner_id = ?
            ORDER BY t.created_at DESC
        """, (g.current_user["user_id"],)).fetchall()
    else:
        tickets = db.execute("""
            SELECT t.id, t.title, t.priority, t.status, t.created_at, 
                   u.username as owner_name
            FROM tickets t
            JOIN users u ON t.owner_id = u.id
            WHERE t.organization = ?
            ORDER BY t.created_at DESC
        """, (g.current_user["organization"],)).fetchall()
    
    return render_template("tickets.html", user=g.current_user, tickets=tickets)

@app.route("/ticket/<int:ticket_id>")
@login_required
def ticket_detail(ticket_id):
    db = get_db()
    
    ticket = db.execute("""
        SELECT t.*, u.username as owner_name 
        FROM tickets t
        JOIN users u ON t.owner_id = u.id
        WHERE t.id = ?
    """, (ticket_id,)).fetchone()
    
    if not ticket:
        flash("Тикет не найден", "error")
        return redirect(url_for("tickets"))
    
    if g.current_user.get("role") != "admin" and ticket["owner_id"] != g.current_user["user_id"]:
        flash("У вас нет доступа к этому тикету", "error")
        return redirect(url_for("tickets"))
    if ticket["organization"] != g.current_user["organization"]:
        flash("Вы можете просматривать только тикеты своей организации", "error")
        return redirect(url_for("tickets"))
    
    return render_template("ticket_detail.html", user=g.current_user, ticket=ticket)


@app.route("/ticket/<int:ticket_id>/edit", methods=["GET", "POST"])
@login_required
def ticket_edit(ticket_id):
    db = get_db()

    ticket = db.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    
    if not ticket:
        flash("Тикет не найден", "error")
        return redirect(url_for("tickets"))
    
    is_admin = g.current_user.get("role") == "admin"
    is_owner = ticket["owner_id"] == g.current_user["user_id"]
    
    if not is_admin and not is_owner:
        flash("У вас нет прав на редактирование этого тикета", "error")
        return redirect(url_for("tickets"))
    
    if not is_admin and ticket["organization"] != g.current_user["organization"]:
        flash("У вас нет прав на редактирование этого тикета", "error")
        return redirect(url_for("tickets"))
    
    if is_admin and ticket["organization"] != g.current_user["organization"]:
        flash("Вы можете редактировать только тикеты своей организации", "error")
        return redirect(url_for("tickets"))
    
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        confidential_data = request.form.get("confidential_data", "").strip()
        priority = request.form.get("priority", "medium")
        status = request.form.get("status", "open")
        
        if is_admin:
            summary = request.form.get("summary", "").strip()
        else:
            summary = ticket["summary"]  
            if status == "closed" and ticket["status"] != "closed":
                flash("Только администратор может закрыть тикет", "error")
                return render_template("ticket_edit.html", user=g.current_user, ticket=ticket, is_admin=is_admin)
        
        if not title:
            flash("Название тикета обязательно", "error")
            return render_template("ticket_edit.html", user=g.current_user, ticket=ticket, is_admin=is_admin)
        
        db.execute(
            """
                UPDATE tickets 
                SET title = ?, summary = ?, description = ?, confidential_data = ?, priority = ?, status = ?
                WHERE id = ?
            """,
            (title, summary, description, confidential_data, priority, status, ticket_id)
        )
        db.commit()
        
        flash("Тикет успешно обновлён", "success")
        return redirect(url_for("ticket_detail", ticket_id=ticket_id))
    
    return render_template("ticket_edit.html", user=g.current_user, ticket=ticket, is_admin=is_admin)


@app.route("/ticket/<int:ticket_id>/scripts")
@login_required
def ticket_scripts(ticket_id):
    db = get_db()
    
    ticket = db.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    if not ticket:
        flash("Тикет не найден", "error")
        return redirect(url_for("tickets"))
    
    if g.current_user.get("role") not in ["admin", "org_admin"]:
        flash("Только администратор может запускать скрипты реагирования", "error")
        return redirect(url_for("ticket_detail", ticket_id=ticket_id))
    
    if ticket["organization"] != g.current_user["organization"]:
        flash("Вы можете запускать скрипты только для тикетов своей организации", "error")
        return redirect(url_for("tickets"))
    
    scripts = db.execute("""
        SELECT * FROM script_results 
        WHERE ticket_id = ? 
        ORDER BY executed_at DESC
    """, (ticket_id,)).fetchall()
    
    return render_template("ticket_scripts.html", 
                         user=g.current_user, 
                         ticket=ticket, 
                         scripts=scripts,
                         available_scripts=AVAILABLE_SCRIPTS)


@app.route("/ticket/<int:ticket_id>/run-script", methods=["POST"])
@login_required
def ticket_run_script(ticket_id):
    db = get_db()
    
    if g.current_user.get("role") not in ["admin", "org_admin"]:
        flash("Только администратор может запускать скрипты реагирования", "error")
        return redirect(url_for("ticket_detail", ticket_id=ticket_id))
    
    ticket = db.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    if not ticket:
        flash("Тикет не найден", "error")
        return redirect(url_for("tickets"))
    
    if ticket["organization"] != g.current_user["organization"]:
        flash("Вы можете запускать скрипты только для тикетов своей организации", "error")
        return redirect(url_for("tickets"))
    
    org_settings = db.execute("""
        SELECT ip, port, api_key FROM organization_settings 
        WHERE organization = ?
    """, (g.current_user["organization"],)).fetchone()
    
    if not org_settings:
        flash(f"Настройки для организации '{g.current_user['organization']}' не найдены. Пожалуйста, попросите org_admin вашей организации настроить IP, порт и API ключ подключения в разделе настроек организации.", "error")
        return redirect(url_for("ticket_scripts", ticket_id=ticket_id))
    
    script_key = request.form.get("script_key")
    script_name = request.form.get("script_name", "")
    
    if not script_key or script_key not in AVAILABLE_SCRIPTS:
        flash("Неверный выбор скрипта", "error")
        return redirect(url_for("ticket_scripts", ticket_id=ticket_id))
    
    script_info = AVAILABLE_SCRIPTS[script_key]
    
    params = {}
    for param in script_info["params"]:
        param_value = request.form.get(param, "").strip()
        if not param_value:
            flash(f"Параметр '{param}' обязателен для заполнения", "error")
            return redirect(url_for("ticket_scripts", ticket_id=ticket_id))
        params[param] = param_value
    
    params_str = json.dumps(params, ensure_ascii=False)
    
    outputs = {
        "collect_processes": f"Сбор процессов на {params.get('target_ip', 'неизвестный IP')} завершён. Найдено 45 процессов.",
        "isolate_host": f"Хост {params.get('target_ip', 'неизвестный IP')} изолирован. Доступ заблокирован.",
        "run_antivirus": f"Антивирусная проверка на {params.get('target_ip', 'неизвестный IP')} в каталоге {params.get('scan_path', 'неизвестный путь')} завершена. Найдено 2 угрозы.",
        "block_account": f"Учётная запись {params.get('account_name', 'неизвестная учётная запись')} на хосте {params.get('target_ip', 'неизвестный IP')} заблокирована.",
        "find_modified_files": f"Поиск изменённых файлов в {params.get('search_dir', 'неизвестный каталог')} на {params.get('target_ip', 'неизвестный IP')} завершён. Найдено 15 изменённых файлов.",
        "collect_services": f"Сбор сервисов на {params.get('target_ip', 'неизвестный IP')} завершён. Найдено 78 сервисов.",
        "collect_commands": f"Сбор последних команд на {params.get('target_ip', 'неизвестный IP')} завершён. Найдено 150 команд.",
        "check_sudoers": f"Проверка sudoers на {params.get('target_ip', 'неизвестный IP')} завершена. Конфигурация корректна.",
        "check_ports": f"Проверка открытых портов на {params.get('target_ip', 'неизвестный IP')} завершена. Открытые порты: 22, 80, 443, 8080."
    }
    
    output = outputs.get(script_key, f"Скрипт '{script_info['name']}' выполнен. Параметры: {params_str}")
    
    db.execute(
        """
        INSERT INTO script_results (ticket_id, script_name, parameters, output, organization)
        VALUES (?, ?, ?, ?, ?)
        """,
        (ticket_id, script_info["name"], params_str, output, g.current_user["organization"])
    )
    db.commit()
    
    flash(f"Скрипт '{script_info['name']}' успешно запущен", "success")
    return redirect(url_for("ticket_scripts", ticket_id=ticket_id))


@app.route("/ticket/create", methods=["GET", "POST"])
@login_required
def ticket_create():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        confidential_data = request.form.get("confidential_data", "").strip()
        priority = request.form.get("priority", "medium")
        
        if not title:
            flash("Название тикета обязательно", "error")
            return render_template("ticket_create.html", user=g.current_user)
        
        db = get_db()
        db.execute(
            """
            INSERT INTO tickets (title, description, confidential_data, priority, owner_id, organization)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (title, description, confidential_data, priority, 
             g.current_user["user_id"], g.current_user["organization"])
        )
        db.commit()
        
        flash("Тикет успешно создан", "success")
        return redirect(url_for("tickets"))
    
    return render_template("ticket_create.html", user=g.current_user)



@app.route("/login", methods=["GET", "POST"])
def login_page():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if not username or not password:
            error = "Заполните все поля"
        else:
            pw_hash = hashlib.sha256(password.encode()).hexdigest()

            user = (
                get_db()
                .execute(
                    "SELECT * FROM users WHERE username = ? AND password = ?",
                    (username, pw_hash),
                )
                .fetchone()
            )

            if user:
                token = create_token(user["id"], user["username"], user["role"], user["organization"])
                if user["role"] == "org_admin" or user["role"] == "local_org_admin":
                    resp = make_response(redirect(url_for("organizations")))
                else:
                    resp = make_response(redirect(url_for("tickets")))
                resp.set_cookie("token", token, httponly=True)
                return resp
            error = "Неверные учётные данные"
    return render_template("login.html", error=error)


@app.route("/register", methods=["GET", "POST"])
def register_page():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        organization = request.form.get("organization", "").strip()
        
        if not username or not password or not organization:
            error = "Заполните все поля"
        elif len(password) < 6:
            error = "Пароль должен быть не менее 6 символов"
        elif not re.match(r'^[a-zA-Z0-9!@$_,.?]+$', password):
            error = "Пароль может содержать только латинские буквы, цифры и специальные символы !@$_,.?"
        else:
            pw_hash = hashlib.sha256(password.encode()).hexdigest()
            db = get_db()
            existing_org = db.execute(
                "SELECT organization FROM users WHERE organization = ? LIMIT 1",
                (organization,)
            ).fetchone()
            if not existing_org:
                role = "local_org_admin"
            else:
                role = "user"

            try:
                cur = db.execute(
                    "INSERT INTO users (username, password, role, organization) VALUES (?, ?, ?, ?)",
                    (username, pw_hash, role, organization),
                )
                db.commit()
                token = create_token(cur.lastrowid, username, "user", organization)
                resp = make_response(redirect(url_for("login_page")))
                resp.set_cookie("token", token, httponly=True)
                return resp
            except sqlite3.IntegrityError:
                error = "Пользователь уже существует"
    return render_template("register.html", error=error)




@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("login_page")))
    resp.set_cookie("token", "", expires=0)
    return resp

@app.route("/organizations")
@org_admin_required
def organizations():
    db = get_db()
    
    if g.current_user["role"] == "org_admin":
        organizations = db.execute("""
            SELECT 
                u.organization,
                COUNT(DISTINCT u.id) as total_users,
                SUM(CASE WHEN u.role = 'admin' THEN 1 ELSE 0 END) as admin_count,
                SUM(CASE WHEN u.role = 'user' THEN 1 ELSE 0 END) as user_count,
                SUM(CASE WHEN u.role = 'org_admin' THEN 1 ELSE 0 END) as org_admin_count,
                SUM(CASE WHEN u.role = 'local_org_admin' THEN 1 ELSE 0 END) as local_org_admin_count
            FROM users u
            GROUP BY u.organization
            ORDER BY u.organization ASC
        """).fetchall()
    else:  
        organizations = db.execute("""
            SELECT 
                u.organization,
                COUNT(DISTINCT u.id) as total_users,
                SUM(CASE WHEN u.role = 'admin' THEN 1 ELSE 0 END) as admin_count,
                SUM(CASE WHEN u.role = 'user' THEN 1 ELSE 0 END) as user_count,
                SUM(CASE WHEN u.role = 'org_admin' THEN 1 ELSE 0 END) as org_admin_count,
                SUM(CASE WHEN u.role = 'local_org_admin' THEN 1 ELSE 0 END) as local_org_admin_count
            FROM users u
            WHERE u.organization = ?
            GROUP BY u.organization
            ORDER BY u.organization ASC
        """, (g.current_user["organization"],)).fetchall()
    
    return render_template("organizations.html", user=g.current_user, organizations=organizations)


@app.route("/organization/<org_name>")
@org_admin_required
def organization_detail(org_name):
    db = get_db()
    
    if g.current_user["role"] == "local_org_admin":
        if org_name != g.current_user["organization"]:
            flash("У вас нет доступа к этой организации", "error")
            return redirect(url_for("organizations"))
    
    org_exists = db.execute("SELECT organization FROM users WHERE organization = ? LIMIT 1", (org_name,)).fetchone()
    if not org_exists:
        flash("Организация не найдена", "error")
        return redirect(url_for("organizations"))
    
    users = db.execute("""
        SELECT id, username, role, created_at 
        FROM users 
        WHERE organization = ?
        ORDER BY 
            CASE role 
                WHEN 'org_admin' THEN 1
                WHEN 'local_org_admin' THEN 2
                WHEN 'admin' THEN 3
                WHEN 'user' THEN 4
            END,
            username ASC
    """, (org_name,)).fetchall()
    
    return render_template("organization_detail.html", 
                         user=g.current_user, 
                         users=users,
                         org_name=org_name)


@app.route("/organization/<org_name>/settings", methods=["GET", "POST"])
@org_admin_required
def organization_settings(org_name):
    db = get_db()
    
    if g.current_user["role"] in ["org_admin", "local_org_admin"]:
        if org_name != g.current_user["organization"]:
            flash("У вас нет доступа к настройкам этой организации", "error")
            return redirect(url_for("organizations"))
    
    settings = db.execute("""
        SELECT * FROM organization_settings 
        WHERE organization = ?
    """, (org_name,)).fetchone()

    if not settings:
        db.execute("""
            INSERT INTO organization_settings (organization, ip, port, api_key)
            VALUES (?, ?, ?, ?)
        """, (org_name, "", 0, ""))
        db.commit()
        settings = db.execute("""
            SELECT * FROM organization_settings 
            WHERE organization = ?
        """, (org_name,)).fetchone()
    
    if request.method == "POST":
        ip = request.form.get("ip", "").strip()
        port = request.form.get("port", "").strip()
        api_key = request.form.get("api_key", "").strip()
        
        if port and not port.isdigit():
            flash("Порт должен быть числом", "error")
            return render_template("organization_settings.html", 
                                 user=g.current_user, 
                                 org_name=org_name, 
                                 settings=settings)
        
        port_int = int(port) if port else 0
        
        db.execute("""
            UPDATE organization_settings 
            SET ip = ?, port = ?, api_key = ?, updated_at = CURRENT_TIMESTAMP
            WHERE organization = ?
        """, (ip, port_int, api_key, org_name))
        db.commit()
        
        flash("Настройки успешно сохранены", "success")
        return redirect(url_for("organization_settings", org_name=org_name))
    
    return render_template("organization_settings.html", 
                         user=g.current_user, 
                         org_name=org_name, 
                         settings=settings)

@app.route("/organization/<org_name>/change-role", methods=["POST"])
@org_admin_required
def change_user_role(org_name):
    user_id = request.form.get("user_id")
    new_role = request.form.get("new_role")
    
    if not user_id or not new_role:
        flash("Неверные параметры запроса", "error")
        return redirect(url_for("organization_detail", org_name=org_name))
    
    if new_role not in ["user", "admin", "org_admin", "local_org_admin"]:
        flash("Недопустимая роль. Доступны роли: user, admin, org_admin, local_org_admin", "error")
        return redirect(url_for("organization_detail", org_name=org_name))
    
    db = get_db()
    
    user = db.execute("SELECT id, username, role, organization FROM users WHERE id = ?", (user_id,)).fetchone()
    
    if not user:
        flash("Пользователь не найден", "error")
        return redirect(url_for("organization_detail", org_name=org_name))
    
    if user["organization"] != org_name:
        flash("Пользователь не принадлежит этой организации", "error")
        return redirect(url_for("organization_detail", org_name=org_name))
    
    if user["id"] == g.current_user["user_id"]:
        flash("Нельзя изменить свою собственную роль", "error")
        return redirect(url_for("organization_detail", org_name=org_name))
    
    current_user_role = g.current_user["role"]
    
    if current_user_role == "local_org_admin":
        if org_name != g.current_user["organization"]:
            flash("У вас нет прав на изменение ролей в этой организации", "error")
            return redirect(url_for("organizations"))
        
        if new_role == "org_admin":
            flash("Администратор организации не может назначать роль org_admin", "error")
            return redirect(url_for("organization_detail", org_name=org_name))
        
        if user["role"] == "org_admin":
            flash("Нельзя изменять роль администратора организации", "error")
            return redirect(url_for("organization_detail", org_name=org_name))
    
    
    db.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
    db.commit()
    
    role_names = {
        "user": "пользователь",
        "admin": "администратор",
        "org_admin": "администратор организации",
        "local_org_admin": "локальный администратор организации"
    }
    
    flash(f"Роль пользователя {user['username']} изменена на {role_names[new_role]}", "success")
    return redirect(url_for("organization_detail", org_name=org_name))


@app.route("/user/<int:user_id>")
@login_required
def user_profile(user_id):
    db = get_db()
    
    if user_id != g.current_user["user_id"]:
        flash("Вы можете просматривать только свой профиль", "error")
        return redirect(url_for("tickets"))
    
    user_info = db.execute("""
        SELECT id, username, role, organization, created_at 
        FROM users 
        WHERE id = ?
    """, (user_id,)).fetchone()
    
    if not user_info:
        flash("Пользователь не найден", "error")
        return redirect(url_for("tickets"))
    
    return render_template("user_profile.html", 
                         user=g.current_user,
                         profile_user=user_info)


@app.route("/user/<int:user_id>/change-password", methods=["POST"])
@login_required
def change_password(user_id):
    if user_id != g.current_user["user_id"]:
        flash("Вы можете менять только свой пароль", "error")
        return redirect(url_for("tickets"))
    
    current_password = request.form.get("current_password", "").strip()
    new_password = request.form.get("new_password", "").strip()
    confirm_password = request.form.get("confirm_password", "").strip()
    
    if not current_password or not new_password or not confirm_password:
        flash("Заполните все поля", "error")
        return redirect(url_for("user_profile", user_id=user_id))
    
    if new_password != confirm_password:
        flash("Новый пароль и подтверждение не совпадают", "error")
        return redirect(url_for("user_profile", user_id=user_id))
    
    if len(new_password) < 6:
        flash("Новый пароль должен быть не менее 6 символов", "error")
        return redirect(url_for("user_profile", user_id=user_id))
    
    if not re.match(r'^[a-zA-Z0-9!@$_,.?]+$', new_password):
        flash("Пароль может содержать только латинские буквы, цифры и специальные символы !@$_,.?", "error")
        return redirect(url_for("user_profile", user_id=user_id))
    
    
    db = get_db()
    
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    
    if not user:
        flash("Пользователь не найден", "error")
        return redirect(url_for("tickets"))
    
    current_password_hash = hashlib.sha256(current_password.encode()).hexdigest()
    
    if user["password"] != current_password_hash:
        flash("Неверный текущий пароль", "error")
        return redirect(url_for("user_profile", user_id=user_id))
    
    new_password_hash = hashlib.sha256(new_password.encode()).hexdigest()

    db.execute("UPDATE users SET password = ? WHERE id = ?", (new_password_hash, user_id))
    db.commit()
    
    flash("Пароль успешно изменён", "success")
    return redirect(url_for("user_profile", user_id=user_id))


def json_response(data, status=200):
    """Функция для возврата JSON с правильной кодировкой"""
    json_str = json.dumps(data, ensure_ascii=False, indent=2)
    response = make_response(json_str, status)
    response.headers['Content-Type'] = 'application/json; charset=utf-8'
    return response


@app.route("/api/admin/users", methods=["GET"])
@admin_required
def api_admin_users():
    rows = (
        get_db().execute("SELECT id, username, role, created_at FROM users").fetchall()
    )
    return json_response([dict(r) for r in rows])

@app.route("/api/tickets", methods=["GET"])
@login_required
def api_login_tickets():
    db = get_db()
    if g.current_user.get("role") == "admin":
        tickets = db.execute("""
            SELECT t.id, t.title, t.priority, t.status, t.created_at, 
                u.username as owner_name
            FROM tickets t
            JOIN users u ON t.owner_id = u.id
            WHERE t.organization = ?
            ORDER BY t.created_at DESC
        """, (g.current_user["organization"],)).fetchall()
        
    else:
        tickets = db.execute("""
            SELECT t.id, t.title, t.priority, t.status, t.created_at, 
                   u.username as owner_name
            FROM tickets t
            JOIN users u ON t.owner_id = u.id
            WHERE t.owner_id = ?
            ORDER BY t.created_at DESC
        """, (g.current_user["user_id"],)).fetchall()
    return json_response([dict(r) for r in tickets])



@app.route("/api/admin/ticket/<int:ticket_id>", methods=["GET"])
@admin_required
def api_admin_ticket_id(ticket_id):
    db = get_db()
    ticket = db.execute("""
        SELECT t.*, u.username as owner_name 
        FROM tickets t
        JOIN users u ON t.owner_id = u.id
        WHERE t.id = ?
    """, (ticket_id,)).fetchone()
    
    if not ticket:
        return json_response({"error": "Ticket not found"}), 404

    if ticket["organization"] != g.current_user["organization"]:
        return json_response({"error": "Only for organization members"}), 403
    
    return json_response(dict(ticket))


@app.route("/api/admin/ticket/<int:ticket_id>/scripts", methods=["GET"])
@admin_required
def api_login_ticket_scripts(ticket_id):
    db = get_db()
    ticket = db.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    if not ticket:
        return json_response({"error": "Ticket not found"}), 404
    
    scripts = db.execute("""
        SELECT * FROM script_results 
        WHERE ticket_id = ? 
        ORDER BY executed_at DESC
    """, (ticket_id,)).fetchall()
    
    return json_response([dict(r) for r in scripts])


@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json()
    
    if not data:
        return json_response({"error": "No JSON data provided"}), 400
    
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    organization = data.get("organization", "").strip()
    if not username or not password or not organization:
        return json_response({"error": "Заполните все поля"}), 400
    elif len(password) < 6:
        return json_response({"error": "Пароль должен быть не менее 6 символов"}), 400
    elif not re.match(r'^[a-zA-Z0-9!@$_,.?]+$', password):
        return json_response({"error": "Пароль может содержать только латинские буквы, цифры и специальные символы !@$_,.?"}), 400
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    db = get_db()
    existing_org = db.execute(
                "SELECT organization FROM users WHERE organization = ? LIMIT 1",
                (organization,)
            ).fetchone()
    if not existing_org:
        role = "local_org_admin"
    else:
        role = "user"
    try:
        cur = db.execute(
            "INSERT INTO users (username, password, role, organization) VALUES (?, ?, ?, ?)",
            (username, pw_hash, role, organization),
        )
        db.commit()
        token = create_token(cur.lastrowid, username, "user", organization)
        resp = make_response(redirect(url_for("login_page")))
        resp.set_cookie("token", token, httponly=True)
        return json_response({"result": "success"}), 201
    except sqlite3.IntegrityError:
        return json_response({"error": "Username already exists"}), 409

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    
    if not username or not password:
        return json_response({"error": "Username and password are required"}), 400
    
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, pw_hash)
    ).fetchone()
    
    if not user:
        return json_response({"error": "Invalid username or password"}), 401
    
    token = create_token(user["id"], user["username"], user["role"], user["organization"])
    
    return json_response({
        "success": True,
        "token": token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "organization": user["organization"]
        }
    }), 200    

@app.route("/api/ticket/<int:ticket_id>/run_script", methods=["POST"])
@login_required
def api_ticket_run_script(ticket_id):
    db = get_db()
    
    if g.current_user.get("role") not in ["admin", "org_admin"]:
        return json_response({"error": "Only administrators can run scripts"}), 403
    
    ticket = db.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    if not ticket:
        return json_response({"error": "Ticket not found"}), 404
    
    if ticket["organization"] != g.current_user["organization"]:
        return json_response({"error": "You can only run scripts on tickets from your organization"}), 403
    
    org_settings = db.execute("""
        SELECT ip, port, api_key FROM organization_settings 
        WHERE organization = ?
    """, (g.current_user["organization"],)).fetchone()
    
    if not org_settings:
        return json_response({"error": "Organization settings not found, please configure your organanization ip, port and api_key"}), 403
    
    data = request.get_json(silent=True) or {}
    
    script_key = data.get("script_key", "").strip()
    
    if not script_key or script_key not in AVAILABLE_SCRIPTS:
        return json_response({"error": "Invalid script selection"}), 400
    
    script_info = AVAILABLE_SCRIPTS[script_key]
    
    params = {}
    for param in script_info["params"]:
        param_value = data.get(param, "").strip()
        if not param_value:
            return json_response({"error": f"Parameter '{param}' is required"}), 400
        params[param] = param_value
    
    params_str = json.dumps(params, ensure_ascii=False)
    
    outputs = {
        "collect_processes": f"Сбор процессов на {params.get('target_ip', 'неизвестный IP')} завершён. Найдено 45 процессов.",
        "isolate_host": f"Хост {params.get('target_ip', 'неизвестный IP')} изолирован. Доступ заблокирован.",
        "run_antivirus": f"Антивирусная проверка на {params.get('target_ip', 'неизвестный IP')} в каталоге {params.get('scan_path', 'неизвестный путь')} завершена. Найдено 2 угрозы.",
        "block_account": f"Учётная запись {params.get('account_name', 'неизвестная учётная запись')} на хосте {params.get('target_ip', 'неизвестный IP')} заблокирована.",
        "find_modified_files": f"Поиск изменённых файлов в {params.get('search_dir', 'неизвестный каталог')} на {params.get('target_ip', 'неизвестный IP')} завершён. Найдено 15 изменённых файлов.",
        "collect_services": f"Сбор сервисов на {params.get('target_ip', 'неизвестный IP')} завершён. Найдено 78 сервисов.",
        "collect_commands": f"Сбор последних команд на {params.get('target_ip', 'неизвестный IP')} завершён. Найдено 150 команд.",
        "check_sudoers": f"Проверка sudoers на {params.get('target_ip', 'неизвестный IP')} завершена. Конфигурация корректна.",
        "check_ports": f"Проверка открытых портов на {params.get('target_ip', 'неизвестный IP')} завершена. Открытые порты: 22, 80, 443, 8080."
    }
    
    output = outputs.get(script_key, f"Скрипт '{script_info['name']}' выполнен. Параметры: {params_str}")
    
    cursor = db.execute(
        """
        INSERT INTO script_results (ticket_id, script_name, parameters, output, organization)
        VALUES (?, ?, ?, ?, ?)
        """,
        (ticket_id, script_info["name"], params_str, output, g.current_user["organization"])
    )
    db.commit()
    
    script_result_id = cursor.lastrowid
    
    return json_response({
        "success": True,
        "message": f"Script '{script_info['name']}' executed successfully",
        "script_result": {
            "id": script_result_id,
            "ticket_id": ticket_id,
            "script_name": script_info["name"],
            "parameters": params,
            "output": output,
            "executed_at": datetime.datetime.now().isoformat()
        }
    }, 200)

@app.route("/api/create_ticket", methods=["POST"])
@login_required
def api_create_ticket():
    db = get_db()
    
    data = request.get_json(silent=True) or {}
    
    title = data.get("title", "").strip()
    description = data.get("description", "").strip()
    confidential_data = data.get("confidential_data", "").strip()
    priority = data.get("priority", "medium")
    
    if not title:
        return json_response({"error": "Title is required"}), 400
    
    if priority not in ["low", "medium", "high"]:
        priority = "medium"
    
    try:
        cursor = db.execute(
            """
            INSERT INTO tickets (title, description, confidential_data, priority, owner_id, organization)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (title, description, confidential_data, priority, 
             g.current_user["user_id"], g.current_user["organization"])
        )
        db.commit()
        
        ticket_id = cursor.lastrowid
        
        new_ticket = db.execute("""
            SELECT t.*, u.username as owner_name 
            FROM tickets t
            JOIN users u ON t.owner_id = u.id
            WHERE t.id = ?
        """, (ticket_id,)).fetchone()
        
        return json_response({
            "success": True,
            "message": "Ticket created successfully",
            "ticket": dict(new_ticket)
        }), 201
        
    except Exception as e:
        return json_response({"error": f"Failed to create ticket: {str(e)}"}), 500
    

@app.route("/api/organizations", methods=["GET"])
@org_admin_required
def api_organizations():
    db = get_db()
    
    if g.current_user["role"] == "org_admin":
        organizations = db.execute("""
            SELECT 
                u.organization,
                COUNT(DISTINCT u.id) as total_users,
                SUM(CASE WHEN u.role = 'admin' THEN 1 ELSE 0 END) as admin_count,
                SUM(CASE WHEN u.role = 'user' THEN 1 ELSE 0 END) as user_count,
                SUM(CASE WHEN u.role = 'org_admin' THEN 1 ELSE 0 END) as org_admin_count,
                SUM(CASE WHEN u.role = 'local_org_admin' THEN 1 ELSE 0 END) as local_org_admin_count
            FROM users u
            GROUP BY u.organization
            ORDER BY u.organization ASC
        """).fetchall()
    else: 
        organizations = db.execute("""
            SELECT 
                u.organization,
                COUNT(DISTINCT u.id) as total_users,
                SUM(CASE WHEN u.role = 'admin' THEN 1 ELSE 0 END) as admin_count,
                SUM(CASE WHEN u.role = 'user' THEN 1 ELSE 0 END) as user_count,
                SUM(CASE WHEN u.role = 'org_admin' THEN 1 ELSE 0 END) as org_admin_count,
                SUM(CASE WHEN u.role = 'local_org_admin' THEN 1 ELSE 0 END) as local_org_admin_count
            FROM users u
            WHERE u.organization = ?
            GROUP BY u.organization
            ORDER BY u.organization ASC
        """, (g.current_user["organization"],)).fetchall()
    
    result = []
    for org in organizations:
        result.append({
            "organization": org["organization"],
            "total_users": org["total_users"] or 0,
            "admin_count": org["admin_count"] or 0,
            "user_count": org["user_count"] or 0,
            "org_admin_count": org["org_admin_count"] or 0,
            "local_org_admin_count": org["local_org_admin_count"] or 0
        })
    
    return json_response({
        "success": True,
        "organizations": result
    }), 200

@app.route("/api/organizations/<org_name>", methods=["GET"])
@org_admin_required
def api_organization_detail(org_name):
    db = get_db()
    
    if g.current_user["role"] == "local_org_admin":
        if org_name != g.current_user["organization"]:
            return json_response({"error": "Access denied. You can only view your own organization"}), 403
    
    org_exists = db.execute(
        "SELECT organization FROM users WHERE organization = ? LIMIT 1", 
        (org_name,)
    ).fetchone()
    
    if not org_exists:
        return json_response({"error": "Organization not found"}), 404
    
    users = db.execute("""
        SELECT id, username, role, created_at 
        FROM users 
        WHERE organization = ?
        ORDER BY 
            CASE role 
                WHEN 'org_admin' THEN 1
                WHEN 'local_org_admin' THEN 2
                WHEN 'admin' THEN 3
                WHEN 'user' THEN 4
            END,
            username ASC
    """, (org_name,)).fetchall()
    
    stats = db.execute("""
        SELECT 
            COUNT(*) as total_users,
            SUM(CASE WHEN role = 'admin' THEN 1 ELSE 0 END) as admin_count,
            SUM(CASE WHEN role = 'user' THEN 1 ELSE 0 END) as user_count,
            SUM(CASE WHEN role = 'org_admin' THEN 1 ELSE 0 END) as org_admin_count,
            SUM(CASE WHEN role = 'local_org_admin' THEN 1 ELSE 0 END) as local_org_admin_count
        FROM users 
        WHERE organization = ?
    """, (org_name,)).fetchone()
    
    result = {
        "success": True,
        "organization": org_name,
        "stats": {
            "total_users": stats["total_users"] or 0,
            "admin_count": stats["admin_count"] or 0,
            "user_count": stats["user_count"] or 0,
            "org_admin_count": stats["org_admin_count"] or 0,
            "local_org_admin_count": stats["local_org_admin_count"] or 0
        },
        "users": [dict(user) for user in users]
    }
    
    return json_response(result)

@app.route("/api/organization/<org_name>/settings", methods=["GET", "POST"])
@org_admin_required
def api_organization_settings(org_name):
    db = get_db()
    
    if g.current_user["role"] in ["org_admin", "local_org_admin"]:
        if org_name != g.current_user["organization"]:
            return json_response({"error": "Access denied"}, 403)
    
    if request.method == "GET":
        settings = db.execute("""
            SELECT ip, port, api_key, updated_at
            FROM organization_settings 
            WHERE organization = ?
        """, (org_name,)).fetchone()
        
        if not settings:
            return json_response({
                "success": True,
                "settings": {
                    "ip": "",
                    "port": 0,
                    "api_key": ""
                }
            }, 200)
        
        return json_response({
            "success": True,
            "settings": dict(settings)
        }, 200)
    
    elif request.method == "POST":
        data = request.get_json(silent=True) or {}
        
        ip = data.get("ip", "").strip()
        port = data.get("port", 0)
        api_key = data.get("api_key", "").strip()
        
        settings = db.execute("""
            SELECT * FROM organization_settings 
            WHERE organization = ?
        """, (org_name,)).fetchone()
        
        if not settings:
            db.execute("""
                INSERT INTO organization_settings (organization, ip, port, api_key)
                VALUES (?, ?, ?, ?)
            """, (org_name, ip, port, api_key))
        else:
            db.execute("""
                UPDATE organization_settings 
                SET ip = ?, port = ?, api_key = ?, updated_at = CURRENT_TIMESTAMP
                WHERE organization = ?
            """, (ip, port, api_key, org_name))
        
        db.commit()
        
        return json_response({
            "success": True,
            "message": "Settings updated successfully",
            "settings": {
                "ip": ip,
                "port": port,
                "api_key": api_key
            }
        }, 200)


@app.route("/api/organizations/<org_name>/change-role", methods=["POST"])
@org_admin_required
def api_change_user_role(org_name):
    db = get_db()
    
    data = request.get_json(silent=True) or {}
    
    user_id = data.get("user_id")
    new_role = data.get("new_role", "").strip()
    
    if not user_id or not new_role:
        return json_response({"error": "user_id and new_role are required"}), 400
    
    allowed_roles = ["user", "admin", "org_admin", "local_org_admin"]
    if new_role not in allowed_roles:
        return json_response({
            "error": f"Invalid role. Allowed roles: {', '.join(allowed_roles)}"
        }), 400
    
    user = db.execute(
        "SELECT id, username, role, organization FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()
    
    if not user:
        return json_response({"error": "User not found"}), 404
    
    if user["organization"] != org_name:
        return json_response({"error": "User does not belong to this organization"}), 400
    
    if user["id"] == g.current_user["user_id"]:
        return json_response({"error": "You cannot change your own role"}), 400
    
    current_user_role = g.current_user["role"]
    current_user_org = g.current_user["organization"]
    

    if current_user_role == "local_org_admin":
        if org_name != current_user_org:
            return json_response({"error": "You don't have permission to change roles in this organization"}), 403
        
        if new_role == "org_admin":
            return json_response({"error": "Local organization admin cannot assign org_admin role"}), 403
        
        if user["role"] == "org_admin":
            return json_response({"error": "Cannot change role of organization administrator"}), 403
    
    db.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
    db.commit()
    
    updated_user = db.execute(
        "SELECT id, username, role, organization, created_at FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()
    
    role_names = {
        "user": "user",
        "admin": "administrator",
        "org_admin": "organization administrator",
        "local_org_admin": "local organization administrator"
    }
    
    return json_response({
        "success": True,
        "message": f"Role of user '{user['username']}' changed to {role_names[new_role]}",
        "user": dict(updated_user)
    })



@app.route("/api/user/<int:user_id>", methods=["GET"])
@login_required
def api_user_profile(user_id):
    db = get_db()
    
    if user_id != g.current_user["user_id"]:
        return json_response({"error": "You can only view your own profile"}), 403
    
    user_info = db.execute("""
        SELECT id, username, role, organization, created_at 
        FROM users 
        WHERE id = ?
    """, (user_id,)).fetchone()
    
    if not user_info:
        return json_response({"error": "User not found"}), 404
    
    return json_response({
        "success": True,
        "user": dict(user_info),
    })

@app.route("/api/user/<int:user_id>/change_password", methods=["POST"])
@login_required
def api_change_password(user_id):
    if user_id != g.current_user["user_id"]:
        return json_response({"error": "You can only change your own password"}), 403
    
    data = request.get_json(silent=True) or {}
    
    current_password = data.get("current_password", "").strip()
    new_password = data.get("new_password", "").strip()
    confirm_password = data.get("confirm_password", "").strip()
    
    errors = []
    if not current_password:
        errors.append("current_password is required")
    if not new_password:
        errors.append("new_password is required")
    if not confirm_password:
        errors.append("confirm_password is required")
    
    if errors:
        return json_response({"error": "Validation failed", "details": errors}), 400
    
    if new_password != confirm_password:
        return json_response({"error": "New password and confirmation do not match"}), 400
    
    if len(new_password) < 6:
        return json_response({"error": "New password must be at least 6 characters"}), 400
    
    if not re.match(r'^[a-zA-Z0-9!@$_,.?]+$', new_password):
        return json_response({
            "error": "Password can only contain letters, numbers and special characters !@$_,.?"
        }), 400
    
    db = get_db()
    
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    
    if not user:
        return json_response({"error": "User not found"}), 404
    
    current_password_hash = hashlib.sha256(current_password.encode()).hexdigest()
    
    if user["password"] != current_password_hash:
        return json_response({"error": "Current password is incorrect"}), 401
    
    new_password_hash = hashlib.sha256(new_password.encode()).hexdigest()
    
    db.execute("UPDATE users SET password = ? WHERE id = ?", (new_password_hash, user_id))
    db.commit()
    
    return json_response({
        "success": True,
        "message": "Password changed successfully"
    })

def initialize_app():
    with app.app_context():
        try:
            logger.info("Initializing database...")
            init_db()
            logger.info("Database initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise

initialize_app()

if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(host="0.0.0.0", port=8080, debug=False)

