import os
import re
import uuid
import sqlite3
import random
import string
import subprocess
import tempfile
import shutil
import smtplib
import hashlib, secrets
from datetime import datetime, timedelta
from flask import request, session, redirect, url_for
from functools import wraps
from flask import flash, redirect, url_for
from flask import Flask

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from flask import (
    Flask, render_template, request, redirect, url_for, session,
    g, flash, send_file, abort, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix   
from dotenv import load_dotenv
load_dotenv()
from flask_babel import Babel, gettext
from flask_wtf import CSRFProtect
# ====================================================
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY') or ('change-me-' + secrets.token_hex(16))

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1)

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = True

CSRF protection
csrf = CSRFProtect(app)

@app.after_request
def add_security_headers(response):
    # Content Security Policy
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://static.cloudflareinsights.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "font-src 'self' data: https://fonts.gstatic.com https://cdn.jsdelivr.net; "
        "img-src 'self' data: blob:; "
        "frame-ancestors 'none'; "
    )

    # Clickjacking protection
    response.headers["X-Frame-Options"] = "DENY"

    # MIME sniffing protection
    response.headers["X-Content-Type-Options"] = "nosniff"

    # HSTS - HTTPS enforcement (خليه في البروود فقط)
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"

    # Referrer policy ✅ تسمح بالـ Referer داخل نفس الدومين باش CSRF يخدم
    # تقدر تستعمل "same-origin" برك لو تحب تكون أكثر تشدد
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Permissions policy
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

    # Cache control
    response.headers.setdefault("Cache-Control", "no-store")

    return response

# ==================== Gmail SMTP (App Password) ====================

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_USER = os.getenv("EMAIL_USER")      # مثال: yaziduniversity@gmail.com
EMAIL_PASS = os.getenv("EMAIL_PASS")      # كلمة مرور التطبيق من Google
FROM_EMAIL = os.getenv("FROM_EMAIL", EMAIL_USER)


def send_email(to_email: str, subject: str, html_body: str, text_body: str | None = None) -> bool:
    """
    إرسال بريد عبر Gmail SMTP.
    يرجع True إذا تم الإرسال بنجاح، وإلا False.
    """
    if not EMAIL_USER or not EMAIL_PASS:
        print("❌ إعدادات Gmail ناقصة (EMAIL_USER / EMAIL_PASS).")
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["From"] = FROM_EMAIL or EMAIL_USER
        msg["To"] = to_email
        msg["Subject"] = subject
        msg["Reply-To"] = EMAIL_USER  

        if text_body:
            msg.attach(MIMEText(text_body, "plain", "utf-8"))
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        print(f"🌐 الاتصال بـ Gmail SMTP على {SMTP_SERVER}:{SMTP_PORT} ...")
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=20)
        server.set_debuglevel(1)  
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(EMAIL_USER, EMAIL_PASS)
        print("✅ تم تسجيل الدخول بنجاح على Gmail SMTP.")

        server.sendmail(msg["From"], [to_email], msg.as_string())
        server.quit()
        print(f"📧 تم إرسال البريد بنجاح إلى {to_email}")
        return True

    except smtplib.SMTPAuthenticationError as e:
        print("❌ خطأ في المصادقة (تأكد من App Password في Gmail):", e)
    except smtplib.SMTPConnectError as e:
        print("❌ فشل الاتصال بخادم Gmail SMTP:", e)
    except smtplib.SMTPException as e:
        print("⚠️ خطأ SMTP:", e)
    except Exception as e:
        print("⚠️ خطأ غير متوقع أثناء الإرسال:", e)

    return False

# ---------------- Charger l'environnement ----------------
DB = os.getenv('DB_PATH', 'data.db')
SECRET_KEY = os.getenv('SECRET_KEY') or 'change-me-' + secrets.token_hex(16)
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD') or 'admin1234'

# ---------------- Application Flask ----------------

app.secret_key = SECRET_KEY
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'videos')
app.config['HLS_FOLDER'] = os.path.join('static', 'videos_hls')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['HLS_FOLDER'], exist_ok=True)

# ---------------- Nettoyage automatique des anciens fichiers HLS ----------------
import threading, time, shutil

def cleanup_old_hls(max_age_seconds=86400):
    """🧹 Supprimer les anciens fichiers HLS (plus d'une heure)."""
    while True:
        try:
            now = time.time()
            for folder in os.listdir(app.config['HLS_FOLDER']):
                path = os.path.join(app.config['HLS_FOLDER'], folder)
                if os.path.isdir(path) and now - os.path.getmtime(path) > max_age_seconds:
                    shutil.rmtree(path, ignore_errors=True)
                    print(f"🧹 Suppression HLS expiré: {path}")
        except Exception as e:
            print("⚠️ Erreur nettoyage HLS:", e)
        time.sleep(3600)  # répéter chaque heure

# 🔄 lancer le thread de nettoyage
#threading.Thread(target=cleanup_old_hls, daemon=True).start()

# ---------------- Flask-Babel ----------------
app.config['BABEL_DEFAULT_LOCALE'] = 'fr'
app.config['BABEL_TRANSLATION_DIRECTORIES'] = 'translations'

def get_locale():
    lang = request.args.get('lang')
    if lang in ['ar', 'en', 'fr']:
        session['lang'] = lang
    return session.get('lang', 'fr')

babel = Babel(app, locale_selector=get_locale)

# Make get_locale available in templates
@app.context_processor
def inject_get_locale():
    return dict(get_locale=get_locale)

@app.context_processor
def inject_user():
    user = None
    if 'user_id' in session:
        try:
            db = get_db()
            user = db.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()
        except Exception:
            user = None
    return dict(user=user)
    
# ---------------- Base de données ----------------

load_dotenv()

DB = os.path.join(os.path.dirname(__file__), "data.db")

def get_db():
    """Connexion à la base de données"""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DB)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    """Fermeture propre de la connexion DB"""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    """Initialisation complète de la base de données"""
    con = sqlite3.connect(DB)
    cur = con.cursor()

    # ✅ Table: Users (avec contraintes UNIQUE sur email et phone)
    cur.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        first_name TEXT,
        last_name TEXT,
        email TEXT UNIQUE,              -- ✅ adresse e-mail unique
        phone TEXT UNIQUE,              -- ✅ numéro de téléphone unique
        birth_date TEXT,
        password TEXT NOT NULL,
        activated INTEGER DEFAULT 0,
        expiry_date TEXT,
        device_hash TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    # ✅ Index supplémentaire pour accélérer la recherche par username
    cur.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')

    # ✅ Table: Codes
    cur.execute('''CREATE TABLE IF NOT EXISTS codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT UNIQUE NOT NULL,
        duration_days INTEGER DEFAULT 365,
        used INTEGER DEFAULT 0,
        used_by INTEGER
    )''')

    # ✅ Table: Logs
    cur.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        event TEXT,
        ip TEXT,
        device_info TEXT,
        time TEXT
    )''')

    # ✅ Table: Videos 
    cur.execute('''CREATE TABLE IF NOT EXISTS videos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        filename TEXT NOT NULL,
        formation_name TEXT,
        formation_id INTEGER,
        description TEXT
    )''')

    # ✅ Table: Reviews
    cur.execute('''CREATE TABLE IF NOT EXISTS reviews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        rating INTEGER NOT NULL,
        comment TEXT NOT NULL,
        time TEXT
    )''')

    # ✅ Table: Reset requests
    cur.execute('''CREATE TABLE IF NOT EXISTS reset_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        reason TEXT,
        status TEXT DEFAULT 'pending',
        temp_password TEXT,
        admin_note TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    # ✅ Table: Formations
    cur.execute('''CREATE TABLE IF NOT EXISTS formations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        titre TEXT NOT NULL,
        description TEXT,
        prix TEXT NOT NULL,
        image TEXT,
        domaine TEXT,
        niveau TEXT,
        specialite TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    # ✅ Table: Orders (liée aux formations)
    cur.execute('''CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        produit TEXT,
        total REAL,
        status TEXT DEFAULT 'en attente',
        payment_mode TEXT,
        proof TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')

    # ✅ Table: Contact messages
    cur.execute('''CREATE TABLE IF NOT EXISTS contact_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        phone TEXT NOT NULL,
        message TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    # ✅ Table: Password resets
    cur.execute('''CREATE TABLE IF NOT EXISTS password_resets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')

    # ✅ Table: Commentaires (nouvelle table permanente)
    cur.execute('''CREATE TABLE IF NOT EXISTS commentaires (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        contenu TEXT NOT NULL,
        note INTEGER NOT NULL,
        date_created TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')

    con.commit()
    con.close()
    print("✅ Toutes les tables ont été vérifiées / créées avec succès !")


# ✅ Création automatique de la base si elle n’existe pas
if not os.path.exists(DB):
    init_db()
else:
    # 🔁 Vérifier la colonne "domaine" dans formations
    con = sqlite3.connect(DB)
    cur = con.cursor()

    # 🔍 Vérif domaine
    columns = [c[1] for c in cur.execute("PRAGMA table_info(formations);").fetchall()]
    if 'domaine' not in columns:
        try:
            cur.execute("ALTER TABLE formations ADD COLUMN domaine TEXT DEFAULT 'Universitaire';")
            con.commit()
            print("✅ Colonne 'domaine' ajoutée automatiquement.")
        except Exception as e:
            print("⚠️ Erreur lors de l’ajout de 'domaine':", e)
            
    # 🔍 Vérif formation_id + description dans videos
    columns_videos = [c[1] for c in cur.execute("PRAGMA table_info(videos);").fetchall()]

    if 'formation_id' not in columns_videos:
        try:
            cur.execute("ALTER TABLE videos ADD COLUMN formation_id INTEGER;")
            con.commit()
            print("✅ Colonne 'formation_id' ajoutée automatiquement à la table 'videos'.")
        except Exception as e:
            print("⚠️ Erreur lors de l’ajout de 'formation_id' dans 'videos':", e)

    if 'description' not in columns_videos:
        try:
            cur.execute("ALTER TABLE videos ADD COLUMN description TEXT;")
            con.commit()
            print("✅ Colonne 'description' ajoutée automatiquement à la table 'videos'.")
        except Exception as e:
            print("⚠️ Erreur lors de l’ajout de 'description' dans 'videos':", e)

    # 🔍 Vérif formation_id dans codes
    columns_codes = [c[1] for c in cur.execute("PRAGMA table_info(codes);").fetchall()]
    if 'formation_id' not in columns_codes:
        try:
            cur.execute("ALTER TABLE codes ADD COLUMN formation_id INTEGER;")
            con.commit()
            print("✅ Colonne 'formation_id' ajoutée automatiquement à la table 'codes'.")
        except Exception as e:
            print("⚠️ Erreur lors de l’ajout de 'formation_id' dans 'codes':", e)

    # 🔍 Vérif formation_id dans orders (🔧 correction finale)
    columns_orders = [c[1] for c in cur.execute("PRAGMA table_info(orders);").fetchall()]
    if 'formation_id' not in columns_orders:
        try:
            cur.execute("ALTER TABLE orders ADD COLUMN formation_id INTEGER;")
            con.commit()
            print("✅ Colonne 'formation_id' ajoutée automatiquement à la table 'orders'.")
        except Exception as e:
            print("⚠️ Erreur lors de l’ajout de 'formation_id' dans 'orders':", e)

    con.close()


# ✅ Vérifier / créer la table des commentaires à chaque démarrage
def ensure_commentaires_table():
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS commentaires (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            contenu TEXT NOT NULL,
            note INTEGER NOT NULL,
            date_created TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    con.commit()
    con.close()
    print("✅ Table 'commentaires' vérifiée / créée.")

ensure_commentaires_table()

# ---------------- Utilitaires ----------------
def make_code():
    """Generate a random code like ABCD-1234-EFGH"""
    alphabet = string.ascii_uppercase + string.digits
    return '-'.join(''.join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3))


def get_device_hash():
    """
    Generate a unique and persistent device fingerprint.
    It combines User-Agent, IP address, and a UUID stored in cookies.
    Ensures that each account is tied to exactly one device/browser.
    """
    cookie_hash = request.cookies.get('device_hash')
    if cookie_hash:
        return cookie_hash

    ua = request.headers.get('User-Agent', 'unknown').strip().lower()
    ip = request.remote_addr or "0.0.0.0"
    unique_seed = f"{ua}-{ip}-{uuid.uuid4()}"
    device_hash = hashlib.sha256(unique_seed.encode()).hexdigest()
    return device_hash


def login_required(f):
    """Ensure that a user is logged in"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Ensure that an admin is logged in"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('is_admin'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated


def check_user_expired(user):
    """Check if a user's account has expired"""
    if not user:
        return True

    expiry = None
    if 'expiry_date' in user.keys():
        expiry = user['expiry_date']

    if expiry:
        try:
            return datetime.utcnow() > datetime.fromisoformat(expiry)
        except Exception as e:
            print(f"⚠️ Error parsing expiry date: {e}")
            return False

    return False
    
# ---------------- Mot de passe oublié (avec code email) ----------------
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    db = get_db()
    step = None
    email = None

    # Étape 1 : saisie de l'email
    if request.method == 'POST' and 'email' in request.form and 'code' not in request.form and 'new_password' not in request.form:
        email = request.form['email']
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        if not user:
            flash("❌ Aucun compte trouvé avec cet email.", "danger")
            return render_template('forgot_password.html')

        # Générer un code à 6 chiffres
        code = ''.join(secrets.choice("0123456789") for _ in range(6))
        expires = (datetime.now() + timedelta(minutes=10)).isoformat()

        # Sauvegarder le code
        db.execute('INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)',
                   (user['id'], code, expires))
        db.commit()

        # ✅ Envoi du code par email via Gmail SMTP
        subject = "🔐 Code de vérification - Réinitialisation du mot de passe"
        html_body = f"""
        <h2>Bonjour {user['username']},</h2>
        <p>Voici votre code de vérification :</p>
        <h1 style="color:#2d6a4f;">{code}</h1>
        <p>Ce code expirera dans 10 minutes.</p>
        <p>— L'équipe Yazid University</p>
        """

        if send_email(email, subject, html_body):
            flash("📩 Code envoyé à votre email.", "success")
            return render_template('forgot_password.html', step='verify', email=email)
        else:
            flash("⚠️ Erreur lors de l'envoi de l'email (Gmail SMTP).", "danger")

    # Étape 2 : vérification du code
    if request.method == 'POST' and 'code' in request.form:
        email = request.form['email']
        code = request.form['code']
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

        reset = db.execute('SELECT * FROM password_resets WHERE user_id=? AND token=?',
                           (user['id'], code)).fetchone()
        if not reset:
            flash("❌ Code invalide.", "danger")
            return render_template('forgot_password.html', step='verify', email=email)

        expires = datetime.fromisoformat(reset['expires_at'])
        if datetime.now() > expires:
            flash("⏰ Code expiré. Veuillez recommencer.", "warning")
            db.execute('DELETE FROM password_resets WHERE id=?', (reset['id'],))
            db.commit()
            return render_template('forgot_password.html')

        flash("✅ Code vérifié avec succès.", "success")
        return render_template('forgot_password.html', step='reset', email=email)

    # Étape 3 : saisie du nouveau mot de passe
    if request.method == 'POST' and 'new_password' in request.form:
        email = request.form['email']
        new_password = request.form['new_password']
        hashed = generate_password_hash(new_password)

        db.execute('UPDATE users SET password=? WHERE email=?', (hashed, email))
        db.execute('DELETE FROM password_resets WHERE user_id=(SELECT id FROM users WHERE email=?)', (email,))
        db.commit()

        flash("✅ Mot de passe réinitialisé avec succès.", "success")
        return redirect(url_for('login'))

    return render_template('forgot_password.html', step=step, email=email)
    
# ---------------- Réinitialisation directe du mot de passe ----------------
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    db = get_db()
    email = request.args.get('email') or request.form.get('email')

    if not email:
        flash("❌ L'adresse e-mail est manquante.", "danger")
        return redirect(url_for('forgot_password'))

    # Étape : formulaire de nouveau mot de passe
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not new_password or not confirm_password:
            flash("⚠️ Veuillez remplir tous les champs.", "warning")
            return render_template('reset_password.html', email=email)

        if new_password != confirm_password:
            flash("❌ Les mots de passe ne correspondent pas.", "danger")
            return render_template('reset_password.html', email=email)

        if len(new_password) < 6:
            flash("⚠️ Le mot de passe doit contenir au moins 6 caractères.", "warning")
            return render_template('reset_password.html', email=email)

        hashed = generate_password_hash(new_password)
        db.execute('UPDATE users SET password=? WHERE email=?', (hashed, email))
        db.execute('DELETE FROM password_resets WHERE user_id=(SELECT id FROM users WHERE email=?)', (email,))
        db.commit()

        flash("✅ Mot de passe réinitialisé avec succès.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html', email=email)
    
# ---------------- Avis ------------------------------------------------------------------
def get_reviews():
    db = get_db()
    rows = db.execute('''
        SELECT r.*, u.username 
        FROM reviews r 
        JOIN users u ON u.id = r.user_id
        ORDER BY r.id DESC
    ''').fetchall()
    return rows

# ---------------- Contact ----------------
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    db = get_db()
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        message = request.form.get('message', '').strip()

        email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        phone_regex = r'^(05|06|07)\d{8}$'

        if not name or not email or not phone or not message:
            flash(gettext("Tous les champs sont obligatoires."), 'error')
        elif not re.match(email_regex, email):
            flash(gettext("L'adresse e-mail n'est pas valide."), 'error')
        elif not re.match(phone_regex, phone):
            flash(gettext("Le numéro de téléphone doit être algérien valide (05, 06 ou 07 + 8 chiffres)."), 'error')
        elif len(message) < 10:
            flash(gettext("Le message est trop court."), 'error')
        else:
            db.execute(
                'INSERT INTO contact_messages (name, email, phone, message) VALUES (?, ?, ?, ?)',
                (name, email, phone, message)
            )
            db.commit()
            flash(gettext("Votre message a été envoyé avec succès !"), 'success')
            return redirect(url_for('contact'))

    return render_template('contact.html')
    
# ---------------- À Propos ----------------
@app.route("/apropos")
def apropos():
    return render_template("apropos.html")

# ---------------- Nos Services ----------------
@app.route('/services')
def services():
    return render_template('services.html')
    
# ---------------- Notre Équipe ----------------
@app.route('/team')
def team():
    return render_template('team.html')
    
    
# ---------------- Routes utilisateur ----------------

@app.route('/dashboard')
@login_required
def dashboard():
    """Espace personnel de l'utilisateur connecté"""
    db = get_db()

    user = db.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()
    if not user:
        session.clear()
        flash(gettext("Utilisateur introuvable"))
        return redirect(url_for('login'))

    # Vérifier si le compte est expiré
    expired = check_user_expired(user)
    session['is_verified'] = bool(user['activated'] and not expired)

    expiry_display = None
    if user['expiry_date']:
        try:
            expiry_display = datetime.fromisoformat(user['expiry_date']).strftime('%Y-%m-%d %H:%M:%S')
        except:
            expiry_display = None

    reviews = get_reviews()
    show_activate = not user['activated'] or expired

    if show_activate:
        return redirect(url_for('activate'))

    videos = []
    if user['activated'] and not expired:
        videos = db.execute('SELECT * FROM videos ORDER BY id DESC').fetchall()

    can_access_content = user['activated'] and not expired

    return render_template(
        'dashboard.html',
        user=user,
        expired=expired,
        expiry_display=expiry_display,
        show_activate=show_activate,
        reviews=reviews,
        videos=videos,
        can_access_content=can_access_content
    )

@app.route('/')
def index():
    """Page d'accueil principale du site (avec les formations et les avis récents)"""
    db = get_db()

    formations = db.execute("""
        SELECT id, titre, description, prix, image
        FROM formations
        ORDER BY id DESC
        LIMIT 10
    """).fetchall()

    recent_reviews = db.execute("""
        SELECT c.contenu, c.note, u.username
        FROM commentaires c
        JOIN users u ON c.user_id = u.id
        ORDER BY c.id DESC
    """).fetchall()
    
    return render_template('index.html', formations=formations, recent_reviews=recent_reviews)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()

        if user and check_password_hash(user['password'], password):
            device_hash = get_device_hash()

            # Enforce single-device access
            if user['activated']:
                # First login on this account → register the current device
                if not user['device_hash']:
                    db.execute('UPDATE users SET device_hash=? WHERE id=?', (device_hash, user['id']))
                    db.commit()

                # Already linked to another device → block access
                elif user['device_hash'] != device_hash:
                    flash("🚫 This account is already linked to another device.", "error")
                    return redirect(url_for('login'))

            # Successful login
            session['user_id'] = user['id']
            flash("Login successful ✅")

            resp = redirect(url_for('index'))
            # Cookie valid for one year
            resp.set_cookie('device_hash', device_hash, max_age=60 * 60 * 24 * 365, httponly=True, samesite='Lax')

            # Log the login attempt
            try:
                db.execute(
                    "INSERT INTO logs (user_id, event, ip, device_info, time) VALUES (?, ?, ?, ?, ?)",
                    (
                        user['id'],
                        'login',
                        request.remote_addr,
                        request.headers.get('User-Agent', 'unknown'),
                        datetime.now().isoformat(),
                    ),
                )
                db.commit()
            except Exception as e:
                print("⚠️ Error while saving login log:", e)

            return resp

        else:
            flash("Invalid username or password.", "error")

    return render_template('login.html')


@app.route('/logout')
def logout():
    resp = redirect(url_for('index'))
    session.clear()
    flash("Logout successful.")
    return resp
    
# ---------------- Inscription stricte avec vérification par e-mail ----------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    db = get_db()

    # 🧩 Étape 1 : formulaire d'inscription
    if request.method == 'POST' and 'code' not in request.form:
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        email = request.form.get('email', '').strip().lower()
        phone = request.form.get('phone', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        # -------------------------------
        # 🧩 Vérifications côté serveur
        # -------------------------------
        if not all([first_name, last_name, email, username, password, confirm_password]):
            flash("⚠️ Tous les champs marqués * doivent être remplis.", "error")
            return render_template('register.html')

        if password != confirm_password:
            flash("❌ Les mots de passe ne correspondent pas.", "error")
            return render_template('register.html')

        if len(password) < 6 or not any(c.isdigit() for c in password):
            flash("⚠️ Le mot de passe doit contenir au moins 6 caractères et un chiffre.", "error")
            return render_template('register.html')

        import re
        email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if not re.match(email_regex, email):
            flash("❌ L'adresse e-mail n'est pas valide.", "error")
            return render_template('register.html')

        if phone:
            phone_regex = r'^(05|06|07)\d{8}$'
            if not re.match(phone_regex, phone):
                flash("⚠️ Le numéro de téléphone doit être algérien valide (05, 06 ou 07 + 8 chiffres).", "error")
                return render_template('register.html')

        # -------------------------------
        # 🚫 Vérifier les doublons
        # -------------------------------
        existing_user = db.execute(
            "SELECT * FROM users WHERE username = ? OR email = ? OR (phone = ? AND phone != '')",
            (username, email, phone)
        ).fetchone()

        if existing_user:
            if existing_user['username'] == username:
                flash("❌ Ce nom d'utilisateur est déjà pris.", "error")
            elif existing_user['email'] == email:
                flash("❌ Cet e-mail est déjà enregistré.", "error")
            elif existing_user['phone'] == phone:
                flash("❌ Ce numéro de téléphone est déjà utilisé.", "error")
            else:
                flash("❌ Les informations fournies existent déjà.", "error")
            return render_template('register.html')

        # -------------------------------
        # ✅ Sauvegarde temporaire dans la session
        # -------------------------------
        session['pending_user'] = {
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'phone': phone,
            'username': username,
            'password': generate_password_hash(password)
        }

        # Générer un code aléatoire à 6 chiffres
        code = ''.join(secrets.choice("0123456789") for _ in range(6))
        session['verify_code'] = code
        session['verify_expire'] = (datetime.now() + timedelta(minutes=10)).isoformat()

        # Envoyer le code par e-mail
        subject = "📧 Vérification de votre compte - Yazid University"
        html_body = f"""
        <h2>Bienvenue {first_name} 👋</h2>
        <p>Voici votre code de vérification :</p>
        <h1 style='color:#2d6a4f;'>{code}</h1>
        <p>Ce code expirera dans 10 minutes.</p>
        <p>— L'équipe Yazid University</p>
        """

        if send_email(email, subject, html_body):
            flash("📩 Un code a été envoyé à votre e-mail pour vérification.", "success")
            return render_template('verify_email.html', email=email)
        else:
            flash("⚠️ Erreur lors de l'envoi du mail de vérification.", "danger")
            return render_template('register.html')

    # 🧩 Étape 2 : vérification du code reçu
    if request.method == 'POST' and 'code' in request.form:
        email = request.form.get('email', '').strip()
        code = request.form.get('code', '').strip()
        expected = session.get('verify_code')
        expire = session.get('verify_expire')

        if not expected or datetime.now() > datetime.fromisoformat(expire):
            flash("⏰ Code expiré. Veuillez recommencer l'inscription.", "warning")
            session.pop('pending_user', None)
            return redirect(url_for('register'))

        if code != expected:
            flash("❌ Code de vérification incorrect.", "danger")
            return render_template('verify_email.html', email=email)

        # ✅ Création du compte dans la base
        data = session.pop('pending_user', None)
        if not data:
            flash("⚠️ Aucune donnée trouvée. Veuillez recommencer.", "danger")
            return redirect(url_for('register'))

        try:
            db.execute("""
                INSERT INTO users (username, password, first_name, last_name, email, phone, activated)
                VALUES (?, ?, ?, ?, ?, ?, 0)
            """, (data['username'], data['password'], data['first_name'],
                  data['last_name'], data['email'], data['phone']))
            db.commit()

            session.pop('verify_code', None)
            session.pop('verify_expire', None)
            flash("✅ Compte créé et vérifié avec succès ! Vous pouvez maintenant vous connecter.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            print("❌ Erreur SQL:", e)
            flash("⚠️ Une erreur s'est produite lors de la création du compte.", "danger")
            return redirect(url_for('register'))

    return render_template('register.html')

# ---------------- Activation du compte (avec formation_id + debug) ----------------
@app.route('/activate', methods=['GET', 'POST'])
@login_required
def activate():
    """Active le compte utilisateur et attribue automatiquement la formation liée au code saisi."""
    print("🚀 activate CALLED")  # Debug 1
    db = get_db()
    user_id = session['user_id']
    user = db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()

    if not user:
        print("❌ Utilisateur introuvable")  # Debug 2
        flash("❌ Utilisateur introuvable.", "error")
        return redirect(url_for('dashboard'))

    # ✅ Afficher simplement la page si c’est une requête GET
    if request.method == 'GET':
        return render_template('activate.html')

    # 🔹 POST → traitement du code
    code_input = request.form.get('code', '').strip().upper()
    print("🔹 Code saisi:", code_input)  # Debug 3

    if not code_input:
        flash("⚠️ Veuillez saisir un code d’activation.", "warning")
        return redirect(url_for('activate'))

    code_row = db.execute('SELECT * FROM codes WHERE code=? AND used=0', (code_input,)).fetchone()
    print("📦 Code trouvé:", code_row)  # Debug 4

    if not code_row:
        flash("❌ Code invalide ou déjà utilisé.", "error")
        return redirect(url_for('activate'))

    expiry = datetime.utcnow() + timedelta(days=code_row['duration_days'])
    db.execute('UPDATE users SET activated=1, expiry_date=? WHERE id=?',
               (expiry.isoformat(), user['id']))
    db.execute('UPDATE codes SET used=1, used_by=? WHERE id=?',
               (user['id'], code_row['id']))
    print("✅ User activé et code marqué utilisé")  # Debug 5

    formation_id = code_row['formation_id'] if 'formation_id' in code_row.keys() else None
    print("🎓 formation_id:", formation_id)  # Debug 6

    # 🔧 Vérification et conversion du formation_id
    if formation_id:
        try:
            formation_id = int(formation_id)
        except:
            formation_id = None

    if formation_id:
        formation = db.execute('SELECT * FROM formations WHERE id=?', (formation_id,)).fetchone()
        print("📘 Formation trouvée:", formation)  # Debug 7
        if formation:
            already = db.execute(
                'SELECT 1 FROM orders WHERE user_id=? AND formation_id=? AND status="validé"',
                (user['id'], formation_id)
            ).fetchone()
            print("🔍 Déjà existant:", already)  # Debug 8

            if not already:
                db.execute('''
                    INSERT INTO orders (user_id, produit, total, status, created_at, formation_id)
                    VALUES (?, ?, ?, 'validé', ?, ?)
                ''', (
                    user['id'],
                    formation['titre'],
                    formation['prix'],
                    datetime.utcnow().isoformat(),
                    formation_id
                ))
                print("🆕 INSERT OK dans orders")  # Debug 9
                flash(f"✅ Compte activé et formation '{formation['titre']}' ajoutée avec succès !", "success")
            else:
                flash(f"ℹ️ Ce code correspond à la formation '{formation['titre']}' que vous possédez déjà.", "info")
        else:
            print("⚠️ Formation liée introuvable.")  # Debug 10
            flash("⚠️ Formation liée introuvable en base de données.", "warning")
    else:
        print("ℹ️ Aucun formation_id dans le code.")  # Debug 11
        flash("✅ Compte activé avec succès.", "success")

    db.commit()
    print("💾 Commit effectué")  # Debug 12
    return redirect(url_for('my_formations'))

# ---------------- Mes Formations ----------------
@app.route('/my_formations')
@login_required
def my_formations():
    db = get_db()
    user_id = session['user_id']
    user = db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()

    expired = check_user_expired(user)
    activated = user['activated'] and not expired

    if not activated:
        flash("⚠️ Votre compte n'est pas encore activé. Veuillez saisir votre code d'activation.", "warning")
        return redirect(url_for('activate'))

    formations = db.execute("""
        SELECT DISTINCT f.*
        FROM formations f
        JOIN orders o
          ON (o.formation_id = f.id)
          OR (o.formation_id IS NULL AND o.produit = f.titre)
        WHERE o.user_id = ?
          AND o.status = 'validé'
        ORDER BY f.id DESC
    """, (user_id,)).fetchall()

    def _norm(x):
        return (x or '').strip().lower()

    formations_univ = [f for f in formations if _norm(f['domaine']) == 'universitaire']
    formations_bac  = [f for f in formations if _norm(f['domaine']) == 'bac']

    formation_ids = [f['id'] for f in formations]
    videos = []
    if formation_ids:
        placeholders = ",".join("?" for _ in formation_ids)
        videos = db.execute(f"""
            SELECT v.*, f.titre AS formation_titre
            FROM videos v
            JOIN formations f ON f.id = v.formation_id
            WHERE v.formation_id IN ({placeholders})
            ORDER BY v.id DESC
        """, formation_ids).fetchall()

    return render_template(
        'my_formations.html',
        activated=True,
        formations=formations,
        formations_univ=formations_univ,
        formations_bac=formations_bac,
        videos=videos
    )

# ---------------- HLS creation with dynamic professional watermark ----------------
def create_hls_with_watermark(video_path, user_name, user_phone, out_hls_folder):
    import subprocess, os

    os.makedirs(out_hls_folder, exist_ok=True)
    ffmpeg_path = r"C:\ffmpeg\bin\ffmpeg.exe"


    safe_name = (user_name or "Utilisateur").replace("'", "").replace('"', "").replace(":", "")
    safe_phone = (user_phone or "").replace("'", "").replace('"', "").replace(":", "")
    watermark_text = f"{safe_name} - {safe_phone}" if safe_phone else safe_name


    font_path = "C\\:/Windows/Fonts/arial.ttf"
    if not os.path.isfile(font_path.replace("\\:/", ":/")):
        font_path = "C\\:/Windows/Fonts/tahoma.ttf"

    watermark_text = watermark_text.encode("utf-8", errors="ignore").decode("utf-8")


    drawtext = (
        f"drawtext=fontfile='{font_path}':"
        f"text='{watermark_text}':"
        "fontsize=30:"
        "fontcolor=white@0.25:"  
        "box=1:boxcolor=black@0.15:boxborderw=5:"  
        "x=(w-text_w)/2:"  
        "y=(h-text_h)/2 + (h/3)*sin(2*PI*t/5)"  
    )

    cmd = [
        ffmpeg_path, "-y",
        "-i", video_path,
        "-vf", drawtext,
        "-c:v", "libx264",
        "-preset", "veryfast",
        "-crf", "23",
        "-c:a", "aac",
        "-b:a", "128k",
        "-f", "hls",
        "-hls_time", "6",
        "-hls_playlist_type", "vod",
        "-hls_segment_filename", os.path.join(out_hls_folder, "seg_%03d.ts"),
        os.path.join(out_hls_folder, "index.m3u8"),
    ]

    print("🔹 Commande FFmpeg:", " ".join(cmd))


    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
    print(result.stderr)


    if result.returncode == 0:
        print(f"✅ HLS créé avec succès : {out_hls_folder}/index.m3u8")
        return True
    else:
        print("❌ Erreur FFmpeg:", result.stderr)
        return False

# ---------------- Route principale ----------------
@app.route('/video/<int:vid>')
@login_required
def play_video(vid):
    """Retourne le lien HLS (JSON) au lieu du HTML — pour lecture directe dans le modal."""
    db = get_db()
    video = db.execute('SELECT * FROM videos WHERE id=?', (vid,)).fetchone()
    user = db.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()

    if not video or not user:
        return jsonify({"error": "Vidéo introuvable"}), 404

    hls_base_folder = os.path.join(app.config['HLS_FOLDER'], f"{vid}_{user['id']}")
    os.makedirs(hls_base_folder, exist_ok=True)
    playlist_path = os.path.join(hls_base_folder, "index.m3u8")

    if not os.path.exists(playlist_path):
        video_path = os.path.join(app.config['UPLOAD_FOLDER'], video['filename'])
        success = create_hls_with_watermark(
            video_path,
            f"{user['first_name']} {user['last_name']}",
            user['phone'] or "",
            hls_base_folder
        )
        if not success:
            return jsonify({"error": "Erreur lors de la génération du flux HLS"}), 500

    playlist_url = url_for(
        "stream_hls",
        vid=vid,
        folder=os.path.basename(hls_base_folder),
        filename="index.m3u8",
    )

    return jsonify({"playlist_url": playlist_url})


# ---------------- Route لبث ملفات HLS ----------------
@app.route("/stream_hls/<int:vid>/<folder>/<filename>")
def stream_hls(vid, folder, filename):
    """Diffuse les fichiers HLS (.m3u8 ou .ts) depuis le dossier généré dynamiquement."""
    from flask import send_from_directory
    base_path = os.path.join("static", "videos_hls", folder)
    file_path = os.path.join(base_path, filename)

    if not os.path.exists(file_path):
        print(f"⚠️ Fichier introuvable : {file_path}")
        return f"❌ Fichier introuvable : {filename}", 404

    return send_from_directory(base_path, filename)

# ---------------- Espace administrateur ----------------
import pyotp

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        password = request.form.get('password', '')
        if password == ADMIN_PASSWORD:

            session['admin_temp_auth'] = True
            return redirect(url_for('admin_verify_2fa'))
        else:
            flash("❌ Mot de passe incorrect", "error")
    return render_template('admin_login.html')

@app.route('/admin/logout')
@admin_required
def admin_logout():
    session.pop('is_admin', None)
    flash(gettext("Déconnexion de l'administrateur réussie"))
    return redirect(url_for('admin_login'))


@app.route('/admin')
@admin_required
def admin_panel():
    """Panneau d'administration principal"""
    db = get_db()

    users = db.execute('SELECT * FROM users ORDER BY id DESC').fetchall()
    codes = db.execute('SELECT * FROM codes ORDER BY id DESC').fetchall()
    vids = db.execute('SELECT * FROM videos ORDER BY id DESC').fetchall()
    reset_requests = db.execute(
        'SELECT r.*, u.username FROM reset_requests r LEFT JOIN users u ON u.id=r.user_id ORDER BY r.id DESC'
    ).fetchall()
    formations = db.execute('SELECT * FROM formations ORDER BY id DESC').fetchall()
    messages = db.execute('SELECT * FROM contact_messages ORDER BY id DESC').fetchall()
    orders = db.execute('''
        SELECT o.*, u.username, u.email, u.phone
        FROM orders o
        LEFT JOIN users u ON o.user_id = u.id
        ORDER BY o.id DESC
    ''').fetchall()
    

    commentaires = db.execute('SELECT * FROM commentaires ORDER BY id DESC').fetchall()


    return render_template(
        'admin_panel.html',
        users=users,
        codes=codes,
        vids=vids,
        reset_requests=reset_requests,
        formations=formations,
        messages=messages,
        orders=orders,
        commentaires=commentaires  
    )

@app.route('/admin/add_formation', methods=['POST'])
@admin_required
def admin_add_formation():
    """Ajouter une nouvelle formation (Universitaire ou BAC)"""
    db = get_db()
    titre = request.form.get('titre', '').strip()
    description = request.form.get('description', '').strip()
    prix = request.form.get('prix', '').strip()
    image_file = request.files.get('image')
    domaine = request.form.get('domaine', 'Universitaire').strip()  

    if not titre or not prix or not image_file:
        flash("Veuillez remplir tous les champs obligatoires.", "error")
        return redirect(url_for('admin_panel'))

    image_name = f"formations/{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{image_file.filename}"
    image_path = os.path.join('static', image_name)
    os.makedirs(os.path.dirname(image_path), exist_ok=True)
    image_file.save(image_path)

    db.execute(
        'INSERT INTO formations (titre, description, prix, image, domaine) VALUES (?, ?, ?, ?, ?)',
        (titre, description, prix, image_name, domaine)
    )
    db.commit()

    flash(f"Formation ajoutée avec succès dans la section {domaine}.", "success")
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete_formation/<int:fid>', methods=['POST'])
@admin_required
def admin_delete_formation(fid):
    """Supprimer une formation"""
    db = get_db()
    f = db.execute('SELECT * FROM formations WHERE id=?', (fid,)).fetchone()
    if not f:
        flash("Formation introuvable.", "error")
        return redirect(url_for('admin_panel'))

    image_path = os.path.join('static', f['image'])
    if os.path.exists(image_path):
        os.remove(image_path)

    db.execute('DELETE FROM formations WHERE id=?', (fid,))
    db.commit()
    flash("Formation supprimée avec succès.", "success")
    return redirect(url_for('admin_panel'))


# ---------------- Génération de codes d’activation liés à une formation ----------------
@app.route('/admin/gen', methods=['POST'])
@admin_required
def admin_gen():
    """Génère des codes d’activation uniques, chacun lié à une formation spécifique."""
    db = get_db()

    # 🔹 Récupération des paramètres du formulaire
    count = int(request.form.get('count', 5))
    days = int(request.form.get('days', 365))
    formation_id = request.form.get('formation_id')

    # 🔸 Vérification que la formation est bien sélectionnée
    if not formation_id:
        flash("❌ Veuillez sélectionner une formation avant de générer des codes.", "error")
        return redirect(url_for('admin_panel'))

    try:
        # 🔹 Génération et insertion des codes
        for _ in range(count):
            code = make_code()
            db.execute(
                'INSERT INTO codes (code, duration_days, formation_id) VALUES (?, ?, ?)',
                (code, days, formation_id)
            )

        db.commit()
        flash(f"✅ {count} codes générés avec succès pour la formation #{formation_id}.", "success")

    except Exception as e:
        db.rollback()
        flash(f"⚠️ Erreur lors de la génération des codes : {e}", "error")

    return redirect(url_for('admin_panel'))
    
@app.route('/admin/verify_2fa', methods=['GET', 'POST'])
def admin_verify_2fa():
    if not session.get('admin_temp_auth'):
        return redirect(url_for('admin_login'))

    secret = os.getenv('ADMIN_2FA_SECRET')

    if request.method == 'POST':
        code = request.form.get('code', '')
        totp = pyotp.TOTP(secret)
        if totp.verify(code):
            session.pop('admin_temp_auth', None)
            session['is_admin'] = True
            flash("✅ Vérification 2FA réussie", "success")
            return redirect(url_for('admin_panel'))
        else:
            flash("❌ Code 2FA invalide ou expiré", "error")

    return render_template('admin_verify_2fa.html')
    
@app.route('/admin/reset_device/<int:uid>', methods=['POST'])
@admin_required
def admin_reset_device(uid):
    """Réinitialiser le device pour permettre la reconnexion sur un nouvel appareil."""
    db = get_db()
    db.execute('UPDATE users SET device_hash=NULL WHERE id=?', (uid,))
    db.commit()
    flash("✅ Le device de cet utilisateur a été réinitialisé. Il pourra se reconnecter depuis un nouvel appareil.", "success")
    return redirect(url_for('admin_panel'))

# ---------------- Gestion des vidéos (Admin) ----------------
@app.route('/admin/videos', methods=['GET', 'POST'])
@admin_required
def admin_videos():
    db = get_db()

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        formation_id = request.form.get('formation_id')
        description = request.form.get('description', '').strip()  
        file = request.files.get('video_file')

        if not title or not file or not formation_id:
            flash("Veuillez remplir tous les champs (titre, vidéo et formation).", "error")
            return redirect(url_for('admin_videos'))

        # 🧩 Sauvegarde du fichier vidéo
        filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(4)}_{file.filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # 🟢 Enregistrement dans la base de données avec description
        db.execute(
            'INSERT INTO videos (title, filename, formation_id, description) VALUES (?, ?, ?, ?)',
            (title, filename, formation_id, description)
        )
        db.commit()

        flash("✅ Vidéo téléchargée et liée à la formation avec succès.", "success")
        return redirect(url_for('admin_videos'))

    # 🟢 Charger les vidéos et formations
    vids = db.execute('''
        SELECT v.*, f.titre AS formation_titre
        FROM videos v
        LEFT JOIN formations f ON f.id = v.formation_id
        ORDER BY v.id DESC
    ''').fetchall()

    formations = db.execute('SELECT id, titre FROM formations ORDER BY id DESC').fetchall()

    return render_template('admin_videos.html', vids=vids, formations=formations)


# ---------------- Suppression d'une vidéo ----------------
@app.route('/admin/videos/delete/<int:vid>', methods=['POST'])
@admin_required
def delete_video(vid):
    db = get_db()
    video = db.execute('SELECT * FROM videos WHERE id=?', (vid,)).fetchone()
    if not video:
        flash(gettext("Vidéo introuvable"))
        return redirect(url_for('admin_videos'))

    # 🗑️ Supprimer le fichier vidéo original
    video_path = os.path.join(app.config['UPLOAD_FOLDER'], video['filename'])
    if os.path.exists(video_path):
        os.remove(video_path)

    # 🧹 Supprimer le dossier HLS généré pour cette vidéo
    for name in os.listdir(app.config['HLS_FOLDER']):
        if name.startswith(f"{vid}_"):
            shutil.rmtree(os.path.join(app.config['HLS_FOLDER'], name), ignore_errors=True)

    # 🗑️ Supprimer l'entrée de la base de données
    db.execute('DELETE FROM videos WHERE id=?', (vid,))
    db.commit()
    flash(gettext("Vidéo supprimée avec succès"))
    return redirect(url_for('admin_videos'))


# ---------------- Suppression d'un commentaire ----------------
@app.route('/admin/commentaires/delete/<int:cid>', methods=['POST'])
@admin_required
def admin_delete_commentaire(cid):
    db = get_db()
    commentaire = db.execute('SELECT * FROM commentaires WHERE id=?', (cid,)).fetchone()
    if not commentaire:
        flash("❌ Commentaire introuvable.", "error")
        return redirect(url_for('admin_panel'))
    db.execute('DELETE FROM commentaires WHERE id=?', (cid,))
    db.commit()
    flash("✅ Commentaire supprimé avec succès.", "success")
    return redirect(url_for('admin_panel'))


# ---------------- Validation et refus des commandes ----------------
@app.route('/admin/validate_order/<int:order_id>')
@admin_required
def admin_validate_order(order_id):
    """Valider une commande, corriger le chemin de la preuve et lier la formation"""
    db = get_db()


    order = db.execute('SELECT * FROM orders WHERE id=?', (order_id,)).fetchone()
    if not order:
        flash("❌ Commande introuvable.", "error")
        return redirect(url_for('admin_panel'))

    user_id = order['user_id']


    formation_id = order['formation_id'] if 'formation_id' in order.keys() else None
    produit = order['produit'] if 'produit' in order.keys() else None

    if not formation_id and produit:
        formation = db.execute(
            "SELECT id FROM formations WHERE titre LIKE ?", (f"%{produit}%",)
        ).fetchone()
        if formation:
            formation_id = formation['id']

    if not formation_id:
        last_formation = db.execute(
            "SELECT id FROM formations ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if last_formation:
            formation_id = last_formation['id']

    import random, string
    code = "-".join(
        "".join(random.choices(string.ascii_uppercase + string.digits, k=4))
        for _ in range(3)
    )


    proof_path = order['proof'] if order['proof'] else None

    if proof_path:

        if not proof_path.startswith("uploads/"):
            proof_path = f"uploads/{proof_path}"
    else:

        proof_path = code


    db.execute(
        "INSERT INTO codes (code, used, used_by) VALUES (?, ?, ?)",
        (code, 1, user_id)
    )

    db.execute("""
        UPDATE orders
        SET status='validé',
            proof=?,
            formation_id=?
        WHERE id=?
    """, (proof_path, formation_id, order_id))

    db.execute("UPDATE users SET activated=1 WHERE id=?", (user_id,))
    db.commit()

    flash(f"✅ Commande #{order_id} validée avec succès.", "success")
    return redirect(url_for('admin_panel'))


@app.route('/admin/refuse_order/<int:order_id>', methods=['POST'])
@admin_required
def admin_refuse_order(order_id):
    """Refuser une commande avec un motif clair"""
    db = get_db()
    reason = request.form.get('reason', '').strip() or 'Non précisé'

    order = db.execute('SELECT * FROM orders WHERE id=?', (order_id,)).fetchone()
    if not order:
        flash("❌ Commande introuvable.", "error")
        return redirect(url_for('admin_panel'))

    db.execute("""
        UPDATE orders
        SET status='refusé',
            payment_mode = COALESCE(payment_mode, '') || ' | Motif: ' || ?
        WHERE id=?
    """, (reason, order_id))
    db.commit()

    flash(f"❌ Commande #{order_id} refusée. Motif : {reason}", "warning")
    return redirect(url_for('admin_panel'))

# ---------------- Supprimer une commande ----------------
@app.route('/admin/delete_order/<int:oid>', methods=['POST'])
@admin_required
def admin_delete_order(oid):
    """Supprimer complètement une commande"""
    db = get_db()
    order = db.execute('SELECT * FROM orders WHERE id=?', (oid,)).fetchone()
    if not order:
        flash("❌ Commande introuvable.", "error")
        return redirect(url_for('admin_panel'))

    db.execute('DELETE FROM orders WHERE id=?', (oid,))
    db.commit()
    flash(f"🗑️ Commande #{oid} supprimée avec succès.", "success")
    return redirect(url_for('admin_panel'))

# ---------------- admin/delete_user ----------------    
@app.route('/admin/delete_user/<int:uid>', methods=['POST'])
@admin_required
def delete_user(uid):
    db = get_db()
    db.execute('DELETE FROM users WHERE id=?', (uid,))
    db.commit()
    flash("Utilisateur supprimé avec succès.", "success")
    return redirect(url_for('admin_panel'))

@app.route('/admin/deactivate_user/<int:uid>', methods=['POST'])
@admin_required
def deactivate_user(uid):
    db = get_db()
    db.execute('UPDATE users SET activated=0 WHERE id=?', (uid,))
    db.commit()
    flash("Compte utilisateur désactivé.", "warning")
    return redirect(url_for('admin_panel'))  
    
# ---------------- admin/delete_user ----------------      
@app.route('/admin/delete_message/<int:mid>', methods=['POST'])
@admin_required
def admin_delete_message(mid):
    db = get_db()
    db.execute('DELETE FROM contact_messages WHERE id=?', (mid,))
    db.commit()
    flash("💬 Message supprimé avec succès.", "success")
    return redirect(url_for('admin_panel'))


# ---------------- API: Récupération des commandes d'un utilisateur ----------------
@app.route('/admin/api/user_orders/<int:user_id>')
@admin_required
def admin_api_user_orders(user_id):
    """
    Endpoint JSON يعرض كل الطلبات الخاصة بمستخدم معين.
    يُستخدم في المودال داخل لوحة التحكم.
    """
    db = get_db()

    orders = db.execute('''
        SELECT id, produit, total, status, created_at
        FROM orders
        WHERE user_id=?
        ORDER BY created_at DESC
    ''', (user_id,)).fetchall()

    orders_list = [dict(o) for o in orders]

    return jsonify({"orders": orders_list})


# ---------------- Supprimer une commande spécifique d'un utilisateur ----------------
@app.route('/admin/user/<int:user_id>/delete_order/<int:order_id>', methods=['POST'])
@admin_required
def admin_delete_user_order(user_id, order_id):
    """
    تمكّن الأدمن من حذف طلب معين من حساب المستخدم مباشرة.
    تُستخدم عند الضغط على زر 🗑️ في نافذة المودال.
    """
    db = get_db()
    order = db.execute(
        'SELECT * FROM orders WHERE id=? AND user_id=?',
        (order_id, user_id)
    ).fetchone()

    if not order:
        flash("❌ Commande introuvable pour cet utilisateur.", "error")
        return redirect(url_for('admin_panel'))

    db.execute('DELETE FROM orders WHERE id=?', (order_id,))
    db.commit()
    flash(f"🗑️ Commande #{order_id} supprimée avec succès pour l'utilisateur #{user_id}.", "success")
    return redirect(url_for('admin_panel'))

# ---------------- Reset requests (user side) ----------------
@app.route('/request_password_reset', methods=['GET', 'POST'])
@login_required
def request_password_reset():
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()
    if not user:
        flash(gettext("Utilisateur introuvable"))
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        reason = request.form.get('reason', '').strip()
        db.execute(
            'INSERT INTO reset_requests (user_id, reason, status, created_at) VALUES (?, ?, ?, ?)',
            (user['id'], reason, 'pending', datetime.utcnow().isoformat())
        )
        db.commit()
        flash(gettext("Votre demande a été envoyée à l'administrateur"))
        return redirect(url_for('dashboard'))

    return render_template('request_password_reset.html')

@app.route('/admin/reset_requests')
@admin_required
def admin_reset_requests():
    db = get_db()
    requests = db.execute('''
        SELECT r.*, u.username
        FROM reset_requests r
        JOIN users u ON u.id = r.user_id
        ORDER BY r.id DESC
    ''').fetchall()
    return render_template('admin_reset_requests.html', requests=requests)

@app.route('/admin/reset_requests/generate/<int:req_id>', methods=['POST'])
@admin_required
def admin_generate_temp_password(req_id):
    db = get_db()
    req = db.execute('SELECT * FROM reset_requests WHERE id=?', (req_id,)).fetchone()
    if not req:
        flash(gettext("Demande introuvable"))
        return redirect(url_for('admin_reset_requests'))

    temp_password = secrets.token_urlsafe(8)[:10]
    hashed_temp = generate_password_hash(temp_password)
    db.execute('UPDATE reset_requests SET temp_password=?, status="done" WHERE id=?',
               (temp_password, req_id))
    db.execute('UPDATE users SET password=? WHERE id=?', (hashed_temp, req['user_id']))
    db.commit()
    flash(gettext(f"Mot de passe temporaire généré: {temp_password}"))
    return redirect(url_for('admin_reset_requests'))

# ---------------- Admin change password ----------------
@app.route('/admin/change_password/<int:user_id>', methods=['POST'])
@admin_required
def admin_change_password(user_id):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
    if not user:
        flash(gettext("Utilisateur introuvable"))
        return redirect(url_for('admin_panel'))

    new_pass = request.form.get('new_password', '').strip()
    generated = False
    if not new_pass:
        new_pass = secrets.token_urlsafe(8)[:10]
        generated = True

    if len(new_pass) < 6:
        flash(gettext("Le mot de passe doit contenir au moins 6 caractères (ou laissez vide pour générer automatiquement)."))
        return redirect(url_for('admin_panel'))

    hashed = generate_password_hash(new_pass)
    db.execute('UPDATE users SET password=? WHERE id=?', (hashed, user_id))
    db.commit()

    if generated:
        flash(gettext(f"Mot de passe temporaire généré pour {user['username']}: {new_pass}"))
    else:
        flash(gettext(f"Mot de passe de {user['username']} mis à jour avec succès"))

    return redirect(url_for('admin_panel'))

# ---------------- Misc helpers ----------------
@app.route('/api/status')
def api_status():
    return jsonify({"ok": True, "version": "1.0"})

# ---------------- orders ----------------
@app.route('/orders')
def orders():
    """Afficher toutes les commandes de l'utilisateur connecté"""
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()
    commandes = db.execute(
        'SELECT * FROM orders WHERE user_id=? ORDER BY created_at DESC',
        (session['user_id'],)
    ).fetchall()

    return render_template('orders.html', user=user, commandes=commandes)
    
# ---------------- cart ----------------
@app.route('/add_to_cart/<int:vid>', methods=['GET', 'POST'])
def add_to_cart(vid):
    """إضافة كورس من formations إلى السلة بدون مغادرة الصفحة"""
    db = get_db()
    formation = db.execute('SELECT * FROM formations WHERE id=?', (vid,)).fetchone()
    if not formation:
        flash(gettext("La formation n'existe pas."), 'error')
        return redirect(url_for('formations'))

    cart = session.get('cart', [])

    if any(item['id'] == formation['id'] for item in cart):
        flash(gettext("Cette formation est déjà dans votre panier."), 'info')
    else:
        cart.append({
            'id': formation['id'],
            'title': formation['titre'],
            'price': float(formation['prix']) if str(formation['prix']).replace('.', '', 1).isdigit() else 0.0,
            'image': formation['image']
        })
        session['cart'] = cart
        flash(gettext("Formation ajoutée au panier avec succès."), 'success')


    return redirect(request.referrer or url_for('formations'))


@app.route('/remove_from_cart/<int:vid>')
def remove_from_cart(vid):
    """إزالة كورس من السلة"""
    cart = session.get('cart', [])
    new_cart = [item for item in cart if item['id'] != vid]
    session['cart'] = new_cart
    flash(gettext("Formation supprimée du panier."), 'success')
    return redirect(url_for('cart'))


@app.route('/cart')
def cart():
    """عرض محتوى السلة"""
    db = get_db()
    user = None
    if 'user_id' in session:
        user = db.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()

    cart_items = session.get('cart', [])

    total = sum(float(item["price"]) for item in cart_items if str(item["price"]).replace('.', '', 1).isdigit())

    return render_template('cart.html', user=user, items=cart_items, total=total)



@app.route('/clear_cart')
def clear_cart():
    """تفريغ السلة بالكامل"""
    session['cart'] = []
    flash(gettext("Votre panier a été vidé avec succès."), "success")
    return redirect(url_for('cart'))



@app.route('/remove_item/<int:fid>')
def remove_item(fid):
    """إزالة عنصر معين من السلة"""
    cart = session.get('cart', [])
    new_cart = [item for item in cart if item['id'] != fid]
    session['cart'] = new_cart
    flash(gettext("Formation supprimée du panier."), "success")
    return redirect(url_for('cart'))
    
# ---------------- Checkout ----------------
@app.route('/checkout', methods=['GET'])
def checkout():
    """Page de paiement"""
    db = get_db()
    user = None
    if 'user_id' in session:
        user = db.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()
    cart_items = session.get('cart', [])
    total = sum(float(item["price"]) for item in cart_items if str(item["price"]).replace('.', '', 1).isdigit())
    return render_template('checkout.html', user=user, items=cart_items, total=total)

# ---------------- validate_order ----------------
@app.route('/validate_order', methods=['POST'])
def validate_order():
    """Validation de la commande et enregistrement dans la base"""
    paiement = request.form.get('paiement')
    preuve = request.files.get('preuve')


    if not paiement:
        flash("Veuillez sélectionner un mode de paiement.", "error")
        return redirect(url_for('checkout'))

    db = get_db()
    user_id = session.get('user_id')
    cart_items = session.get('cart', [])


    total = sum(
        float(item["price"]) for item in cart_items
        if str(item["price"]).replace('.', '', 1).isdigit()
    )


    proof_filename = None
    if preuve and preuve.filename:
        os.makedirs('static/uploads', exist_ok=True)


        filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{preuve.filename}"


        preuve.save(os.path.join('static/uploads', filename))


        proof_filename = f"uploads/{filename}"


    for item in cart_items:
        titre = item.get("title") or item.get("titre")
        prix = item.get("price")
        formation_id = None


        if titre:
            formation = db.execute(
                "SELECT id FROM formations WHERE titre LIKE ?", (titre,)
            ).fetchone()
            if formation:
                formation_id = formation["id"]


        db.execute('''
            INSERT INTO orders (user_id, produit, total, payment_mode, proof, formation_id)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, titre, prix, paiement, proof_filename, formation_id))

    db.commit()


    session['cart'] = []

    flash("✅ Votre commande a été enregistrée avec succès. En attente de validation.", "success")
    return redirect(url_for('orders'))
    
# ---------------- user_id ----------------
@app.route('/profile/<int:user_id>')
@login_required
def profile_user(user_id):
    db = get_db()
    user_target = db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
    if not user_target:
        flash(gettext("Utilisateur introuvable"))
        return redirect(url_for('dashboard'))
    return render_template('profile.html', user=user_target)   

# ---------------- Profile (Unified: GET + POST) ----------------
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()
    if not user:
        flash(gettext("Utilisateur introuvable"))
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        phone = request.form.get('phone', '').strip()
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        email = request.form.get('email', '').strip()

        db.execute(
            'UPDATE users SET phone=?, first_name=?, last_name=?, email=? WHERE id=?',
            (phone, first_name, last_name, email, user['id'])
        )
        db.commit()
        flash(gettext("Profil mis à jour avec succès."))
        return redirect(url_for('profile'))

    return render_template('profile.html', user=user)
  
# ---------------- Recherche globale ----------------
@app.route('/search')
def search():
    db = get_db()
    q = request.args.get('q', '').strip()
    per_page = 12
    page = int(request.args.get('page', 1))
    offset = (page - 1) * per_page

    # ✅ Requête de base
    query = "SELECT * FROM formations WHERE 1=1"
    params = []

    if q:
        query += " AND (titre LIKE ? OR description LIKE ?)"
        like = f"%{q}%"
        params.extend([like, like])

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([per_page, offset])

    formations = db.execute(query, params).fetchall()

    # ✅ Compter les résultats
    count_query = "SELECT COUNT(*) FROM formations WHERE 1=1"
    count_params = []
    if q:
        count_query += " AND (titre LIKE ? OR description LIKE ?)"
        count_params.extend([f"%{q}%", f"%{q}%"])
    total = db.execute(count_query, count_params).fetchone()[0]
    total_pages = (total + per_page - 1) // per_page

    return render_template(
        'search_results.html',
        formations=formations,
        q=q,
        page=page,
        total_pages=total_pages,
        total=total
    )
    
# ---------------- Page Nos Formations (Universitaires) ----------------
@app.route('/formations')
def formations():
    db = get_db()

    per_page = 6
    page = int(request.args.get('page', 1))
    offset = (page - 1) * per_page

    domaines = request.args.getlist('domaine')
    niveaux = request.args.getlist('niveau')
    specialites = request.args.getlist('specialite')

    query = "SELECT * FROM formations WHERE domaine = 'Universitaire'"
    params = []

    if domaines:
        query += " AND domaine IN ({})".format(','.join(['?'] * len(domaines)))
        params.extend(domaines)
    if niveaux:
        query += " AND niveau IN ({})".format(','.join(['?'] * len(niveaux)))
        params.extend(niveaux)
    if specialites:
        query += " AND specialite IN ({})".format(','.join(['?'] * len(specialites)))
        params.extend(specialites)

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([per_page, offset])

    formations = db.execute(query, params).fetchall()

    # ✅ Compter uniquement universitaires
    count_query = "SELECT COUNT(*) FROM formations WHERE domaine = 'Universitaire'"
    total = db.execute(count_query).fetchone()[0]
    total_pages = (total + per_page - 1) // per_page

    return render_template(
        'formations.html',
        formations=formations,
        page=page,
        total_pages=total_pages,
        selected_domaines=domaines,
        selected_niveaux=niveaux,
        selected_specialites=specialites
    )

# ---------------- Page Formations BAC ----------------
@app.route('/formations_bac')
def formations_bac():
    db = get_db()

    per_page = 6
    page = int(request.args.get('page', 1))
    offset = (page - 1) * per_page

    domaines = request.args.getlist('domaine')
    niveaux = request.args.getlist('niveau')
    specialites = request.args.getlist('specialite')

    query = "SELECT * FROM formations WHERE domaine = 'BAC'"
    params = []

    if domaines:
        query += " AND domaine IN ({})".format(','.join(['?'] * len(domaines)))
        params.extend(domaines)
    if niveaux:
        query += " AND niveau IN ({})".format(','.join(['?'] * len(niveaux)))
        params.extend(niveaux)
    if specialites:
        query += " AND specialite IN ({})".format(','.join(['?'] * len(specialites)))
        params.extend(specialites)

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([per_page, offset])

    formations = db.execute(query, params).fetchall()

    # ✅ Compter uniquement BAC
    count_query = "SELECT COUNT(*) FROM formations WHERE domaine = 'BAC'"
    total = db.execute(count_query).fetchone()[0]
    total_pages = (total + per_page - 1) // per_page

    return render_template(
        'formations_bac.html',
        formations=formations,
        page=page,
        total_pages=total_pages,
        selected_domaines=domaines,
        selected_niveaux=niveaux,
        selected_specialites=specialites
    )

# ---------------- commentaires ---------------
from flask import render_template, request, redirect, url_for, session, flash

@app.route("/commentaires")
def commentaires():
    """Afficher tous les commentaires depuis la base de données"""
    db = get_db()

    # ✅ Récupérer tous les commentaires avec le nom d'utilisateur lié
    commentaires = db.execute("""
        SELECT c.id, c.contenu, c.note, c.date_created, u.username
        FROM commentaires c
        JOIN users u ON c.user_id = u.id
        ORDER BY c.id DESC
    """).fetchall()

    return render_template("commentaires.html", commentaires=commentaires)


@app.route("/ajouter_commentaire", methods=["POST"])
def ajouter_commentaire():
    """Ajouter un nouveau commentaire à la base de données"""
    if not session.get("user_id"):
        flash("Vous devez être connecté pour commenter.", "warning")
        return redirect(url_for("login"))

    contenu = request.form.get("contenu", "").strip()
    note = request.form.get("note", "").strip()

    # ✅ Validation
    if not contenu:
        flash("Le contenu du commentaire ne peut pas être vide.", "danger")
        return redirect(url_for("commentaires"))

    if not note:
        flash("Veuillez sélectionner une note avant d'envoyer votre commentaire.", "danger")
        return redirect(url_for("commentaires"))

    try:
        note = int(note)
    except ValueError:
        flash("La note envoyée est invalide.", "danger")
        return redirect(url_for("commentaires"))

    # ✅ Sauvegarder le commentaire dans la base
    db = get_db()
    db.execute("""
        INSERT INTO commentaires (user_id, contenu, note, date_created)
        VALUES (?, ?, ?, ?)
    """, (
        session["user_id"],
        contenu,
        note,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    db.commit()

    flash("Commentaire ajouté avec succès !", "success")
    return redirect(url_for("commentaires"))
    
# ---------------- Lancer l'application ----------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)


