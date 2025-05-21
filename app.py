from flask import Flask, render_template, request, redirect, url_for, send_from_directory, jsonify, session, flash
from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import pyotp
import os
import base64
import qrcode
from PIL import Image
from io import BytesIO
from datetime import datetime, timedelta
from dotenv import load_dotenv
import requests
from requests_oauthlib import OAuth2Session
from werkzeug.security import generate_password_hash, check_password_hash
import re
import json
import hmac
import hashlib
from werkzeug.utils import secure_filename
from flask import Response

app = Flask(__name__)
load_dotenv()
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'None'
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://securedocs_user:securedocs_password@localhost/securedocs'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)  # مدة الـ session لـ 30 يوم
db = SQLAlchemy(app)

# إعداد مفتاح تشفير
def load_or_generate_key():
    key_file = 'fernet_key.key'
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, 'wb') as f:
            f.write(key)
        return key
def load_or_generate_hmac_key():
    key_file = 'hmac_key.key'
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            return f.read()
    else:
        key = os.urandom(32)
        with open(key_file, 'wb') as f:
            f.write(key)
        return key

HMAC_KEY = load_or_generate_hmac_key()
key = load_or_generate_key()
cipher = Fernet(key)
# مفتاح لـ HMAC


# إعداد مفاتيح توقيع
def load_or_generate_keys():
    private_key_file = 'private_key.pem'
    public_key_file = 'public_key.pem'

    if os.path.exists(private_key_file) and os.path.exists(public_key_file):
        with open(private_key_file, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(public_key_file, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read())
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        with open(private_key_file, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(public_key_file, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    return private_key, public_key

private_key, public_key = load_or_generate_keys()
# إعداد Okta OIDC
OKTA_CLIENT_ID = os.getenv('OKTA_CLIENT_ID')
OKTA_CLIENT_SECRET = os.getenv('OKTA_CLIENT_SECRET')
OKTA_ISSUER = os.getenv('OKTA_ISSUER')
OKTA_REDIRECT_URI = "https://localhost:5000/auth/okta/callback"
OKTA_AUTHORIZATION_URL = f"{OKTA_ISSUER}/v1/authorize"
OKTA_TOKEN_URL = f"{OKTA_ISSUER}/v1/token"
OKTA_USERINFO_URL = f"{OKTA_ISSUER}/v1/userinfo"

# نماذج قاعدة البيانات
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=True)  # حقل جديد للاسم
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255))
    role = db.Column(db.Enum('user', 'admin'), default='user')
    twoFactorSecret = db.Column(db.String(255))
    createdAt = db.Column(db.DateTime, default=datetime.utcnow)

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userId = db.Column(db.Integer, db.ForeignKey('user.id'))
    name = db.Column(db.String(255), nullable=False)
    hash = db.Column(db.String(64), nullable=False)
    hmac = db.Column(db.String(64), nullable=False)  # لتخزين HMAC
    encryptedData = db.Column(db.LargeBinary(length=16777215), nullable=False)  # MEDIUMBLOB
    signature = db.Column(db.Text, nullable=False)
    createdAt = db.Column(db.DateTime, default=datetime.utcnow)

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userId = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(255), nullable=False)
    createdAt = db.Column(db.DateTime, default=datetime.utcnow)

# دالة للتحقق من قوة كلمة السر
def is_strong_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    return True

# Middleware للتحقق من تسجيل الدخول وانتهاء الـ session
def login_required(f):
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first.', 'error')
            return redirect(url_for('login'))
        # تحقق من انتهاء الـ session
        session_start = session.get('session_start')
        if session_start:
            start_time = datetime.fromisoformat(session_start)
            if (datetime.utcnow() - start_time) > app.config['PERMANENT_SESSION_LIFETIME']:
                session.clear()
                flash('Session expired. Please login again.', 'error')
                return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

# الصفحات
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        remember = 'remember' in request.form  # التحقق من اختيار "Remember Me"
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['session_start'] = datetime.utcnow().isoformat()  # وقت بدء الـ session
            session.permanent = remember  # تفعيل الـ session المستمر لو اختار "Remember Me"
            log = Log(userId=user.id, action='Logged in')
            db.session.add(log)
            db.session.commit()
            if user.twoFactorSecret:
                return redirect(url_for('verify2fa'))
            return redirect(url_for('setup2fa'))
        flash('Invalid email or password.', 'error')
    return render_template('login.html', bootstrap=True)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        if not is_strong_password(password):
            flash('Password must be at least 8 characters long and include uppercase, lowercase, and numbers.', 'error')
            return render_template('register.html', bootstrap=True)
        if User.query.filter_by(email=email).first():
            flash('Email is already in use. Please use a different email.', 'error')
            return render_template('register.html', bootstrap=True)
        hashed_password = generate_password_hash(password)
        new_user = User(name=name, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful. Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', bootstrap=True)

@app.route('/auth/google')
def google_auth():
    auth_url = (
        "https://accounts.google.com/o/oauth2/auth?response_type=code&client_id="
        + os.getenv('GOOGLE_CLIENT_ID')
        + "&redirect_uri=https://localhost:5000/auth/google/callback&scope=email%20profile"
    )
    return redirect(auth_url)

@app.route('/auth/google/callback')
def google_callback():
    code = request.args.get('code')
    token_url = "https://oauth2.googleapis.com/token"
    token_data = {
        "code": code,
        "client_id": os.getenv('GOOGLE_CLIENT_ID'),
        "client_secret": os.getenv('GOOGLE_CLIENT_SECRET'),
        "redirect_uri": "https://localhost:5000/auth/google/callback",
        "grant_type": "authorization_code",
    }
    response = requests.post(token_url, data=token_data)
    token_json = response.json()
    access_token = token_json.get('access_token')
    user_info = requests.get("https://www.googleapis.com/oauth2/v1/userinfo?access_token=" + access_token).json()
    email = user_info.get('email')
    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(name=user_info.get('name', email.split('@')[0]), email=email, role='user')  # استخدام الاسم من Google أو جزء الإيميل
        db.session.add(user)
        db.session.commit()
    session['user_id'] = user.id
    session['session_start'] = datetime.utcnow().isoformat()
    session.permanent = True
    log = Log(userId=user.id, action='Logged in via Google')
    db.session.add(log)
    db.session.commit()
    if user.twoFactorSecret:
        return redirect(url_for('verify2fa'))
    return redirect(url_for('setup2fa'))

@app.route('/auth/github')
def github_auth():
    auth_url = (
        "https://github.com/login/oauth/authorize?client_id="
        + os.getenv('GITHUB_CLIENT_ID')
        + "&redirect_uri=https://localhost:5000/auth/github/callback&scope=user:email"
    )
    return redirect(auth_url)

@app.route('/auth/github/callback')
def github_callback():
    code = request.args.get('code')
    token_url = "https://github.com/login/oauth/access_token"
    token_data = {
        "client_id": os.getenv('GITHUB_CLIENT_ID'),
        "client_secret": os.getenv('GITHUB_CLIENT_SECRET'),
        "code": code,
        "redirect_uri": "https://localhost:5000/auth/github/callback",
    }
    headers = {'Accept': 'application/json'}
    response = requests.post(token_url, data=token_data, headers=headers)
    
    if response.status_code != 200:
        flash(f'Failed to get access token from GitHub. Status: {response.status_code}', 'error')
        print(f"Debug: Token response: {response.text}")
        return redirect(url_for('login'))
    
    token_json = response.json()
    access_token = token_json.get('access_token')
    if not access_token:
        flash('No access token received from GitHub.', 'error')
        print(f"Debug: Token JSON: {token_json}")
        return redirect(url_for('login'))

    user_info = requests.get("https://api.github.com/user", headers={"Authorization": f"Bearer {access_token}"}).json()
    
    email_response_raw = requests.get("https://api.github.com/user/emails", headers={"Authorization": f"Bearer {access_token}"})
    
    if email_response_raw.status_code != 200:
        flash(f'Failed to fetch emails from GitHub. Status: {email_response_raw.status_code}', 'error')
        print(f"Debug: Email response: {email_response_raw.text}")
        return redirect(url_for('login'))
    
    email_response = email_response_raw.json()
    
    if not isinstance(email_response, list):
        flash('Unexpected response format from GitHub email API.', 'error')
        print(f"Debug: Email response type: {type(email_response)}, content: {email_response}")
        return redirect(url_for('login'))
    
    email = next((email['email'] for email in email_response if email.get('primary', False) and email.get('verified', False)), None)
    if not email:
        flash('No verified primary email found.', 'error')
        print(f"Debug: Email response: {email_response}")
        return redirect(url_for('login'))
    
    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(name=user_info.get('login', email.split('@')[0]), email=email, role='user')  # استخدام username من GitHub أو جزء الإيميل
        db.session.add(user)
        db.session.commit()
    session['user_id'] = user.id
    session['session_start'] = datetime.utcnow().isoformat()
    session.permanent = True
    log = Log(userId=user.id, action='Logged in via GitHub')
    db.session.add(log)
    db.session.commit()
    if user.twoFactorSecret:
        return redirect(url_for('verify2fa'))
    return redirect(url_for('setup2fa'))

@app.route('/auth/okta')
def okta_auth():
    session['test'] = 'test_value'
    print(f"Before setting state, session: {session}")
    
    try:
        okta = OAuth2Session(
            OKTA_CLIENT_ID,
            redirect_uri=OKTA_REDIRECT_URI,
            scope=["openid", "email", "profile"]
        )
        authorization_url, state = okta.authorization_url(OKTA_AUTHORIZATION_URL)
        session['oauth_state'] = state
        print(f"After setting state, session: {session}")
        return redirect(authorization_url)
    except Exception as e:
        print(f"Error in okta_auth: {str(e)}")
        flash(f'Error initiating Okta login: {str(e)}', 'error')
        return redirect(url_for('login'))
                    
@app.route('/auth/okta/callback')
def okta_callback():
    print(f"Session content at callback: {session}")
    
    if 'oauth_state' not in session:
        print(f"Missing oauth_state, session: {session}")
        flash('Invalid state parameter. Session might have expired.', 'error')
        return redirect(url_for('login'))
    
    try:
        okta = OAuth2Session(
            OKTA_CLIENT_ID,
            state=session['oauth_state'],
            redirect_uri=OKTA_REDIRECT_URI
        )
        
        token = okta.fetch_token(
            OKTA_TOKEN_URL,
            client_secret=OKTA_CLIENT_SECRET,
            code=request.args.get('code')
        )
        
        okta = OAuth2Session(OKTA_CLIENT_ID, token=token)
        user_info = okta.get(OKTA_USERINFO_URL).json()
        
        email = user_info.get('email')
        if not email:
            flash('No email found in Okta user info.', 'error')
            return redirect(url_for('login'))
        
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(name=user_info.get('name', email.split('@')[0]), email=email, role='user')  # استخدام الاسم من Okta أو جزء الإيميل
            db.session.add(user)
            db.session.commit()
        
        session['user_id'] = user.id
        session['session_start'] = datetime.utcnow().isoformat()
        session.permanent = True
        
        log = Log(userId=user.id, action='Logged in via Okta')
        db.session.add(log)
        db.session.commit()
        
        if user.twoFactorSecret:
            return redirect(url_for('verify2fa'))
        return redirect(url_for('setup2fa'))
    
    except Exception as e:
        print(f"Error in okta_callback: {str(e)}")
        flash(f'Error during Okta callback: {str(e)}', 'error')
        return redirect(url_for('login'))

@app.route('/setup2fa', methods=['GET', 'POST'])
@login_required
def setup2fa():
    user = db.session.get(User, session['user_id'])
    if request.method == 'POST':
        token = request.form['token']
        temp_secret = session.get('temp_2fa_secret')
        if not temp_secret:
            flash('2FA setup session expired. Please try again.', 'error')
            return redirect(url_for('setup2fa'))
        totp = pyotp.TOTP(temp_secret)
        if totp.verify(token):
            user.twoFactorSecret = temp_secret
            db.session.commit()
            session.pop('temp_2fa_secret', None)
            session['2faverified'] = True
            flash('2FA setup completed successfully.', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid 2FA token. Please try again.', 'error')
    if not user.twoFactorSecret:
        secret = pyotp.random_base32()
        session['temp_2fa_secret'] = secret
        totp = pyotp.TOTP(secret)
        qr_url = totp.provisioning_uri(user.email, issuer_name="SecureDocs")
        qr = qrcode.make(qr_url)
        buffer = BytesIO()
        qr.save(buffer, format="PNG")
        qr_code = base64.b64encode(buffer.getvalue()).decode('utf-8')
        return render_template('setup2fa.html', qr_code=qr_code, user=user, bootstrap=True)
    return redirect(url_for('dashboard'))

@app.route('/verify2fa', methods=['GET', 'POST'])
@login_required
def verify2fa():
    if request.method == 'POST':
        token = request.form['token']
        user = db.session.get(User, session['user_id'])
        totp = pyotp.TOTP(user.twoFactorSecret)
        if totp.verify(token):
            session['2faverified'] = True
            return redirect(url_for('dashboard'))
        flash('Invalid 2FA token.', 'error')
    user = db.session.get(User, session['user_id'])
    return render_template('verify2fa.html', user=user, bootstrap=True)

@app.route('/dashboard')
@login_required
def dashboard():
    if '2faverified' not in session:
        return redirect(url_for('verify2fa'))
    user = db.session.get(User, session['user_id'])
    documents = Document.query.filter_by(userId=user.id).all()
    total_docs = len(documents)
    recent_docs = Document.query.filter_by(userId=user.id).order_by(Document.createdAt.desc()).limit(5).all()
    return render_template('dashboard.html', user=user, documents=documents, total_docs=total_docs, recent_docs=recent_docs, bootstrap=True)

@app.route('/documents')
@login_required
def documents():
    if '2faverified' not in session:
        return redirect(url_for('verify2fa'))
    user = db.session.get(User, session['user_id'])
    user_docs = Document.query.filter_by(userId=user.id).all()
    return render_template('documents.html', user=user, documents=user_docs, bootstrap=True)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if '2faverified' not in session:
        return redirect(url_for('verify2fa'))
    user = db.session.get(User, session['user_id'])
    if request.method == 'POST':
        file = request.files['file']
        if file and file.filename.lower().endswith(('.pdf', '.docx', '.txt')):
            # تنظيف اسم الملف
            filename = secure_filename(file.filename)
            data = file.read()
            # احفظي الملف في uploads/
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            with open(file_path, 'wb') as f:
                f.write(data)
            encrypted = cipher.encrypt(data)
            
            # حساب SHA-256 hash
            digest = hashes.Hash(hashes.SHA256())
            digest.update(data)
            hash_value = digest.finalize().hex()
            
            # حساب HMAC-SHA256
            hmac_obj = hmac.new(HMAC_KEY, data, hashlib.sha256)
            hmac_value = hmac_obj.hexdigest()
            
            # التأكد من الحجم
            if len(encrypted) > 16777215:  # 16 MB
                flash('File too large after encryption. Max size is 16 MB.', 'error')
                return redirect(url_for('upload'))
            
            signature = private_key.sign(
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            ).hex()
            new_doc = Document(
                userId=session['user_id'],
                name=filename,  # استخدمي الاسم المنظف
                hash=hash_value,
                hmac=hmac_value,
                encryptedData=encrypted,
                signature=signature
            )
            db.session.add(new_doc)
            log = Log(userId=session['user_id'], action=f'Uploaded document: {filename}')
            db.session.add(log)
            db.session.commit()
            flash('Document uploaded successfully.', 'success')
            return redirect(url_for('documents'))
        flash('Invalid file type. Only PDF, DOCX, and TXT are allowed.', 'error')
    return render_template('upload.html', user=user, bootstrap=True)
    
@app.route('/download/<int:id>')
@login_required
def download(id):
    if '2faverified' not in session:
        return redirect(url_for('verify2fa'))
    doc = Document.query.get_or_404(id)
    user = db.session.get(User, session['user_id'])
    if doc.userId != user.id and user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('documents'))
    decrypted = cipher.decrypt(doc.encryptedData)
    
    # التحقق من HMAC
    hmac_obj = hmac.new(HMAC_KEY, decrypted, hashlib.sha256)
    current_hmac = hmac_obj.hexdigest()
    if not hmac.compare_digest(current_hmac, doc.hmac):
        flash('Document integrity check failed (HMAC). The file may have been tampered with.', 'error')
        log = Log(userId=user.id, action=f'Integrity check failed for document: {doc.name}')
        db.session.add(log)
        db.session.commit()
        return redirect(url_for('documents'))
    
    # التحقق من SHA-256 hash
    digest = hashes.Hash(hashes.SHA256())
    digest.update(decrypted)
    current_hash = digest.finalize().hex()
    if current_hash != doc.hash:
        flash('Document integrity check failed (Hash). The file may have been tampered with.', 'error')
        log = Log(userId=user.id, action=f'Integrity check failed for document: {doc.name}')
        db.session.add(log)
        db.session.commit()
        return redirect(url_for('documents'))
    
    try:
        public_key.verify(
            bytes.fromhex(doc.signature),
            decrypted,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
    except Exception as e:
        flash('Signature verification failed. The document may not be authentic.', 'error')
        log = Log(userId=user.id, action=f'Signature verification failed for document: {doc.name}')
        db.session.add(log)
        db.session.commit()
        return redirect(url_for('documents'))
    
    log = Log(userId=user.id, action=f'Downloaded document: {doc.name}')
    db.session.add(log)
    db.session.commit()
    
    # ارجعي البيانات المفككة مباشرة
    return Response(
        decrypted,
        mimetype='application/octet-stream',
        headers={"Content-Disposition": f"attachment;filename={doc.name}"}
    )

@app.route('/delete_document/<int:id>')
@login_required
def delete_document_user(id):
    if '2faverified' not in session:
        return redirect(url_for('verify2fa'))
    doc = Document.query.get_or_404(id)
    user = db.session.get(User, session['user_id'])
    if doc.userId != user.id:
        flash('Access denied.', 'error')
        return redirect(url_for('documents'))
    db.session.delete(doc)
    db.session.commit()
    flash('Document deleted successfully.', 'success')
    return redirect(url_for('documents'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if '2faverified' not in session:
        return redirect(url_for('verify2fa'))
    user = db.session.get(User, session['user_id'])
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form.get('password')
        if email != user.email and User.query.filter_by(email=email).first():
            flash('Email is already in use.', 'error')
            return render_template('profile.html', user=user, bootstrap=True)
        if password and not is_strong_password(password):
            flash('Password must be at least 8 characters long and include uppercase, lowercase, and numbers.', 'error')
            return render_template('profile.html', user=user, bootstrap=True)
        user.name = name
        user.email = email
        if password:
            user.password = generate_password_hash(password)
        db.session.commit()
        flash('Profile updated successfully.', 'success')
        return redirect(url_for('profile'))
    return render_template('profile.html', user=user, bootstrap=True)

@app.route('/admin')
@login_required
def admin():
    if '2faverified' not in session:
        return redirect(url_for('verify2fa'))
    user = db.session.get(User, session['user_id'])
    if user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    users = User.query.all()
    logs = Log.query.all()
    documents = Document.query.all()
    return render_template('admin.html', user=user, users=users, logs=logs, documents=documents, bootstrap=True)

@app.route('/admin/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    user = db.session.get(User, session['user_id'])
    if user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        role = request.form.get('role', 'user')
        if User.query.filter_by(email=email).first():
            flash('Email is already in use.', 'error')
            return render_template('add_user.html', user=user, bootstrap=True)
        if not is_strong_password(password):
            flash('Password must be at least 8 characters long and include uppercase, lowercase, and numbers.', 'error')
            return render_template('add_user.html', user=user, bootstrap=True)
        hashed_password = generate_password_hash(password)
        new_user = User(name=name, email=email, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('User added successfully.', 'success')
        return redirect(url_for('admin'))
    return render_template('add_user.html', user=user, bootstrap=True)

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    user = db.session.get(User, session['user_id'])
    if user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    target_user = db.session.get(User, user_id)
    if not target_user:
        flash('User not found.', 'error')
        return redirect(url_for('admin'))
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form.get('password')
        if email != target_user.email and User.query.filter_by(email=email).first():
            flash('Email is already in use.', 'error')
            return render_template('edit_user.html', user=user, target_user=target_user, bootstrap=True)
        if password and not is_strong_password(password):
            flash('Password must be at least 8 characters long and include uppercase, lowercase, and numbers.', 'error')
            return render_template('edit_user.html', user=user, target_user=target_user, bootstrap=True)
        target_user.name = name
        target_user.email = email
        if password:
            target_user.password = generate_password_hash(password)
        target_user.role = request.form.get('role', 'user')
        db.session.commit()
        flash('User updated successfully.', 'success')
        return redirect(url_for('admin'))
    return render_template('edit_user.html', user=user, target_user=target_user, bootstrap=True)

@app.route('/admin/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    user = db.session.get(User, session['user_id'])
    if user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    target_user = db.session.get(User, user_id)
    if not target_user:
        flash('User not found.', 'error')
        return redirect(url_for('admin'))
    if target_user.id == user.id:
        flash('You cannot delete yourself.', 'error')
        return redirect(url_for('admin'))
    
    Log.query.filter_by(userId=target_user.id).delete()
    
    db.session.delete(target_user)
    db.session.commit()
    flash('User deleted successfully.', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/change_role/<int:user_id>', methods=['POST'])
@login_required
def change_role(user_id):
    user = db.session.get(User, session['user_id'])
    if user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    target_user = db.session.get(User, user_id)
    if not target_user:
        flash('User not found.', 'error')
        return redirect(url_for('admin'))
    new_role = request.form['role']
    target_user.role = new_role
    db.session.commit()
    flash('Role updated successfully.', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/edit_document/<int:doc_id>', methods=['GET', 'POST'])
@login_required
def edit_document(doc_id):
    user = db.session.get(User, session['user_id'])
    if user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    doc = Document.query.get_or_404(doc_id)
    if request.method == 'POST':
        # جيب الاسم الجديد من الفورم
        new_name = request.form['name']
        if not new_name:
            flash('Document name cannot be empty.', 'error')
            return render_template('edit_document.html', user=user, doc=doc, bootstrap=True)
            
        file = request.files.get('file')
        # لو الأدمن رفع ملف جديد، اعمل تحديث للمحتوى
        if file and file.filename.lower().endswith(('.pdf', '.docx', '.txt')):
            data = file.read()
            encrypted = cipher.encrypt(data)
            digest = hashes.Hash(hashes.SHA256())
            digest.update(data)
            hash_value = digest.finalize().hex()
            
            hmac_obj = hmac.new(HMAC_KEY, data, hashlib.sha256)
            hmac_value = hmac_obj.hexdigest()
            
            signature = private_key.sign(
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            ).hex()
            
            # تحديث بيانات المستند
            doc.encryptedData = encrypted
            doc.hash = hash_value
            doc.hmac = hmac_value
            doc.signature = signature
        elif not file:
            # لو ما رفعش ملف جديد، حافظ على المحتوى الحالي
            pass
        else:
            flash('Invalid file type. Only PDF, DOCX, and TXT are allowed.', 'error')
            return render_template('edit_document.html', user=user, doc=doc, bootstrap=True)

        # تحديث الاسم دايمًا
        doc.name = new_name
        db.session.commit()
        flash('Document updated successfully.', 'success')
        return redirect(url_for('admin'))
    return render_template('edit_document.html', user=user, doc=doc, bootstrap=True)
    
@app.route('/edit_document/<int:doc_id>', methods=['GET', 'POST'])
@login_required
def edit_document_user(doc_id):
    user = db.session.get(User, session['user_id'])
    doc = Document.query.get_or_404(doc_id)
    
    # التأكد إن اليوزر هو صاحب المستند
    if doc.userId != user.id:
        flash('Access denied. You can only edit your own documents.', 'error')
        return redirect(url_for('documents'))
    
    if request.method == 'POST':
        # جيب الاسم الجديد من الفورم
        new_name = request.form['name']
        if not new_name:
            flash('Document name cannot be empty.', 'error')
            return render_template('edit_document_user.html', user=user, doc=doc, bootstrap=True)
            
        file = request.files.get('file')
        # لو اليوزر رفع ملف جديد، اعمل تحديث للمحتوى
        if file and file.filename.lower().endswith(('.pdf', '.docx', '.txt')):
            data = file.read()
            encrypted = cipher.encrypt(data)
            digest = hashes.Hash(hashes.SHA256())
            digest.update(data)
            hash_value = digest.finalize().hex()
            
            hmac_obj = hmac.new(HMAC_KEY, data, hashlib.sha256)
            hmac_value = hmac_obj.hexdigest()
            
            signature = private_key.sign(
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            ).hex()
            
            # تحديث بيانات المستند
            doc.encryptedData = encrypted
            doc.hash = hash_value
            doc.hmac = hmac_value
            doc.signature = signature
        elif not file:
            # لو ما رفعش ملف جديد، حافظ على المحتوى الحالي
            pass
        else:
            flash('Invalid file type. Only PDF, DOCX, and TXT are allowed.', 'error')
            return render_template('edit_document_user.html', user=user, doc=doc, bootstrap=True)

        # تحديث الاسم دايمًا
        doc.name = new_name
        db.session.commit()
        flash('Document updated successfully.', 'success')
        return redirect(url_for('documents'))
    return render_template('edit_document_user.html', user=user, doc=doc, bootstrap=True)

@app.route('/admin/delete_document/<int:doc_id>')
@login_required
def delete_document(doc_id):
    user = db.session.get(User, session['user_id'])
    if user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    doc = Document.query.get_or_404(doc_id)
    db.session.delete(doc)
    db.session.commit()
    flash('Document deleted successfully.', 'success')
    return redirect(url_for('admin'))

@app.route('/logout')
@login_required
def logout():
    user_id = session.get('user_id')
    session.clear()
    if user_id:
        log = Log(userId=user_id, action='Logged out')
        db.session.add(log)
        db.session.commit()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

# إنشاء قاعدة البيانات
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(ssl_context=('certs/server.crt', 'certs/server.key'), host='0.0.0.0', port=5000)
