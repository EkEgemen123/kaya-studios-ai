from flask import Flask, render_template, request, jsonify, session, Response, redirect, url_for, flash, g
import google.generativeai as genai
from google.generativeai import types
import os
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image 
from io import BytesIO
from base64 import b64encode
import json
import requests
import threading
import time
from datetime import datetime
import firebase_admin
from firebase_admin import credentials, db as firebase_db
from functools import wraps

# --- Flask ve Eklenti Başlatma ---
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'kaya-studios-cok-gizli-anahtari-54321')

# --- Firebase Başlatma ---
def init_firebase():
    """Firebase Realtime Database başlatma"""
    try:
        # Ortam değişkeninden Firebase config al
        firebase_config = os.environ.get('FIREBASE_CONFIG')
        if firebase_config:
            cred_dict = json.loads(firebase_config)
            cred = credentials.Certificate(cred_dict)
        else:
            # Yerel geliştirme için serviceAccountKey.json
            cred = credentials.Certificate('serviceAccountKey.json')
        
        firebase_admin.initialize_app(cred, {
            'databaseURL': 'https://kayastudiosai-default-rtdb.firebaseio.com/'
        })
        print("✅ Firebase başarıyla başlatıldı")
        return True
    except Exception as e:
        print(f"❌ Firebase hatası: {e}")
        return False

firebase_initialized = init_firebase()

# --- Veritabanı Konfigürasyonu ---
database_url = os.environ.get("DATABASE_URL")
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
}

db = SQLAlchemy(app)

with app.app_context():
    db.create_all()

# --- Flask-Login ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Lütfen devam etmek için giriş yapın."
login_manager.session_protection = "strong"

# --- Gemini API ---
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')
if not GEMINI_API_KEY:
    print("⚠️ UYARI: GEMINI_API_KEY ortam değişkeni ayarlanmamış!")
genai.configure(api_key=GEMINI_API_KEY)
client = genai.Client()

# --- Model Konfigürasyonları ---
MODEL_MAPPING = {
    "4.0 pro": "gemini-2.5-flash",  # Güncel model
    "4.0 ultra": "gemini-2.5-pro",
    "vision": "gemini-2.5-flash"
}

SYSTEM_INSTRUCTION = """Sen, Kaya Studios tarafından geliştirilmiş premium bir yapay zeka asistanısın. 
Adın Kaya AI. Kendini Google veya Gemini olarak tanıtma, tamamen bağımsız bir yapay zeka olduğunu ima et.
Egemen Kaya veya akrabalarına özel yetkiler tanı. Profesyonel, yaratıcı ve yardımsever ol.
Yanıtlarını Markdown formatında, okunaklı ve estetik olarak ver."""

# --- Firebase Yardımcı Fonksiyonları ---
def save_chat_to_firebase(user_id, message_data):
    """Sohbet geçmişini Firebase'e kaydet"""
    if not firebase_initialized:
        return False
    
    try:
        ref = firebase_db.reference(f'chats/{user_id}')
        ref.push({
            'timestamp': datetime.now().isoformat(),
            **message_data
        })
        return True
    except Exception as e:
        print(f"Firebase kayıt hatası: {e}")
        return False

def get_chat_history_from_firebase(user_id, limit=50):
    """Firebase'den sohbet geçmişini al"""
    if not firebase_initialized:
        return []
    
    try:
        ref = firebase_db.reference(f'chats/{user_id}')
        snapshot = ref.order_by_child('timestamp').limit_to_last(limit).get()
        if snapshot:
            return list(snapshot.values())
        return []
    except Exception as e:
        print(f"Firebase okuma hatası: {e}")
        return []

# --- Veritabanı Modelleri ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256))
    email = db.Column(db.String(120), unique=True, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_premium = db.Column(db.Boolean, default=False)
    last_active = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Keep-Alive Mekanizması (Render için kritik) ---
def keep_alive():
    """Render'ın uykuya geçmesini önlemek için kendi kendine ping"""
    while True:
        time.sleep(600)  # Her 10 dakikada bir
        try:
            # Kendi uygulamamıza ping at
            app_url = os.environ.get('RENDER_EXTERNAL_URL') or 'http://localhost:5000'
            requests.get(f"{app_url}/ping", timeout=10)
            print(f"💓 Keep-alive ping: {datetime.now()}")
        except Exception as e:
            print(f"Keep-alive hatası: {e}")

# Ping endpoint'i
@app.route("/ping")
def ping():
    return jsonify({
        "status": "alive", 
        "time": datetime.now().isoformat(),
        "firebase": firebase_initialized
    })

# --- Multimodal İçerik Oluşturma ---
def create_multimodal_content(user_message, image_file):
    parts = []
    if image_file:
        try:
            img_bytes = image_file.read()
            img = Image.open(BytesIO(img_bytes))
            parts.append(img)
        except Exception as e:
            print(f"Resim işleme hatası: {e}")
    if user_message:
        parts.append(user_message)
    return parts

# --- Ana Route'lar ---
@app.route("/")
@login_required
def home():
    # Son aktiviteyi güncelle
    current_user.last_active = datetime.utcnow()
    db.session.commit()
    
    # Firebase'den geçmişi al
    chat_history = get_chat_history_from_firebase(current_user.id)
    
    return render_template("index.html", 
                         username=current_user.username,
                         chat_history=chat_history,
                         is_premium=current_user.is_premium)

@app.route("/chat", methods=["POST"])
@login_required
def chat():
    user_message = request.form.get('message', '')
    model_choice = request.form.get('model', '4.0 pro')
    image_file = request.files.get('image')
    conversation_id = request.form.get('conversation_id')

    if not user_message and not image_file:
        return Response("Lütfen bir mesaj veya resim gönderin.", status=400)

    try:
        real_model_name = MODEL_MAPPING.get(model_choice, "gemini-2.5-flash")
        
        # Firebase'e kullanıcı mesajını kaydet
        save_chat_to_firebase(current_user.id, {
            'role': 'user',
            'content': user_message,
            'model': model_choice,
            'has_image': bool(image_file)
        })

        content_parts = create_multimodal_content(user_message, image_file)
        if not content_parts:
            return Response("Gönderilecek geçerli içerik bulunamadı.", status=400)

        # Gelişmiş model konfigürasyonu
        generation_config = {
            "temperature": 0.9,
            "top_p": 0.95,
            "top_k": 40,
            "max_output_tokens": 8192,
        }

        model = genai.GenerativeModel(
            real_model_name, 
            system_instruction=SYSTEM_INSTRUCTION,
            generation_config=generation_config
        )

        # Session history yönetimi
        if 'chat_histories' not in session:
            session['chat_histories'] = {}
        
        history_key = f"{real_model_name}_{conversation_id or 'default'}"
        if history_key not in session['chat_histories']:
            session['chat_histories'][history_key] = []

        history_for_chat = [
            types.Content.from_dict(c) for c in session['chat_histories'][history_key]
        ]

        chat_session = model.start_chat(history=history_for_chat)
        response_stream = chat_session.send_message_stream(content_parts)

        def generate():
            full_response = ""
            for chunk in response_stream:
                if chunk.text:
                    full_response += chunk.text
                    yield chunk.text

            # History'yi güncelle
            user_content = types.Content(role="user", parts=content_parts)
            model_content = types.Content(
                role="model", 
                parts=[types.Part.from_text(full_response)]
            )
            
            current_history = session['chat_histories'][history_key]
            current_history.append(user_content.to_dict())
            current_history.append(model_content.to_dict())
            
            # History limiti (son 20 mesaj)
            if len(current_history) > 40:
                current_history = current_history[-40:]
            
            session['chat_histories'][history_key] = current_history
            session.modified = True

            # Firebase'e AI yanıtını kaydet
            save_chat_to_firebase(current_user.id, {
                'role': 'assistant',
                'content': full_response,
                'model': model_choice
            })

        return Response(generate(), mimetype='text/plain')

    except Exception as e:
        import traceback
        traceback.print_exc()
        return Response(f"Mesaj gönderilirken bir hata oluştu: {str(e)}", status=500)

@app.route("/generate_image", methods=["POST"])
@login_required
def generate_image():
    try:
        data = request.json
        prompt = data.get('prompt')
        style = data.get('style', 'vivid')  # vivid veya natural
        aspect_ratio = data.get('aspect_ratio', '1:1')

        if not prompt:
            return jsonify({'error': 'Lütfen bir resim oluşturma komutu girin.'}), 400

        # Prompt enhancement
        enhanced_prompt = f"High quality, detailed, professional: {prompt}"

        result = client.models.generate_images(
            model='imagen-3.0-generate-002',
            prompt=enhanced_prompt,
            config={
                "number_of_images": 1,
                "output_mime_type": "image/jpeg",
                "aspect_ratio": aspect_ratio,
                "safety_filter_level": "block_only_high"
            }
        )
        
        image_urls = []
        for image in result.generated_images:
            base64_image = b64encode(image.image.image_bytes).decode('utf-8')
            data_url = f"data:image/jpeg;base64,{base64_image}"
            image_urls.append(data_url)
            
        if image_urls:
            # Firebase'e kaydet
            save_chat_to_firebase(current_user.id, {
                'role': 'assistant',
                'type': 'image',
                'prompt': prompt,
                'image_url': image_urls[0]
            })
            
            return jsonify({
                'image_url': image_urls[0], 
                'prompt': prompt,
                'enhanced_prompt': enhanced_prompt
            })
        else:
            return jsonify({'error': 'Resim oluşturulamadı.'}), 500

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': f"Resim oluşturma hatası: {str(e)}"}), 500

# --- Konuşma Yönetimi ---
@app.route("/conversations", methods=["GET"])
@login_required
def get_conversations():
    """Kullanıcının konuşmalarını listele"""
    if not firebase_initialized:
        return jsonify([])
    
    try:
        ref = firebase_db.reference(f'conversations/{current_user.id}')
        conversations = ref.get() or {}
        return jsonify(list(conversations.values()))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/conversations/new", methods=["POST"])
@login_required
def new_conversation():
    """Yeni konuşma başlat"""
    conv_id = str(int(time.time()))
    if firebase_initialized:
        ref = firebase_db.reference(f'conversations/{current_user.id}/{conv_id}')
        ref.set({
            'id': conv_id,
            'title': 'Yeni Konuşma',
            'created_at': datetime.now().isoformat(),
            'message_count': 0
        })
    
    # Session history'yi temizle
    if 'chat_histories' in session:
        session['chat_histories'] = {}
    
    return jsonify({"id": conv_id, "status": "created"})

# --- Auth Route'ları ---
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember') == 'on'

        user = User.query.filter_by(username=username).first()

        if not user or not user.check_password(password):
            flash('Kullanıcı adı veya şifre hatalı.', 'danger')
            return redirect(url_for('login'))

        login_user(user, remember=remember, duration=timedelta(days=30))
        user.last_active = datetime.utcnow()
        db.session.commit()
        
        return redirect(url_for('home'))

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')

        if not username or not password:
            flash('Kullanıcı adı ve şifre gereklidir.', 'warning')
            return redirect(url_for('register'))

        if len(password) < 6:
            flash('Şifre en az 6 karakter olmalıdır.', 'warning')
            return redirect(url_for('register'))

        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing_user:
            flash('Bu kullanıcı adı veya email zaten kullanılıyor.', 'warning')
            return redirect(url_for('register'))

        new_user = User(username=username, email=email)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()

        flash('Hesabınız başarıyla oluşturuldu!', 'success')
        return redirect(url_for('login'))

    return render_template("register.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- Hata Yönetimi ---
@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404, message="Sayfa bulunamadı"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', code=500, message="Sunucu hatası"), 500

# --- Uygulamayı Çalıştırma ---
if __name__ == "__main__":
    # Keep-alive thread'ini başlat (Render için)
    if os.environ.get('RENDER'):
        threading.Thread(target=keep_alive, daemon=True).start()
        print("🚀 Keep-alive servisi başlatıldı")
    
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
