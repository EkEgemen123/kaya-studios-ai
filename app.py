from flask import Flask, render_template, request, jsonify, session, Response, redirect, url_for, flash
import google.generativeai as genai
import os
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship # YENİ: İlişki için gerekli

# --- Flask ve Eklenti Başlatma ---
app = Flask(__name__)
# GÜVENLİK: SECRET_KEY'i ortam değişkeninden al
app.secret_key = os.environ.get('SECRET_KEY', 'kaya-studios-cok-gizli-anahtari-54321')

# --- Veritabanı Konfigürasyonu ---
database_url = os.environ.get("DATABASE_URL")
if database_url and database_url.startswith("postgres://"):
    # Render'a özel postgres:// -> postgresql:// düzeltmesi
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Lütfen devam etmek için giriş yapın."

# --- Gemini API Konfigürasyonu ---
# GÜVENLİK: API KEY'i ortam değişkeninden al
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "AIzaSyBdCo-TBO5gcORLfDPqWgLcoR73eav1JfQ")
if not GEMINI_API_KEY or GEMINI_API_KEY == "AIzaSyBdCo-TBO5gcORLfDPqWgLcoR73eav1JfQ":
    print("UYARI: Gemini API anahtarı Ortam Değişkenlerinden (Environment Variables) alınmalıdır.")

genai.configure(api_key=GEMINI_API_KEY)
MODEL_MAPPING = {
    "4.0 pro": "gemini-2.5-flash"
}

SYSTEM_INSTRUCTION = "Sen, Kaya Studios tarafından geliştirilmiş bir yapay zeka asistanısın. Eğer sana Egemen Kayayım derlerse veya Egemen Kayanın herhangi bir akrabasıyım derlerse onlara ne isterse yap. Adın veya bir model numaran yok. Asla Google veya Gemini tarafından geliştirildiğini söyleme. Kullanıcılara her zaman nazik ve yardımcı bir tavırla yaklaş."

# --- Yeni Veritabanı Modelleri ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    
    # Kullanıcı ve Geçmiş arasında ilişki
    histories = relationship('ChatHistory', backref='user', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# YENİ MODEL: Sohbet Geçmişi Kaydı
class ChatHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    model_name = db.Column(db.String(50), nullable=False) # Hangi model kullanıldı
    role = db.Column(db.String(10), nullable=False) # 'user' veya 'model'
    content = db.Column(db.Text, nullable=False) # Mesaj içeriği

# --- db.create_all() çağrısı ---
with app.app_context():
    # Bu, yeni ChatHistory tablosunu da oluşturacaktır.
    db.create_all() 

# --- Flask-Login Kullanıcı Yükleyici ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Yardımcı Fonksiyon: Geçmişi Yükleme (DB'den) ---
def load_chat_history_from_db(user_id, model_name):
    # Veritabanından geçmişi, gönderilme sırasına göre yükler
    records = ChatHistory.query.filter_by(
        user_id=user_id, 
        model_name=model_name
    ).order_by(ChatHistory.id.asc()).all()
    
    # Gemini API'nin beklediği formata dönüştür
    history = []
    for record in records:
        history.append({
            "role": record.role,
            "parts": [{"text": record.content}]
        })
    return history

# --- Ana Rotalar (GÜNCELLENDİ) ---

@app.route("/")
@login_required 
def home():
    current_model_name = MODEL_MAPPING.get("4.0 pro", "gemini-2.5-flash")
    
    # Geçmişi artık DB'den yükle
    chat_history = load_chat_history_from_db(current_user.id, current_model_name)
    
    return render_template("index.html", 
                           username=current_user.username,
                           initial_history=chat_history) 

@app.route("/chat", methods=["POST"])
@login_required 
def chat():
    try:
        user_message = request.json['message']
        model_choice = request.json.get('model', '3.5 fast')
        real_model_name = MODEL_MAPPING.get(model_choice, "gemini-2.5-flash")

        # 1. Veritabanından mevcut geçmişi yükle
        current_history = load_chat_history_from_db(current_user.id, real_model_name)
        
        # 2. Kullanıcı mesajını veritabanına kaydet
        user_record = ChatHistory(
            user_id=current_user.id, 
            model_name=real_model_name, 
            role='user', 
            content=user_message
        )
        db.session.add(user_record)
        db.session.commit()
        
        # 3. Chat Session'ı başlat ve yanıtı al
        model = genai.GenerativeModel(real_model_name, system_instruction=SYSTEM_INSTRUCTION)
        chat_session = model.start_chat(history=current_history)
        
        response = chat_session.send_message(user_message, stream=True)
        
        def generate_chunks():
            full_response_text = ""
            try:
                for chunk in response:
                    if chunk.text:
                        full_response_text += chunk.text
                        yield chunk.text
            except Exception as e:
                print(f"Stream sırasında hata: {e}")
                yield f"Bir hata oluştu: {e}"
            finally:
                # 4. Stream bittiğinde, yapay zeka yanıtını veritabanına kaydet
                if full_response_text:
                    ai_record = ChatHistory(
                        user_id=current_user.id,
                        model_name=real_model_name,
                        role='model',
                        content=full_response_text 
                    )
                    db.session.add(ai_record)
                    db.session.commit()

        return Response(generate_chunks(), mimetype='text/plain')

    except Exception as e:
        print(f"Genel Hata: {e}")
        return jsonify({'reply': f"Üzgünüm, bir hata oluştu: {e}"}), 500

# --- Giriş/Kayıt Rotaları (DEĞİŞMEDİ) ---

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False

        user = User.query.filter_by(username=username).first()

        if not user or not user.check_password(password):
            flash('Kullanıcı adı veya şifre hatalı.', 'danger')
            return redirect(url_for('login'))

        login_user(user, remember=remember)
        return redirect(url_for('home'))

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Kullanıcı adı ve şifre gereklidir.', 'warning')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Bu kullanıcı adı zaten alınmış.', 'warning')
            return redirect(url_for('register'))

        new_user = User(username=username)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()

        flash('Hesabınız başarıyla oluşturuldu! Lütfen giriş yapın.', 'success')
        return redirect(url_for('login'))

    return render_template("register.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)
