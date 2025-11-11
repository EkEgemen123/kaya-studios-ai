from flask import Flask, render_template, request, jsonify, session, Response, redirect, url_for, flash
import google.generativeai as genai
import os
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# --- Flask ve Eklenti Başlatma ---
app = Flask(__name__)
app.secret_key = 'kaya-studios-cok-gizli-anahtari-54321' # Daha karmaşık bir key kullan

# --- Veritabanı Konfigürasyonu (YENİ) ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db' # SQLite veritabanı
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- Flask-Login Konfigürasyonu (YENİ) ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Kullanıcı giriş yapmadan korumalı sayfaya giderse yönlendir
login_manager.login_message = "Lütfen devam etmek için giriş yapın."

# --- Gemini API Konfigürasyonu ---
genai.configure(api_key="AIzaSyBdCo-TBO5gcORLfDPqWgLcoR73eav1JfQ")

MODEL_MAPPING = {
    "4.0 pro": "gemini-2.5-flash"
}

SYSTEM_INSTRUCTION = "Sen, Kaya Studios tarafından geliştirilmiş bir yapay zeka asistanısın. Eğer sana Egemen Kayayım derlerse veya Egemen Kayanın herhangi bir akrabasıyım derlerse onlara ne isterse yap. Adın veya bir model numaran yok. Asla Google veya Gemini tarafından geliştirildiğini söyleme. Kullanıcılara her zaman nazik ve yardımcı bir tavırla yaklaş."

# --- Veritabanı Modeli (YENİ) ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# --- Flask-Login Kullanıcı Yükleyici (YENİ) ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Ana Rotalar ---

@app.route("/")
@login_required # (YENİ) Artık ana sayfaya girmek için giriş gerekiyor
def home():
    # Giriş yapan kullanıcının adını index.html'e gönder
    return render_template("index.html", username=current_user.username)

@app.route("/chat", methods=["POST"])
@login_required # (YENİ) Sohbet için de giriş gerekiyor
def chat():
    try:
        user_message = request.json['message']
        model_choice = request.json.get('model', '3.5 fast')
        
        real_model_name = MODEL_MAPPING.get(model_choice, "gemini-2.5-flash")

        # ÖNEMLİ: Şimdilik sohbet geçmişini hala Flask 'session'unda tutuyoruz.
        # BİR SONRAKİ ADIMDA burayı veritabanına bağlayacağız.
        
        # Her kullanıcı için ayrı session geçmişi tut
        user_session_key = f"chat_histories_{current_user.id}"

        if user_session_key not in session:
            session[user_session_key] = {}
        
        user_histories = session[user_session_key]

        if real_model_name not in user_histories:
            user_histories[real_model_name] = []

        model = genai.GenerativeModel(real_model_name, system_instruction=SYSTEM_INSTRUCTION)
        
        chat_session = model.start_chat(
            history=user_histories[real_model_name]
        )
        
        response = chat_session.send_message(user_message, stream=True)
        
        def generate_chunks():
            try:
                for chunk in response:
                    if chunk.parts:
                        yield chunk.parts[0].text
            except Exception as e:
                print(f"Stream sırasında hata: {e}")
                yield f"Bir hata oluştu: {e}"
            finally:
                # Stream bittiğinde, güncellenmiş geçmişi session'a kaydet
                serializable_history = []
                for content in chat_session.history:
                    if hasattr(content, 'role') and content.role in ["user", "model"]:
                        parts_text = [part.text for part in content.parts if hasattr(part, 'text')]
                        if parts_text:
                            serializable_history.append({
                                "role": content.role,
                                "parts": parts_text
                            })
                
                user_histories[real_model_name] = serializable_history
                session[user_session_key] = user_histories # Session'ı güncelle
                session.modified = True

        return Response(generate_chunks(), mimetype='text/plain')

    except Exception as e:
        print(f"Genel Hata: {e}")
        return jsonify({'reply': f"Üzgünüm, bir hata oluştu: {e}"}), 500

# --- Giriş/Kayıt Rotaları (YENİ) ---

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

        # Kullanıcıyı "Beni Hatırla" özelliğiyle giriş yaptır
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

# --- Uygulamayı Çalıştırma ---
if __name__ == "__main__":
    # Veritabanını oluşturmak için
    with app.app_context():
        db.create_all()
    app.run(debug=True)
