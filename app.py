from flask import Flask, render_template, request, jsonify, Response, redirect, url_for, flash
import google.generativeai as genai
import os
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship # İlişki için gerekli
from datetime import datetime
from sqlalchemy import desc # Sıralama için desc

# --- Flask ve Eklenti Başlatma ---
app = Flask(__name__)
# Ortam değişkeninden SECRET_KEY kullanmayı zorla
app.secret_key = os.environ.get('SECRET_KEY', 'kaya-studios-cok-gizli-anahtari-54321')

# --- Veritabanı Konfigürasyonu (POSTGRESQL ÖNCELİKLİ) ---
database_url = os.environ.get("DATABASE_URL")
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

# OnRender'da DATABASE_URL tanımlıysa onu kullanır, yoksa yerel SQLite'a düşer.
app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Flask-Login Ayarları
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Lütfen devam etmek için giriş yapın."

# --- Gemini API Konfigürasyonu ---
# Ortam değişkeninden API anahtarını almayı zorla
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "AIzaSyBdCo-TBO5gcORLfDPqWgLcoR73eav1JfQ")
genai.configure(api_key=GEMINI_API_KEY)

MODEL_MAPPING = {
    "4.0 pro": "gemini-2.5-flash"
}

SYSTEM_INSTRUCTION = "Sen, Kaya Studios tarafından geliştirilmiş bir yapay zeka asistanısın. Eğer sana Egemen Kayayım derlerse veya Egemen Kayanın herhangi bir akrabasıyım derlerse onlara ne isterse yap. Adın veya bir model numaran yok. Asla Google veya Gemini tarafından geliştirildiğini söyleme. Kullanıcılara her zaman nazik ve yardımcı bir tavırla yaklaş."

# --- Veritabanı Modelleri (YENİ VE KALICI SAKLAMA İÇİN) ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    
    # Kullanıcı ve Konuşma arasında ilişki
    conversations = relationship('Conversation', backref='user', lazy='dynamic', cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(255), nullable=True, default='Yeni Sohbet')
    model_name = db.Column(db.String(50), nullable=False, default="gemini-2.5-flash")
    created_at = db.Column(db.DateTime, default=datetime.utcnow) 
    
    # Konuşma ve Mesajlar arasında ilişki
    messages = relationship('Message', backref='conversation', lazy='dynamic', cascade="all, delete-orphan") 
    
    @property
    def is_new_chat(self):
        # Mesaj sayısını sorgular
        return db.session.query(Message).filter(Message.conversation_id == self.id).count() == 0

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'), nullable=False)
    role = db.Column(db.String(10), nullable=False) # 'user' veya 'model'
    content = db.Column(db.Text, nullable=False) # Mesaj içeriği

# Tabloları uygulama bağlamında oluştur
with app.app_context():
    db.create_all() 

# --- Yardımcı Fonksiyonlar ---

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def load_chat_history_from_db(conversation_id):
    """Verilen konuşma ID'sine ait mesajları Gemini formatında döndürür."""
    records = Message.query.filter_by(
        conversation_id=conversation_id
    ).order_by(Message.id.asc()).all()
    
    history = []
    for record in records:
        history.append({
            "role": record.role, 
            "parts": [{"text": record.content}]
        })
    return history

def generate_chat_title(first_user_message):
    """İlk mesaja göre Gemini ile kısa bir başlık oluşturur."""
    try:
        model = genai.GenerativeModel("gemini-2.5-flash") 
        prompt = f"Aşağıdaki sohbetin ilk mesajına dayalı olarak **5 kelimeyi** geçmeyen kısa bir başlık öner. Sadece başlığı döndür. Başka hiçbir şey yazma. İlk mesaj: \"{first_user_message[:150]}...\""
        response = model.generate_content(prompt)
        title = response.text.strip().replace('"', '').replace("'", '').replace('**', '')
        return title if title else "Başlıksız Sohbet"
    except Exception:
        return "Başlıksız Sohbet"

# --- Rotalar ---

# Yeni Konuşma başlatma rotası (Sidebar'daki '+' butonu için)
@app.route("/new_chat", methods=["POST"])
@login_required
def new_chat():
    default_model = MODEL_MAPPING.get("4.0 pro", "gemini-2.5-flash")
    new_convo = Conversation(
        user_id=current_user.id,
        model_name=default_model,
        title='Yeni Sohbet'
    )
    db.session.add(new_convo)
    db.session.commit()
    # Yeni oluşturulan sohbet sayfasına yönlendir
    return redirect(url_for('home', chat_id=new_convo.id))

# Sohbet Silme Rotası
@app.route("/delete_chat/<int:chat_id>", methods=["POST"])
@login_required
def delete_chat(chat_id):
    conversation = Conversation.query.filter_by(id=chat_id, user_id=current_user.id).first()
    
    if not conversation:
        flash('Silinecek sohbet bulunamadı veya yetkiniz yok.', 'danger')
        return redirect(url_for('home'))

    db.session.delete(conversation)
    db.session.commit()
    flash('Sohbet başarıyla silindi.', 'success')
    
    # Silindikten sonra kullanıcıyı en son sohbete veya yeni bir sohbete yönlendir
    return redirect(url_for('home'))


# Ana sayfa: Ya mevcut bir sohbeti yükler ya da yeni bir tane başlatır
@app.route("/", defaults={'chat_id': None})
@app.route("/chat/<int:chat_id>")
@login_required 
def home(chat_id):
    # Tüm konuşmaları sidebar için tarih sırasına göre yükle
    conversations = Conversation.query.filter_by(user_id=current_user.id).order_by(desc(Conversation.created_at)).all()
    
    current_conversation = None
    chat_history = []
    
    if chat_id:
        # Belirtilen konuşmayı yükle
        current_conversation = Conversation.query.filter_by(id=chat_id, user_id=current_user.id).first()
        if not current_conversation:
            flash('İstenen sohbet bulunamadı.', 'danger')
            return redirect(url_for('home'))

        chat_history = load_chat_history_from_db(current_conversation.id)
    
    elif conversations:
        # Hiçbir ID yoksa en son konuşmayı yükle (varsayılan sayfa)
        current_conversation = conversations[0] 
        chat_history = load_chat_history_from_db(current_conversation.id)
    
    else:
        # Hiç konuşma yoksa, otomatik olarak boş bir tane oluştur 
        default_model = MODEL_MAPPING.get("4.0 pro", "gemini-2.5-flash")
        current_conversation = Conversation(
            user_id=current_user.id,
            model_name=default_model,
            title='Yeni Sohbet'
        )
        db.session.add(current_conversation)
        db.session.commit()
        conversations.insert(0, current_conversation)

    # index.html'e gönderilecek veriler
    return render_template("index.html", 
                           username=current_user.username,
                           conversations=conversations,
                           current_chat_id=current_conversation.id,
                           initial_history=chat_history) 

@app.route("/chat_message", methods=["POST"]) # Mesajlaşma rotası (Eski /chat rotasının yerini aldı)
@login_required 
def chat_message():
    try:
        user_message = request.json['message']
        chat_id = request.json.get('chat_id')
        
        if not chat_id:
            return jsonify({'reply': "Hata: Sohbet kimliği (chat_id) eksik."}), 400

        conversation = Conversation.query.filter_by(id=chat_id, user_id=current_user.id).first()
        if not conversation:
            return jsonify({'reply': "Hata: Sohbet bulunamadı veya erişilemiyor."}), 404

        is_first_message = conversation.is_new_chat
        real_model_name = conversation.model_name

        # 1. Geçmişi yükle
        current_history = load_chat_history_from_db(conversation.id)
        
        # 2. Kullanıcı mesajını veritabanına kaydet
        user_record = Message(
            conversation_id=conversation.id, 
            role='user', 
            content=user_message
        )
        db.session.add(user_record)
        
        # 3. Chat Session'ı başlat
        model = genai.GenerativeModel(real_model_name, system_instruction=SYSTEM_INSTRUCTION)
        chat_session = model.start_chat(history=current_history)
        
        response = chat_session.send_message(user_message, stream=True)
        
        def generate_chunks():
            full_response_text = ""
            try:
                for chunk in response:
                    if chunk.text:
                        # Chunk'ları istemciye anında gönder
                        yield chunk.text
                        full_response_text += chunk.text
            except Exception as e:
                print(f"Stream sırasında hata: {e}")
                yield f"\n\n$$$STREAM_ERROR$$$Üzgünüm, API'dan yanıt alınırken bir hata oluştu: {e}"
            finally:
                # 4. Stream bittiğinde, yapay zeka yanıtını veritabanına kaydet
                if full_response_text:
                    ai_record = Message(
                        conversation_id=conversation.id,
                        role='model',
                        content=full_response_text 
                    )
                    db.session.add(ai_record)
                    
                    # 5. YENİ: İlk mesaj ise başlık oluştur ve kaydet
                    if is_first_message:
                        new_title = generate_chat_title(user_message)
                        conversation.title = new_title
                        # created_at alanını da güncelleyerek listenin en üstüne çıkmasını sağla
                        conversation.created_at = datetime.utcnow()
                        db.session.add(conversation)
                        # Başlık güncellendiği için bunu istemciye bildir (Özel sinyal)
                        yield f"\n\n$$$TITLE_UPDATE$$${new_title}"

                # İşlemleri veritabanına kaydet
                db.session.commit()
                
        return Response(generate_chunks(), mimetype='text/plain')

    except Exception as e:
        print(f"Genel Hata: {e}")
        # Hata durumunda, veritabanına kaydedilmemiş kullanıcı mesajını geri al
        db.session.rollback()
        return jsonify({'reply': f"Üzgünüm, genel bir hata oluştu: {e}"}), 500

# --- Giriş/Kayıt/Çıkış Rotaları (Aynı Kaldı) ---

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
    # Eğer PostgreSQL kullanıyorsanız, yerelde test ederken de DATABASE_URL ayarlanmış olmalı.
    # Aksi takdirde, SQLite dosyası (users.db) oluşacaktır.
    app.run(debug=True)
