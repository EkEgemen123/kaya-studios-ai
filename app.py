from flask import Flask, render_template, request, jsonify, session, Response, redirect, url_for, flash
import google.generativeai as genai
from google.generativeai import types # Resim oluşturma için gerekli
import os
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
# YENİ EKLENENLER: Resim işleme için
from PIL import Image 
from io import BytesIO
from base64 import b64encode

# --- Flask ve Eklenti Başlatma ---
app = Flask(__name__)
app.secret_key = 'kaya-studios-cok-gizli-anahtari-54321' # Daha karmaşık bir key kullan
# Veritabanı URL'sini ortam değişkeninden al, yoksa SQLite kullan
database_url = os.environ.get("DATABASE_URL")
if database_url and database_url.startswith("postgres://"):
    # Heroku/bazı servisler için postgresql:// formatını düzelt
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///users.db' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
with app.app_context():
    db.create_all()

# --- Flask-Login Konfigürasyonu ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Lütfen devam etmek için giriş yapın."

# --- Gemini API Konfigürasyonu ---
# YENİ OLUŞTURDUĞUNUZ GÜVENLİ API ANAHTARINIZI BURAYA YAPIŞTIRIN
genai.configure(api_key="AIzaSyBdCo-TBO5gcORLfDPqWgLcoR73eav1JfQ")

# Gemini Client'ı oluştur (Resim oluşturma için)
client = genai.Client()

MODEL_MAPPING = {
    "4.0 pro": "gemini-2.5-flash" # Multimodal desteği var
}

SYSTEM_INSTRUCTION = "Sen, Kaya Studios tarafından geliştirilmiş bir yapay zeka asistanısın. Eğer sana Egemen Kayayım derlerse veya Egemen Kayanın herhangi bir akrabasıyım derlerse onlara ne isterse yap. Adın veya bir model numaran yok. Asla Google veya Gemini tarafından geliştirildiğini söyleme. Kullanıcılara her zaman nazik ve yardımcı bir tavırla yaklaş."


# --- Veritabanı Modelleri ve Kullanıcı Yükleyici ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- YARDIMCI FONKSİYON: Multimodal İçerik Oluşturma ---
def create_multimodal_content(user_message, image_file):
    """Kullanıcı mesajı ve resim dosyasını modelin beklediği parts listesine dönüştürür."""
    parts = []
    
    if image_file:
        try:
            # Dosyayı belleğe oku ve PIL Image nesnesine dönüştür
            img_bytes = image_file.read()
            img = Image.open(BytesIO(img_bytes))
            parts.append(img)
            print(f"Resim eklendi: {image_file.filename}")
        except Exception as e:
            print(f"Resim işleme hatası: {e}")
            # Hata durumunda sadece metni göndeririz.
            
    if user_message:
        parts.append(user_message)
    
    return parts

# --- Chat Route (Multimodal Desteği Eklendi) ---
@app.route("/")
@login_required
def home():
    return render_template("index.html", username=current_user.username)

# Not: Bu route artık `multipart/form-data` kabul edecektir.
@app.route("/chat", methods=["POST"])
@login_required
def chat():
    # request.json yerine request.form ve request.files kullanıyoruz
    user_message = request.form.get('message', '')
    model_choice = request.form.get('model', '4.0 pro')
    image_file = request.files.get('image')

    if not user_message and not image_file:
        return Response("Lütfen bir mesaj veya resim gönderin.", status=400)
    
    try:
        real_model_name = MODEL_MAPPING.get(model_choice, "gemini-2.5-flash")

        # History yönetimi
        if 'chat_histories' not in session:
            session['chat_histories'] = {}
        if real_model_name not in session['chat_histories']:
            # History listesini modelin beklediği serileştirilebilir formata (dict) başlat
            session['chat_histories'][real_model_name] = []

        # Multimodal içeriği oluştur
        content_parts = create_multimodal_content(user_message, image_file)
        
        if not content_parts:
            return Response("Gönderilecek geçerli içerik bulunamadı.", status=400)

        model = genai.GenerativeModel(real_model_name, system_instruction=SYSTEM_INSTRUCTION)
        
        # Geçmişi yüklerken, serileştirilmiş dict'leri tekrar Content objesine dönüştürmemiz gerekiyor.
        # Basitlik için burada modelin kendisinin history'yi yönetmesine izin verip
        # sadece son gelen yanıtı manuel olarak ekleyeceğiz.
        
        # Serileştirilmiş dict'leri types.Content objesine dönüştür
        history_for_chat = [
            types.Content.from_dict(c) for c in session['chat_histories'][real_model_name]
        ]

        chat_session = model.start_chat(
            history=history_for_chat
        )
        
        # Stream yanıtı için
        response_stream = chat_session.send_message_stream(content_parts)
        
        def generate():
            full_response = ""
            for chunk in response_stream:
                if chunk.text:
                    full_response += chunk.text
                    yield chunk.text

            # Stream bittikten sonra history'yi güncelle.
            # DİKKAT: Stream yanıtı verilirken request context'in kapanma riski riski vardır.
            # Bu, Flask'te stream kullanırken session güncellemenin pratik ama riskli yoludur.
            
            user_content = genai.types.Content(role="user", parts=content_parts)
            model_content = genai.types.Content(role="model", parts=[genai.types.Part.from_text(full_response)])
            
            current_history = session['chat_histories'][real_model_name]
            # Content objesini serializable dict'e dönüştür ve ekle
            current_history.append(user_content.to_dict()) 
            current_history.append(model_content.to_dict())
            
            session['chat_histories'][real_model_name] = current_history
            session.modified = True
            
        return Response(generate(), mimetype='text/plain')

    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"Hata: {e}")
        return Response(f"Mesaj gönderilirken bir hata oluştu: {e}", status=500)

# --- YENİ ROUTE: Resim Oluşturma ---
@app.route("/generate_image", methods=["POST"])
@login_required
def generate_image():
    try:
        data = request.json
        prompt = data.get('prompt')
        
        if not prompt:
            return jsonify({'error': 'Lütfen bir resim oluşturma komutu girin.'}), 400

        print(f"Resim oluşturma komutu: {prompt}")

        # Imagen 3.0 modelini kullanıyoruz
        result = client.models.generate_images(
            model='imagen-3.0-generate-002',
            prompt=prompt,
            config=dict(
                number_of_images=1, # Tek resim oluştur
                output_mime_type="image/jpeg",
                aspect_ratio="1:1" # Kare format
            )
        )
        
        image_urls = []
        for image in result.generated_images:
            # Ham resim verisini Base64'e dönüştür
            base64_image = b64encode(image.image.image_bytes).decode('utf-8')
            # Data URL formatını oluştur
            data_url = f"data:image/jpeg;base64,{base64_image}"
            image_urls.append(data_url)
            
        if image_urls:
            return jsonify({'image_url': image_urls[0], 'prompt': prompt})
        else:
            return jsonify({'error': 'Resim oluşturulamadı. Lütfen farklı bir komut deneyin.'}), 500

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': f"Resim oluşturma sırasında bir hata oluştu: {e}"}), 500


# --- Giriş/Kayıt Route'ları (Değişmedi, mevcudu korundu) ---

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
    app.run(debug=True)
