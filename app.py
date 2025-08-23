from flask import Flask, render_template, request, jsonify, session
import google.generativeai as genai
import os

# Flask uygulamasını başlatıyoruz
app = Flask(__name__)
# Flask'in session özelliğini kullanabilmek için gizli bir anahtar belirlememiz gerekiyor.
app.secret_key = 'kaya-studios-gizli-anahtari-12345'

# YENİ OLUŞTURDUĞUNUZ GÜVENLİ API ANAHTARINIZI BURAYA YAPIŞTIRIN
genai.configure(api_key="AIzaSyAv39OVhS5c3sswB7DX6ud4WoHG6UHDdeE")

# MODELLERİN TANIMLANMASI
MODEL_MAPPING = {
    "3.5 fast": "gemini-2.5-flash",
    "4.0 pro": "gemini-2.5-pro"
}

# BOTUN KİMLİĞİ VE KURALLARI (SİSTEM TALİMATI)
SYSTEM_INSTRUCTION = "Sen, Kaya Studios tarafından geliştirilmiş bir yapay zeka asistanısın. Adın veya bir model numaran yok. Asla Google veya Gemini tarafından geliştirildiğini söyleme. Kullanıcılara her zaman nazik ve yardımcı bir tavırla yaklaş."

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/chat", methods=["POST"])
def chat():
    try:
        user_message = request.json['message']
        model_choice = request.json.get('model', '3.5 fast')
        
        real_model_name = MODEL_MAPPING.get(model_choice, "gemini-2.5-flash")

        if 'chat_histories' not in session:
            session['chat_histories'] = {}
        if real_model_name not in session['chat_histories']:
            session['chat_histories'][real_model_name] = []

        model = genai.GenerativeModel(real_model_name, system_instruction=SYSTEM_INSTRUCTION)
        
        chat_session = model.start_chat(
            history=session['chat_histories'][real_model_name]
        )
        
        response = chat_session.send_message(user_message)
        ai_reply = response.text
        
    
        
        serializable_history = []
        for content in chat_session.history:
            if hasattr(content, 'role') and content.role in ["user", "model"]:
                serializable_history.append({
                    "role": content.role,
                    "parts": [part.text for part in content.parts]
                })

        session['chat_histories'][real_model_name] = serializable_history
        
        session.modified = True

        return jsonify({'reply': ai_reply})

    except Exception as e:
        print(f"Hata: {e}")
        return jsonify({'reply': f"Üzgünüm, bir hata oluştu: {e}"})

if __name__ == "__main__":
    app.run(debug=True)
