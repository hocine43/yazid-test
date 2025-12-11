Flask Course Platform - Quick Start

1. إنشاء بيئة افتراضية:
   python -m venv venv
   source venv/bin/activate   (Linux/macOS)
   venv\Scripts\activate      (Windows)

2. تثبيت المتطلبات:
   pip install -r requirements.txt

3. تهيئة الملف .env (انسخ .env.example إلى .env وعدّل القيم)

4. تشغيل محلياً:
   python app.py
   ثم افتح http://127.0.0.1:5000

5. لرفع على Render:
   - ارفع المشروع إلى GitHub.
   - أنشئ Web Service على Render وربطه بالمستودع.
   - في Env Vars ضع SECRET_KEY و ADMIN_PASSWORD.
   - Start Command: web: gunicorn app:app (Procfile يحتوي ذلك)

ملاحظات:
- استبدل مشغّل الفيديو بخدمة محمية مثل Vimeo Pro أو VdoCipher قبل الإنتاج.
- غيّر SECRET_KEY و ADMIN_PASSWORD و لا تشاركها.
