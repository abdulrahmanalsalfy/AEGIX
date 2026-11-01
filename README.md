# AEGIX (SOC-AI Assistant)

> **An AI-Powered Assistant for Security Operations Center Analysts**  
> **مشروع تخرج البكالوريوس في الأمن السيبراني والأدلة الرقمية (2026 – 2027)**  
> **جامعة الناصر — كلية الهندسة وعلوم الحاسوب — قسم الحوسبة وتكنولوجيا المعلومات**  
> **إشراف:** أ.م.د. نشوان غالب الذبحاني (Dr. Nashwan Ghaleb Al-Thobhani)

---

## 1. نبذة عن المشروع (Project Overview)

يعالج مشروع **AEGIX** مشكلة تشتت محلل مركز عمليات الأمان (SOC Analyst) بين منصات متعددة، وبطء التحقيق اليدوي، وإرهاق التنبيهات (Alert Fatigue).  
يربط النظام بين ثلاث منصات أمنية رئيسية (**Splunk SIEM**, **Wazuh EDR/XDR**, **VirusTotal Threat Intelligence**) عبر واجهة محادثة ذكية مبنية على **LangChain** و**FastAPI** و**React**، مع الالتزام التام بالمبدأ الهندسي الصارم:  
**«النموذج يقترح والكود البرمجي يقرر (The model proposes and the code decides)».**

---

## 2. المبادئ الأمنية ومناطق الثقة (Trust Zones & Principles)

ينقسم النظام معمارياً إلى ثلاث مناطق ثقة رئيسية (الفصل الرابع - القسم 4.1):

* **المنطقة A (Zone A - Analyst Workstation)**: واجهة المحلل (React SPA) عبر قنوات HTTPS الآمنة وتوكنات JWT.
* **المنطقة B (Zone B - Trusted AEGIX Backend)**: خادم FastAPI، وقاعدة بيانات SQLite/SQLAlchemy (12 جدولاً)، وبوابة الأدوات (`Tool Gateway`)، ومدقق الـ SPL، وخدمة الموافقة البشرية (`Approval Service`).
* **المنطقة C (Zone C - External Untrusted Services)**: مزود النموذج اللغوي (OpenAI)، ومنصات Splunk وWazuh وVirusTotal. تُعامل جميع ردودها كـ **بيانات غير موثوقة** ولا تملك أي سلطة لاتخاذ القرارات.

### القواعد الأمنية الأربع (Section 4.1.1):
1. **النموذج يقترح والكود يقرر**: لا تُنفذ أي سياسة أمنية عبر موجه النظام فقط؛ التحقق بالكامل داخل كود الـ Backend.
2. **فصل مسارات القراءة عن التنفيذ**: يملك الوكيل الذكي 6 أدوات للقراءة وإنشاء مقترح معلق (`propose_action`) فقط، بينما منفذ العزل (`Action Executor`) معزول تماماً عن الوكيل ولا تستدعيه إلا خدمة الموافقة.
3. **مخرجات السجلات بيانات وليست تعليمات**: تُنقى جميع السجلات وتُقص عند سقف 4,000 حرف وتُغلف بوسم `UNTRUSTED_DATA` لمنع حقن الأوامر غير المباشر (`Indirect Prompt Injection - T1`).
4. **كل خطوة تترك أثراً**: تُسجل جميع العمليات في جدول `AUDIT_LOG` بتسلسل تجزئة تشفيري (`SHA-256 Hash Chain`) محمي بمشغلات تمنع التعديل والحذف نهائياً.

---

## 3. مصفوفة المسؤوليات للفريق التنفيذي (5 أعضاء)

| المسار والدور | العضو المسؤول | المكونات المعمارية والجداول المسندة | التسليم في الأسبوع الأول (Setup Only) |
| :--- | :--- | :--- | :--- |
| **قائد الفريق ومسؤول الذكاء الاصطناعي** | **عبدالرحمن محمد السلفي** | `Agent Service`, `Tool Gateway`, `Case-State Builder`, موجهات النظام | تأسيس المستودع، ملف الإعدادات `config.py`، وعقود الأدوات `schemas.py`. |
| **مسؤول الواجهة الخلفية (Backend)** | عضو الفريق (1) | `API Layer`, `Database (12 Tables)`, `Auth/RBAC`, `Audit Logger` | تأسيس تطبيق FastAPI، وبرمجة الجداول الـ 12 في `models.py` بـ SQLite. |
| **مسؤول صيد التهديدات (Threat Hunting)** | عضو الفريق (2) | `SPL Generator`, `SPL Validator (C1-C6)`, `Splunk Tool`, `VirusTotal` | أداة فحص المؤشرات `virustotal_tool.py` وتجربة الاتصال الأولي بالمختبر. |
| **مسؤول الواجهة الأمامية (Frontend)** | عضو الفريق (3) | `Frontend React SPA` (الشاشات السبع `S1` إلى `S7`) | تأسيس مشروع React + Tailwind وتصميم شاشة الدخول `S1 Login`. |
| **مسؤول المختبر الأمني (Lab)** | عضو الفريق (4) | بيئة المختبر المعزول (`Splunk` + `Wazuh` + Target Host) | تنصيب وتشغيل Splunk وWazuh في المختبر وتفعيل الوصول عبر الـ API. |

*(ملاحظة: عضو الفريق السادس أتم توثيق الفصول النظرية 1 إلى 4 ولن يشارك في المهام البرمجية).*

---

## 4. خطوات التثبيت والتشغيل المحلي (Quickstart Guide)

### أولاً: إعداد الواجهة الخلفية (Backend)

1. **إنشاء وتفعيل بيئة بايثون الافتراضية**:
   ```bash
   cd backend
   python3 -m venv venv
   source venv/bin/activate    # على لينكس / ماك
   # أو على ويندوز: venv\Scripts\activate
   ```

2. **تثبيت المتطلبات**:
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

3. **إعداد ملف المتغيرات البيئية (`.env`)**:
   ```bash
   # من المجلد الرئيسي للمشروع:
   cp .env.example .env
   # قم بتعديل ملف .env وإضافة مفاتيح المختبر الخاصة بك
   ```

4. **تشغيل خادم التطوير (FastAPI)**:
   ```bash
   uvicorn app.main:app --reload --port 8000
   ```
   * رابط التوثيق التفاعلي للـ API: `http://localhost:8000/docs`

---

## 5. قواعد المساهمة على مستودع Git (Git Workflow)

* **الفرع الرئيسي (`main`)**: يحتوي على الكود المختبر فقط؛ يُمنع الرفع المباشر عليه.
* **الفروع الجانبية (`Feature Branches`)**: ينشئ كل عضو فرعاً خاصاً بمساره (`feature/backend-models`, `feature/threat-hunting`, `feature/frontend-login`).
* **قاعدة عدم رفع الأسرار**: تأكد من عدم رفع ملف `.env` أو أي مفاتيح API أبداً؛ ملف `.gitignore` يقوم بحجبها تلقائياً.
