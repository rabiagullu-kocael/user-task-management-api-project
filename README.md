# user-task-management-api-project


# 🧑‍💻 User Task Management API

**FastAPI + MongoDB + JWT Authentication**

---

## 📌 Proje Tanımı

Bu proje, kullanıcı bazlı görev yönetimi yapabilen, JWT ile kimlik doğrulama içeren, güvenli ve stateless bir RESTful API uygulamasıdır.

Sistem aşağıdaki prensipler üzerine kurulmuştur:

* Stateless authentication (JWT)
* Kullanıcı bazlı veri izolasyonu
* Güvenli şifre saklama (bcrypt hashing)
* Query parametreleri ile filtreleme ve sıralama
* Environment variable tabanlı konfigürasyon

Bu proje, modern backend geliştirme süreçlerinde kullanılan temel mimari yaklaşımları içermektedir.

---

# 🏗 Mimari Yapı

Sistem aşağıdaki akışa göre çalışır:

Client
↓
FastAPI Router
↓
Dependency Injection (JWT doğrulama)
↓
MongoDB Query Layer
↓
Response Serialization

Temel mimari kararlar:

* JWT ile stateless authentication
* Her kullanıcı sadece kendi verisine erişebilir
* Şifreler hashlenerek saklanır (plaintext asla tutulmaz)
* MongoDB sorgularında kullanıcı ID bazlı filtreleme zorunludur

---

# 🛠 Kullanılan Teknolojiler

* **FastAPI** → ASGI tabanlı modern Python web framework
* **Uvicorn** → ASGI server
* **MongoDB Atlas** → Cloud NoSQL veritabanı
* **pymongo** → MongoDB driver
* **python-jose** → JWT encode/decode işlemleri
* **passlib + bcrypt** → Güvenli şifre hashleme
* **python-dotenv** → Ortam değişkeni yönetimi

---

# ⚙️ Konfigürasyon Yönetimi

Proje içerisinde hassas bilgiler `.env` dosyasında tutulur:

```env
MONGODB_URL=" "
DATABASE_NAME=user_task_db
SECRET_KEY=your_secret_key
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
```

Bu yaklaşımın amacı:

* Secret bilgilerin versiyon kontrolüne eklenmemesi
* Production ve development ortamlarının ayrıştırılması
* 12-Factor App prensiplerine uygunluk

---




# 🔐 Kimlik Doğrulama Mekanizması

## 1️⃣ Register Endpoint

* Kullanıcı şifresi bcrypt ile hashlenir.
* Hashlenmiş şifre MongoDB’de saklanır.
* Aynı email ile ikinci kayıt engellenir (unique kontrol önerilir).

Veritabanına kaydedilen yapı:

```json
{
  "_id": ObjectId,
  "email": "user@example.com",
  "password": "hashed_password"
}
```



---

## 2️⃣ Login Endpoint

* Girilen şifre hash ile karşılaştırılır.
* Doğruysa JWT token üretilir.
* Token payload içerisinde `user_id` ve `exp` bilgisi bulunur.

Örnek payload:

```json
{
  "user_id": "6994af4d25fb90a4e912e590",
  "exp": 1771353813
}

```



JWT ile sistem stateless çalışır; sunucu tarafında session tutulmaz.

---

## 3️⃣ Protected Endpoint Erişimi

`Depends(get_current_user)` mekanizması ile:

* Authorization header’dan Bearer token alınır.
* Token decode edilir.
* user_id çıkarılır.
* Geçerli kullanıcı bilgisi request lifecycle’ına eklenir.

Bu yapı FastAPI’nin Dependency Injection sistemini kullanır.

---



# 📋 Görev (Task) İşlemleri

## ➕ Görev Oluşturma

* Giriş yapan kullanıcıya otomatik olarak bağlanır.
* user_id manuel girilmez.
* Güvenlik açısından user_id client tarafından belirlenemez.

Veritabanı yapısı:

```json
{
  "_id": ObjectId,
  "title": "Task title",
  "description": "Task description",
  "status": "pending",
  "user_id": "user_object_id",
  "created_at": "datetime"
}
```



---

## 📄 Görev Listeleme

Endpoint:

```
GET /tasks
```

Temel query:

```python
query = {"user_id": str(current_user["_id"])}
```

Bu tasarım sayesinde:

* Kullanıcı yalnızca kendi görevlerini görebilir.
* Başka kullanıcı verilerine erişim mümkün değildir.

---

## 🔎 Filtreleme

```
GET /tasks?status=pending
```

Backend tarafında:

```python
if status:
    query["status"] = status
```

Bu yapı dinamik MongoDB query üretir.

---

## ↕ Sıralama

```
GET /tasks?sort_by=created_at
```

```python
tasks = tasks.sort(sort_by, 1)
```

* 1 → artan
* -1 → azalan

Sorting parametresinin whitelist ile sınırlandırılması production ortamında önerilir.

---



# 🔐 Güvenlik Prensipleri

* Şifreler plaintext saklanmaz.
* JWT expiration süresi vardır.
* Kullanıcı bazlı veri izolasyonu zorunludur.
* Secret key environment variable’da tutulur.
* Stateless authentication uygulanır.

---

# 📊 REST API Tasarım Prensipleri

* HTTP metodları doğru kullanılmıştır.
* Endpoint isimlendirmeleri resource bazlıdır.
* Query parametreleri ile filtreleme yapılır.
* Response JSON formatındadır.

---

# 📦 Kurulum

```bash
pip install -r requirements.txt
uvicorn main:app --reload
```

Swagger:

```
http://127.0.0.1:8000/docs
```

---

# 🧠 Bu Projede Uygulanan Backend Konseptleri

* RESTful API tasarımı
* JWT Authentication
* Dependency Injection
* MongoDB CRUD
* Query-based filtering
* Sorting
* Environment variable management
* Secure password hashing
* Stateless architecture

---
<
