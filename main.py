# ==============================
# GEREKLİ IMPORTLAR
# ==============================


from fastapi import FastAPI, HTTPException, Depends, status, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from bson import ObjectId
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import JWTError, jwt
from dotenv import load_dotenv
import os


# ==============================
# ENV DOSYASINI YÜKLE
# ==============================

load_dotenv()



MONGODB_URL = os.getenv("MONGODB_URL")
DATABASE_NAME = os.getenv("DATABASE_NAME")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES")




# ==============================
# ENV VALIDATION 
# ==============================

if not all([MONGODB_URL, DATABASE_NAME, SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES]):
    raise Exception("ENV değişkenleri eksik! .env dosyasını kontrol et.")

ACCESS_TOKEN_EXPIRE_MINUTES = int(ACCESS_TOKEN_EXPIRE_MINUTES)


# ==============================
# FASTAPI APP OLUŞTUR
# ==============================

app = FastAPI(title="Advanced User Task Management API")


# ==============================
# DATABASE BAĞLANTISI
# ==============================

try:
    client = MongoClient(MONGODB_URL)
    client.admin.command("ping")  # Bağlantı test
    print("MongoDB bağlantısı başarılı ✅")
except ConnectionFailure:
    raise Exception("MongoDB bağlantısı başarısız ❌ URI veya Atlas IP ayarını kontrol et.")

db = client[DATABASE_NAME]

users_collection = db["users"]
tasks_collection = db["tasks"]


# ==============================
# PASSWORD HASH AYARLARI
# ==============================

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str):
    """Şifreyi bcrypt ile hashler"""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str):
    """Girilen şifre ile hashli şifreyi karşılaştırır"""
    return pwd_context.verify(plain_password, hashed_password)


# ==============================
# JWT TOKEN OLUŞTURMA
# ==============================

def create_access_token(data: dict):
    """JWT access token üretir"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


security = HTTPBearer()


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Authorization header'dan token alır,
    decode eder ve kullanıcıyı döndürür.
    """
    token = credentials.credentials

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("user_id")

        if user_id is None:
            raise HTTPException(status_code=401, detail="Geçersiz token")

    except JWTError:
        raise HTTPException(status_code=401, detail="Token doğrulanamadı")

    user = users_collection.find_one({"_id": ObjectId(user_id)})

    if user is None:
        raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")

    return user


# ==============================
# AUTH ENDPOINTLERİ
# ==============================

@app.post("/register")
def register(
    email: str = Query(...),
    password: str = Query(...)
):
    """
    Yeni kullanıcı kaydı oluşturur.
    Şifre hashlenerek saklanır.
    """

    if users_collection.find_one({"email": email}):
        raise HTTPException(status_code=400, detail="Bu email zaten kayıtlı")

    hashed_pw = hash_password(password)

    user_data = {
        "email": email,
        "password": hashed_pw,
        "created_at": datetime.utcnow()
    }

    result = users_collection.insert_one(user_data)

    return {
        "message": "Kullanıcı oluşturuldu",
        "user_id": str(result.inserted_id)
    }


@app.post("/login")
def login(
    email: str = Query(...),
    password: str = Query(...)
):
    """
    Kullanıcı giriş yapar.
    Doğruysa JWT token döndürülür.
    """

    user = users_collection.find_one({"email": email})

    if not user:
        raise HTTPException(status_code=400, detail="Email veya şifre hatalı")

    if not verify_password(password, user["password"]):
        raise HTTPException(status_code=400, detail="Email veya şifre hatalı")

    access_token = create_access_token(
        {"user_id": str(user["_id"])}
    )

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }


# ==============================
# TASK ENDPOINTLERİ
# ==============================

@app.post("/tasks")
def create_task(
    title: str = Query(...),
    description: str = Query(...),
    status: str = Query("pending"),
    current_user: dict = Depends(get_current_user)
):
    """
    Giriş yapan kullanıcı için yeni görev oluşturur.
    """

    task_data = {
        "title": title,
        "description": description,
        "status": status,
        "user_id": str(current_user["_id"]),
        "created_at": datetime.utcnow()
    }

    result = tasks_collection.insert_one(task_data)

    return {
        "message": "Görev oluşturuldu",
        "task_id": str(result.inserted_id)
    }


@app.get("/tasks")
def get_tasks(
    status: str = None,
    sort_by: str = None,
    current_user: dict = Depends(get_current_user)
):
    """
    Kullanıcının görevlerini listeler.
    İsteğe bağlı filtreleme ve sıralama yapılabilir.
    """

    query = {"user_id": str(current_user["_id"])}

    if status:
        query["status"] = status

    tasks = tasks_collection.find(query)

    if sort_by:
        tasks = tasks.sort(sort_by, 1)

    task_list = []

    for task in tasks:
        task["_id"] = str(task["_id"])
        task_list.append(task)

    return task_list



