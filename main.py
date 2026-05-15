from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
)

from fastapi.middleware.cors import (
    CORSMiddleware,
)

from fastapi.security import (
    HTTPBearer,
    HTTPAuthorizationCredentials,
)

from datetime import (
    datetime,
    timedelta,
)

from bson import ObjectId

import string
import random
import smtplib
import os

from random import randint

from email.mime.text import MIMEText

from dotenv import load_dotenv

from database import (
    users_collection,
    links_collection,
    otp_collection,
)

from models import (
    UserRegister,
    UserLogin,
    OTPLoginRequest,
    SendOTPRequest,
    VerifyOTPRequest,
    ResetPasswordRequest,
    LinkCreate,
    LinkUpdate,
    TokenResponse,
)

from auth import (
    hash_password,
    verify_password,
    create_access_token,
    verify_token,
    get_user_by_id,
)

# ======================================================
# LOAD ENV
# ======================================================

load_dotenv()

# ======================================================
# APP
# ======================================================

app = FastAPI(
    title="NexSpace API"
)

# ======================================================
# ENV VARIABLES
# ======================================================

BASE_URL = os.getenv(
    "BASE_URL",
    "http://localhost:8000"
)

EMAIL = os.getenv(
    "EMAIL"
)

EMAIL_PASS = os.getenv(
    "EMAIL_PASS"
)

# ======================================================
# AUTH URLS
# ======================================================

AUTH_BASE = f"{BASE_URL}/api/auth"

REGISTER_URL = f"{AUTH_BASE}/register"

LOGIN_URL = f"{AUTH_BASE}/login"

LOGIN_OTP_URL = (
    f"{AUTH_BASE}/login-otp"
)

ME_URL = f"{AUTH_BASE}/me"

SEND_OTP_URL = (
    f"{AUTH_BASE}/send-otp"
)

VERIFY_OTP_URL = (
    f"{AUTH_BASE}/verify-otp"
)

RESET_PASSWORD_URL = (
    f"{AUTH_BASE}/reset-password"
)

# ======================================================
# LINKS URLS
# ======================================================

LINKS_BASE = (
    f"{BASE_URL}/api/links"
)

CREATE_LINK_URL = LINKS_BASE

GET_LINKS_URL = LINKS_BASE

UPDATE_LINK_URL = (
    f"{LINKS_BASE}/{{link_id}}"
)

DELETE_LINK_URL = (
    f"{LINKS_BASE}/{{link_id}}"
)

# ======================================================
# OTHER URLS
# ======================================================

HEALTH_URL = (
    f"{BASE_URL}/health"
)

ROOT_URL = BASE_URL

# ======================================================
# CORS
# ======================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "https://nexspacefrontend.azurewebsites.net",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

# ======================================================
# SEND OTP EMAIL
# ======================================================

def send_otp_email(
    receiver_email,
    otp
):

    subject = (
        "NexSpace Verification OTP"
    )

    body = f"""
Your OTP is:

{otp}

This OTP expires in 5 minutes.

Do not share this OTP with anyone.
"""

    msg = MIMEText(body)

    msg["Subject"] = subject

    msg["From"] = EMAIL

    msg["To"] = receiver_email

    server = smtplib.SMTP(
        "smtp.gmail.com",
        587
    )

    server.starttls()

    server.login(
        EMAIL,
        EMAIL_PASS
    )

    server.sendmail(
        EMAIL,
        receiver_email,
        msg.as_string()
    )

    server.quit()

# ======================================================
# AUTH HELPER
# ======================================================

def get_current_user(
    credentials:
    HTTPAuthorizationCredentials
    = Depends(security),
):

    token = credentials.credentials

    user_id = verify_token(token)

    if not user_id:
        raise HTTPException(
            status_code=401,
            detail="Invalid token",
        )

    user = get_user_by_id(user_id)

    if not user:
        raise HTTPException(
            status_code=401,
            detail="User not found",
        )

    return user

# ======================================================
# GENERATE SHORT CODE
# ======================================================

def generate_short_code(
    length: int = 6
):

    characters = (
        string.ascii_letters
        + string.digits
    )

    while True:

        short_code = "".join(
            random.choice(characters)
            for _ in range(length)
        )

        existing = (
            links_collection.find_one(
                {
                    "short_code":
                    short_code
                }
            )
        )

        if not existing:
            return short_code

# ======================================================
# REGISTER
# ======================================================

@app.post(
    "/api/auth/register",
    response_model=TokenResponse,
)
async def register(
    user_data: UserRegister
):

    existing_user = (
        users_collection.find_one(
            {
                "email":
                user_data.email
            }
        )
    )

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Email already registered",
        )

    hashed_password = (
        hash_password(
            user_data.password
        )
    )

    user_doc = {
        "email":
        user_data.email,

        "password":
        hashed_password,

        "full_name":
        user_data.full_name,

        "created_at":
        datetime.utcnow(),
    }

    result = (
        users_collection.insert_one(
            user_doc
        )
    )

    user_id = str(
        result.inserted_id
    )

    access_token = (
        create_access_token(
            data={"sub": user_id}
        )
    )

    return {
        "access_token":
        access_token,

        "token_type":
        "bearer",
    }

# ======================================================
# LOGIN WITH PASSWORD
# ======================================================

@app.post(
    "/api/auth/login",
    response_model=TokenResponse,
)
async def login(
    user_data: UserLogin
):

    user = (
        users_collection.find_one(
            {
                "email":
                user_data.email
            }
        )
    )

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
        )

    valid_password = (
        verify_password(
            user_data.password,
            user["password"],
        )
    )

    if not valid_password:
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
        )

    user_id = str(user["_id"])

    access_token = (
        create_access_token(
            data={"sub": user_id}
        )
    )

    return {
        "access_token":
        access_token,

        "token_type":
        "bearer",
    }

# ======================================================
# LOGIN WITH OTP
# ======================================================

@app.post(
    "/api/auth/login-otp",
    response_model=TokenResponse,
)
async def login_with_otp(
    data: OTPLoginRequest
):

    email = data.email

    otp = data.otp

    user = users_collection.find_one(
        {
            "email": email
        }
    )

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )

    otp_data = otp_collection.find_one(
        {
            "email": email
        }
    )

    if not otp_data:
        raise HTTPException(
            status_code=400,
            detail="OTP not found",
        )

    if otp_data["otp"] != otp:
        raise HTTPException(
            status_code=400,
            detail="Invalid OTP",
        )

    if (
        otp_data["expiry"]
        < datetime.utcnow()
    ):
        raise HTTPException(
            status_code=400,
            detail="OTP expired",
        )

    otp_collection.delete_one(
        {
            "email": email
        }
    )

    user_id = str(user["_id"])

    access_token = (
        create_access_token(
            data={"sub": user_id}
        )
    )

    return {
        "access_token":
        access_token,

        "token_type":
        "bearer",
    }

# ======================================================
# CURRENT USER
# ======================================================

@app.get("/api/auth/me")
async def get_me(
    current_user=Depends(
        get_current_user
    ),
):

    return {
        "_id":
        str(current_user["_id"]),

        "email":
        current_user["email"],

        "full_name":
        current_user["full_name"],

        "created_at":
        current_user["created_at"],
    }

# ======================================================
# SEND OTP
# ======================================================

@app.post("/api/auth/send-otp")
async def send_otp(
    data: SendOTPRequest
):

    email = data.email

    otp = str(
        randint(100000, 999999)
    )

    expiry = (
        datetime.utcnow()
        + timedelta(minutes=5)
    )

    otp_collection.update_one(
        {"email": email},
        {
            "$set": {
                "otp": otp,
                "expiry": expiry,
            }
        },
        upsert=True,
    )

    send_otp_email(
        email,
        otp
    )

    return {
        "message":
        "OTP sent successfully"
    }

# ======================================================
# VERIFY OTP
# ======================================================

@app.post("/api/auth/verify-otp")
async def verify_otp(
    data: VerifyOTPRequest
):

    email = data.email

    otp = data.otp

    otp_data = (
        otp_collection.find_one(
            {
                "email": email
            }
        )
    )

    if not otp_data:
        raise HTTPException(
            status_code=400,
            detail="OTP not found",
        )

    if otp_data["otp"] != otp:
        raise HTTPException(
            status_code=400,
            detail="Invalid OTP",
        )

    if (
        otp_data["expiry"]
        < datetime.utcnow()
    ):
        raise HTTPException(
            status_code=400,
            detail="OTP expired",
        )

    return {
        "message":
        "OTP verified successfully"
    }

# ======================================================
# RESET PASSWORD
# ======================================================

@app.post(
    "/api/auth/reset-password"
)
async def reset_password(
    data: ResetPasswordRequest
):

    email = data.email

    otp = data.otp

    password = data.password

    user = (
        users_collection.find_one(
            {
                "email": email
            }
        )
    )

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )

    otp_data = (
        otp_collection.find_one(
            {
                "email": email
            }
        )
    )

    if not otp_data:
        raise HTTPException(
            status_code=400,
            detail="OTP not found",
        )

    if otp_data["otp"] != otp:
        raise HTTPException(
            status_code=400,
            detail="Invalid OTP",
        )

    if (
        otp_data["expiry"]
        < datetime.utcnow()
    ):
        raise HTTPException(
            status_code=400,
            detail="OTP expired",
        )

    old_password_same = (
        verify_password(
            password,
            user["password"],
        )
    )

    if old_password_same:
        raise HTTPException(
            status_code=400,
            detail="New password cannot be same as old password",
        )

    hashed_password = (
        hash_password(password)
    )

    users_collection.update_one(
        {
            "email": email
        },
        {
            "$set": {
                "password":
                hashed_password
            }
        },
    )

    otp_collection.delete_one(
        {
            "email": email
        }
    )

    return {
        "message":
        "Password reset successful"
    }

# ======================================================
# CREATE LINK
# ======================================================

@app.post(
    "/api/links",
    status_code=201,
)
async def create_link(
    link_data: LinkCreate,
    current_user=Depends(
        get_current_user
    ),
):

    user_id = str(
        current_user["_id"]
    )

    link_doc = {
        "user_id": user_id,
        "title": link_data.title,
        "url": link_data.url,
        "category":
        link_data.category,
        "tags": link_data.tags,
        "description":
        link_data.description,
        "color": link_data.color,
        "short_code":
        generate_short_code(),
        "created_at":
        datetime.utcnow(),
        "updated_at":
        datetime.utcnow(),
    }

    result = (
        links_collection.insert_one(
            link_doc
        )
    )

    link_doc["_id"] = str(
        result.inserted_id
    )

    return link_doc

# ======================================================
# GET LINKS
# ======================================================

@app.get("/api/links")
async def get_links(
    current_user=Depends(
        get_current_user
    ),
):

    user_id = str(
        current_user["_id"]
    )

    links = list(
        links_collection.find(
            {
                "user_id": user_id
            }
        ).sort(
            "created_at",
            -1
        )
    )

    for link in links:
        link["_id"] = str(
            link["_id"]
        )

    return links

# ======================================================
# UPDATE LINK
# ======================================================

@app.put("/api/links/{link_id}")
async def update_link(
    link_id: str,
    link_data: LinkUpdate,
    current_user=Depends(
        get_current_user
    ),
):

    user_id = str(
        current_user["_id"]
    )

    existing_link = (
        links_collection.find_one(
            {
                "_id": ObjectId(link_id),
                "user_id": user_id,
            }
        )
    )

    if not existing_link:
        raise HTTPException(
            status_code=404,
            detail="Link not found",
        )

    update_data = {
        "title": link_data.title,
        "url": link_data.url,
        "category": link_data.category,
        "tags": link_data.tags,
        "description": link_data.description,
        "color": link_data.color,
        "updated_at": datetime.utcnow(),
    }

    links_collection.update_one(
        {
            "_id": ObjectId(link_id)
        },
        {
            "$set": update_data
        }
    )

    updated_link = (
        links_collection.find_one(
            {
                "_id": ObjectId(link_id)
            }
        )
    )

    updated_link["_id"] = str(
        updated_link["_id"]
    )

    return updated_link

# ======================================================
# DELETE LINK
# ======================================================

@app.delete(
    "/api/links/{link_id}",
    status_code=204,
)
async def delete_link(
    link_id: str,
    current_user=Depends(
        get_current_user
    ),
):

    user_id = str(
        current_user["_id"]
    )

    result = (
        links_collection.delete_one(
            {
                "_id":
                ObjectId(link_id),

                "user_id":
                user_id,
            }
        )
    )

    if result.deleted_count == 0:
        raise HTTPException(
            status_code=404,
            detail="Link not found",
        )

    return None

# ======================================================
# HEALTH
# ======================================================

@app.get("/health")
async def health_check():

    return {
        "status": "ok"
    }

# ======================================================
# ROOT
# ======================================================

@app.get("/")
async def root():

    return {
        "message":
        "NexSpace API Running",

        "base_url":
        BASE_URL,

        "login_url":
        LOGIN_URL,

        "register_url":
        REGISTER_URL,

        "links_url":
        LINKS_BASE,
    }

# ======================================================
# RUN SERVER
# ======================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )