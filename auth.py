from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from config import settings
from database import users_collection
from bson import ObjectId
import hashlib

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)

# ======================================================
# PREPROCESS PASSWORD
# ======================================================

def preprocess_password(password: str) -> bytes:
    """
    Fix bcrypt 72-byte limitation
    using SHA256 pre-hashing
    """

    return hashlib.sha256(
        password.encode("utf-8")
    ).digest()

# ======================================================
# HASH PASSWORD
# ======================================================

def hash_password(password: str) -> str:

    safe_password = preprocess_password(
        password
    )

    return pwd_context.hash(
        safe_password
    )

# ======================================================
# VERIFY PASSWORD
# ======================================================

def verify_password(
    plain_password: str,
    hashed_password: str
) -> bool:

    safe_password = preprocess_password(
        plain_password
    )

    return pwd_context.verify(
        safe_password,
        hashed_password
    )

# ======================================================
# CREATE ACCESS TOKEN
# ======================================================

def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None
):

    to_encode = data.copy()

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=7)

    to_encode.update(
        {
            "exp": expire
        }
    )

    encoded_jwt = jwt.encode(
        to_encode,
        settings.secret_key,
        algorithm=settings.algorithm
    )

    return encoded_jwt

# ======================================================
# VERIFY TOKEN
# ======================================================

def verify_token(token: str):

    try:

        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.algorithm]
        )

        user_id: str = payload.get("sub")

        if user_id is None:
            return None

        return user_id

    except JWTError:
        return None

# ======================================================
# GET USER BY ID
# ======================================================

def get_user_by_id(user_id: str):

    try:

        user = users_collection.find_one(
            {
                "_id": ObjectId(user_id)
            }
        )

        return user

    except Exception:
        return None
