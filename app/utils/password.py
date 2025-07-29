from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)



def is_password_expired(last_changed: datetime) -> bool:
    now = datetime.now(timezone.utc)
    try:
        last_changed = last_changed.astimezone(timezone.utc)
    except Exception:
        return True 
    return (now - last_changed) > timedelta(days=30)