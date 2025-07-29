import re

def validate_mobile(v: str) -> str:
    pattern = r'^[6-9]\d{9}$'
    if not re.fullmatch(pattern, v):
        raise ValueError("Mobile number must be a valid 10-digit  number.")
    return v

def validate_email_domain(v: str) -> str:
    v = v.lower()
    if not v.endswith('gmail.com'):
        raise ValueError("Only gmail.com domains are allowed.")
    return v

def validate_password_strength(v: str) -> str:
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,20}$'
    if not re.fullmatch(pattern, v):
        raise ValueError("Password must include uppercase, lowercase, number, and special character.")
    return v