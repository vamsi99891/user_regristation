from pydantic import BaseModel, Field, EmailStr, field_validator
from typing import Optional
from app.utils.validators import validate_mobile, validate_email_domain,validate_password_strength

class UserRegister(BaseModel):
    email: EmailStr
    mobile: str
    first_name: str
    last_name: str
    dob: str
    doj: str
    address: str
    password: str = Field(min_length=8, max_length=20)
    active: bool

    @field_validator('email')
    def email_domain(cls, v): 
        return validate_email_domain(v)

    @field_validator('mobile')
    def mobile_check(cls, v): 
        return validate_mobile(v)

    @field_validator('password')
    def password_check(cls, v): 
        return validate_password_strength(v)


class LoginRequest(BaseModel):
    username: str
    password: str = Field(min_length=8, max_length=20)


class ChangeContactRequest(BaseModel):
    email: Optional[EmailStr] = None
    mobile: Optional[str] = None

    @field_validator('email')
    def email_domain(cls, v): 
        return validate_email_domain(v)

    @field_validator('mobile')
    def mobile_check(cls, v): 
        return validate_mobile(v)


class ChangePasswordRequest(BaseModel):
    old_password: str = Field(min_length=8, max_length=20)
    new_password: str = Field(min_length=8, max_length=20)

    @field_validator('new_password')
    def password_check(cls, v): 
        return validate_password_strength(v)
    

class ForgotPasswordRequest(BaseModel):
    email: EmailStr