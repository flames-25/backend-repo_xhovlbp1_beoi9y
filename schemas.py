"""
Database Schemas for VellStore (Top-up Platform)

Each Pydantic model represents a collection in MongoDB.
Collection name is the lowercase of the class name.
"""
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List
from datetime import datetime

class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    password_hash: str = Field(..., description="BCrypt password hash")
    role: str = Field("user", description="Role: user or admin")
    phone: Optional[str] = Field(None, description="Phone/WhatsApp number")
    avatar: Optional[str] = None
    is_active: bool = True

class Game(BaseModel):
    name: str = Field(...)
    publisher: Optional[str] = None
    description: Optional[str] = None
    image: Optional[str] = None

class Platform(BaseModel):
    name: str = Field(..., description="Platform name (e.g., Android, iOS, PC)")
    description: Optional[str] = None

class Package(BaseModel):
    game_id: str = Field(..., description="Linked Game _id as string")
    platform_id: str = Field(..., description="Linked Platform _id as string")
    name: str = Field(..., description="Package name (e.g., 86 Diamonds)")
    amount: float = Field(..., ge=0)
    price: float = Field(..., ge=0)
    is_active: bool = True

class Order(BaseModel):
    user_id: str = Field(..., description="User _id as string")
    package_id: str = Field(..., description="Package _id as string")
    target_id: str = Field(..., description="In-game identifier / player ID")
    note: Optional[str] = None
    status: str = Field("pending", description="pending|paid|processing|completed|failed|refunded")
    payment_reference: Optional[str] = None
    receipt_code: Optional[str] = None
    paid_at: Optional[datetime] = None

class PaymentInit(BaseModel):
    order_id: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    phone: Optional[str] = None

class AdminStatusUpdate(BaseModel):
    status: str
    note: Optional[str] = None
