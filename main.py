import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from bson import ObjectId
import bcrypt
import jwt

from database import db, create_document, get_documents
from schemas import (
    User, Game, Platform, Package, Order,
    PaymentInit, LoginRequest, RegisterRequest, AdminStatusUpdate
)

APP_NAME = "VellStore"
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change")
JWT_ALGO = "HS256"

app = FastAPI(title=APP_NAME)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()


# Helpers
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()


def verify_password(pw: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(pw.encode(), hashed.encode())
    except Exception:
        return False


def create_token(payload: Dict[str, Any]) -> str:
    to_encode = {**payload, "exp": datetime.now(timezone.utc).timestamp() + 60 * 60 * 24 * 7}
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGO)


def current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    try:
        data = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGO])
        user = db["user"].find_one({"_id": ObjectId(data["sub"])})
        if not user:
            raise HTTPException(status_code=401, detail="Invalid token")
        user["_id"] = str(user["_id"])
        return user
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def admin_required(user: Dict[str, Any] = Depends(current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return user


@app.get("/")
def read_root():
    return {"message": f"{APP_NAME} API is running"}


@app.get("/test")
def test_database():
    try:
        collections = db.list_collection_names()
        return {
            "backend": "Running",
            "database": "Connected",
            "collections": collections,
        }
    except Exception as e:
        return {"backend": "Running", "database": f"Error: {str(e)}"}


# Auth Routes
@app.post("/auth/register", response_model=TokenResponse)
def register(payload: RegisterRequest):
    if db["user"].find_one({"email": payload.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(
        name=payload.name,
        email=payload.email,
        password_hash=hash_password(payload.password),
        role="user",
        phone=payload.phone,
        is_active=True,
    )
    uid = create_document("user", user)
    token = create_token({"sub": uid, "email": user.email, "role": user.role})
    return TokenResponse(access_token=token)


@app.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest):
    user = db["user"].find_one({"email": payload.email})
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_token({"sub": str(user["_id"]), "email": user["email"], "role": user.get("role", "user")})
    return TokenResponse(access_token=token)


@app.get("/me")
def me(user: Dict[str, Any] = Depends(current_user)):
    return user


# Catalog Routes
@app.post("/admin/game")
def create_game(game: Game, admin=Depends(admin_required)):
    gid = create_document("game", game)
    return {"_id": gid}


@app.get("/games")
def list_games():
    items = get_documents("game")
    for it in items:
        it["_id"] = str(it["_id"])  # type: ignore
    return items


@app.post("/admin/platform")
def create_platform(platform: Platform, admin=Depends(admin_required)):
    pid = create_document("platform", platform)
    return {"_id": pid}


@app.get("/platforms")
def list_platforms():
    items = get_documents("platform")
    for it in items:
        it["_id"] = str(it["_id"])  # type: ignore
    return items


@app.post("/admin/package")
def create_package(package: Package, admin=Depends(admin_required)):
    pkid = create_document("package", package)
    return {"_id": pkid}


@app.get("/packages")
def list_packages(game_id: Optional[str] = None, platform_id: Optional[str] = None):
    filt: Dict[str, Any] = {}
    if game_id:
        filt["game_id"] = game_id
    if platform_id:
        filt["platform_id"] = platform_id
    items = get_documents("package", filt)
    for it in items:
        it["_id"] = str(it["_id"])  # type: ignore
    return items


# Orders + Payments (mock gateway integration ready)
class CreateOrderRequest(BaseModel):
    package_id: str
    target_id: str
    note: Optional[str] = None


@app.post("/orders")
def create_order(payload: CreateOrderRequest, user=Depends(current_user)):
    # Ensure package exists
    pkg = db["package"].find_one({"_id": ObjectId(payload.package_id)})
    if not pkg:
        raise HTTPException(status_code=404, detail="Package not found")

    order = Order(
        user_id=str(user["_id"]),
        package_id=payload.package_id,
        target_id=payload.target_id,
        note=payload.note,
        status="pending",
        payment_reference=None,
        receipt_code=None,
        paid_at=None,
    )
    oid = create_document("order", order)

    # Payment preparation (mock). Replace with real gateway create invoice API.
    payment_ref = f"VELL-{oid[:6]}-{int(datetime.now().timestamp())}"
    db["order"].update_one({"_id": ObjectId(oid)}, {"$set": {"payment_reference": payment_ref, "status": "paid"}})

    # Generate receipt for warranty claim
    receipt = f"RCPT-{oid[-6:]}"
    db["order"].update_one({"_id": ObjectId(oid)}, {"$set": {"receipt_code": receipt, "paid_at": datetime.now(timezone.utc), "status": "processing"}})

    return {"order_id": oid, "payment_reference": payment_ref, "receipt_code": receipt}


@app.get("/orders/me")
def my_orders(user=Depends(current_user)):
    items = get_documents("order", {"user_id": str(user["_id"])})
    # Join with package to return basic info
    for it in items:
        it["_id"] = str(it["_id"])  # type: ignore
        pkg = db["package"].find_one({"_id": ObjectId(it["package_id"])})
        if pkg:
            it["package_name"] = pkg.get("name")
            it["price"] = pkg.get("price")
    return items


@app.get("/orders/{order_id}/receipt")
def order_receipt(order_id: str, user=Depends(current_user)):
    order = db["order"].find_one({"_id": ObjectId(order_id), "user_id": str(user["_id"])})
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    order["_id"] = str(order["_id"])  # type: ignore
    return {
        "order_id": order["_id"],
        "receipt_code": order.get("receipt_code"),
        "status": order.get("status"),
        "payment_reference": order.get("payment_reference"),
        "paid_at": order.get("paid_at"),
    }


# Admin Panel Essentials
@app.get("/admin/orders")
def admin_orders(admin=Depends(admin_required)):
    items = get_documents("order")
    for it in items:
        it["_id"] = str(it["_id"])  # type: ignore
    return items


@app.post("/admin/orders/{order_id}/status")
def update_order_status(order_id: str, payload: AdminStatusUpdate, admin=Depends(admin_required)):
    ok = db["order"].update_one({"_id": ObjectId(order_id)}, {"$set": {"status": payload.status, "note": payload.note, "updated_at": datetime.now(timezone.utc)}})
    if ok.matched_count == 0:
        raise HTTPException(status_code=404, detail="Order not found")
    return {"success": True}


# Public Catalog for landing page
@app.get("/catalog")
def public_catalog():
    games = list(db["game"].find())
    platforms = list(db["platform"].find())
    packages = list(db["package"].find({"is_active": True}))
    for arr in (games, platforms, packages):
        for it in arr:
            it["_id"] = str(it["_id"])  # type: ignore
    return {"games": games, "platforms": platforms, "packages": packages}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
