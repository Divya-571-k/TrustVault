
from pathlib import Path

from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr

from app.database import Base, engine, get_db
from app import models
from app.auth import hash_password

app = FastAPI(
    title="TrustVault",
    description="Secure Document Sharing Platform",
    version="0.1.0",
)

Base.metadata.create_all(bind=engine)

HTML_FILE = Path(__file__).with_name("index.html")


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str


@app.get("/", include_in_schema=False)
def home():
    return FileResponse(HTML_FILE)


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/register", status_code=201)
def register(data: RegisterRequest, db: Session = Depends(get_db)):
    email = data.email.strip().lower()

    if len(data.password) < 12:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 12 characters long",
        )

    existing_user = (
        db.query(models.User)
        .filter(models.User.email == email)
        .first()
    )

    if existing_user:
        raise HTTPException(
            status_code=409,
            detail="Email is already registered",
        )

    user = models.User(
        email=email,
        password_hash=hash_password(data.password),
        role="owner",
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return {
        "message": "Registration successful",
        "user_id": user.id,
        "email": user.email,
    }
