
from pathlib import Path
import os
import uuid

from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    Request,
    UploadFile,
    File,
)
from fastapi.responses import FileResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr

from app.database import Base, engine, get_db
from app import models
from app.auth import hash_password, verify_password


app = FastAPI(
    title="TrustVault",
    description="Secure Document Sharing Platform",
    version="0.3.0",
)

app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get(
        "TRUSTVAULT_SECRET_KEY",
        "trustvault-local-development-key-change-before-deployment",
    ),
    session_cookie="trustvault_session",
    max_age=3600,
    same_site="lax",
    https_only=False,
)

Base.metadata.create_all(bind=engine)

HTML_FILE = Path(__file__).with_name("index.html")
DASHBOARD_FILE = Path(__file__).with_name("dashboard.html")
UPLOAD_DIR = Path(__file__).with_name("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

MAX_FILE_SIZE = 10 * 1024 * 1024

ALLOWED_EXTENSIONS = {
    ".pdf", ".txt", ".doc", ".docx",
    ".png", ".jpg", ".jpeg",
}


# -------------------- REQUEST MODELS --------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ShareRequest(BaseModel):
    email: EmailStr


# -------------------- HELPER FUNCTIONS --------------------

def get_current_user(request: Request, db: Session):
    user_id = request.session.get("user_id")

    if not user_id:
        raise HTTPException(
            status_code=401,
            detail="Please log in first",
        )

    user = db.query(models.User).filter(
        models.User.id == user_id,
        models.User.is_active.is_(True),
    ).first()

    if not user:
        request.session.clear()
        raise HTTPException(
            status_code=401,
            detail="Session invalid. Please log in again.",
        )

    return user


def add_audit_log(
    db: Session,
    actor_id: int,
    action: str,
    document_id: int,
    details: str,
):
    db.add(
        models.AuditLog(
            actor_id=actor_id,
            action=action,
            document_id=document_id,
            details=details,
            success=True,
        )
    )


def get_accessible_document(
    document_id: int,
    user_id: int,
    db: Session,
):
    # The owner always has access to their own document.
    document = db.query(models.Document).filter(
        models.Document.id == document_id,
        models.Document.owner_id == user_id,
    ).first()

    if document:
        return document

    # Other users need an active viewing permission.
    permission = db.query(models.DocumentPermission).filter(
        models.DocumentPermission.document_id == document_id,
        models.DocumentPermission.user_id == user_id,
        models.DocumentPermission.can_view.is_(True),
        models.DocumentPermission.revoked.is_(False),
    ).first()

    if not permission:
        raise HTTPException(
            status_code=404,
            detail="Document not found or access denied",
        )

    document = db.query(models.Document).filter(
        models.Document.id == document_id,
    ).first()

    if not document:
        raise HTTPException(
            status_code=404,
            detail="Document not found",
        )

    return document


# -------------------- HOME AND DASHBOARD --------------------

@app.get("/", include_in_schema=False)
def home():
    return FileResponse(HTML_FILE)


@app.get("/dashboard", include_in_schema=False)
def dashboard(request: Request):
    if not request.session.get("user_id"):
        return RedirectResponse(url="/", status_code=303)

    return FileResponse(DASHBOARD_FILE)


@app.get("/health")
def health():
    return {"status": "healthy"}
@app.get("/register", include_in_schema=False)
def register_page():
    return FileResponse(
        Path(__file__).with_name("register.html")
    )

# -------------------- REGISTER --------------------

@app.post("/register", status_code=201)
def register(
    data: RegisterRequest,
    db: Session = Depends(get_db),
):
    email = str(data.email).strip().lower()

    if len(data.password) < 12:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 12 characters",
        )

    existing_user = db.query(models.User).filter(
        models.User.email == email,
    ).first()

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


# -------------------- LOGIN --------------------

@app.post("/login")
def login(
    data: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    email = str(data.email).strip().lower()

    user = db.query(models.User).filter(
        models.User.email == email,
    ).first()

    if (
        not user
        or not user.is_active
        or not verify_password(data.password, user.password_hash)
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password",
        )

    request.session.clear()
    request.session["user_id"] = user.id

    return {
        "message": "Login successful",
        "user_id": user.id,
        "email": user.email,
        "role": user.role,
    }


# -------------------- LOGOUT --------------------

@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return {"message": "Logged out successfully"}


# -------------------- UPLOAD DOCUMENT --------------------

@app.post("/documents/upload")
async def upload_document(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    user = get_current_user(request, db)

    original_name = Path(file.filename or "").name

    if not original_name or original_name in {".", ".."}:
        raise HTTPException(
            status_code=400,
            detail="Please select a file",
        )

    extension = Path(original_name).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail="Unsupported file format",
        )

    storage_name = f"{uuid.uuid4().hex}{extension}"
    destination = UPLOAD_DIR / storage_name
    size = 0

    try:
        with destination.open("wb") as output:
            while True:
                chunk = await file.read(1024 * 1024)

                if not chunk:
                    break

                size += len(chunk)

                if size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail="Maximum file size is 10 MB",
                    )

                output.write(chunk)

        document = models.Document(
            owner_id=user.id,
            filename=original_name,
            storage_name=storage_name,
        )

        db.add(document)
        db.flush()

        add_audit_log(
            db,
            user.id,
            "DOCUMENT_UPLOAD",
            document.id,
            f"Uploaded {original_name}",
        )

        db.commit()
        db.refresh(document)

        return {
            "message": "Document uploaded successfully",
            "document_id": document.id,
            "filename": document.filename,
        }

    except Exception:
        db.rollback()

        if destination.exists():
            destination.unlink()

        raise

    finally:
        await file.close()


# -------------------- LIST OWNED AND SHARED DOCUMENTS --------------------

@app.get("/documents")
def list_documents(
    request: Request,
    db: Session = Depends(get_db),
):
    user = get_current_user(request, db)

    owned = db.query(models.Document).filter(
        models.Document.owner_id == user.id,
    ).all()

    permissions = db.query(models.DocumentPermission).filter(
        models.DocumentPermission.user_id == user.id,
        models.DocumentPermission.can_view.is_(True),
        models.DocumentPermission.revoked.is_(False),
    ).all()

    shared_ids = {p.document_id for p in permissions}

    shared = []
    if shared_ids:
        shared = db.query(models.Document).filter(
            models.Document.id.in_(shared_ids),
            models.Document.owner_id != user.id,
        ).all()

    results = []

    for document in owned:
        results.append({
            "id": document.id,
            "filename": document.filename,
            "created_at": document.created_at.isoformat(),
            "type": "owned",
            "download_url": f"/documents/{document.id}/download",
        })

    for document in shared:
        owner = db.query(models.User).filter(
            models.User.id == document.owner_id,
        ).first()

        results.append({
            "id": document.id,
            "filename": document.filename,
            "created_at": document.created_at.isoformat(),
            "type": "shared",
            "shared_by": owner.email if owner else "Unknown",
            "download_url": f"/documents/{document.id}/download",
        })

    results.sort(
        key=lambda item: item["created_at"],
        reverse=True,
    )

    return results


# -------------------- SHARE DOCUMENT --------------------

@app.post("/documents/{document_id}/share")
def share_document(
    document_id: int,
    data: ShareRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    owner = get_current_user(request, db)
    recipient_email = str(data.email).strip().lower()

    document = db.query(models.Document).filter(
        models.Document.id == document_id,
        models.Document.owner_id == owner.id,
    ).first()

    if not document:
        raise HTTPException(
            status_code=404,
            detail="Document not found or you are not the owner",
        )

    recipient = db.query(models.User).filter(
        models.User.email == recipient_email,
        models.User.is_active.is_(True),
    ).first()

    if not recipient:
        raise HTTPException(
            status_code=404,
            detail="Recipient must register for TrustVault first",
        )

    if recipient.id == owner.id:
        raise HTTPException(
            status_code=400,
            detail="You cannot share a document with yourself",
        )

    permission = db.query(models.DocumentPermission).filter(
        models.DocumentPermission.document_id == document.id,
        models.DocumentPermission.user_id == recipient.id,
    ).first()

    if permission:
        permission.can_view = True
        permission.revoked = False
    else:
        db.add(
            models.DocumentPermission(
                document_id=document.id,
                user_id=recipient.id,
                can_view=True,
                revoked=False,
            )
        )

    add_audit_log(
        db,
        owner.id,
        "DOCUMENT_SHARE",
        document.id,
        f"Shared with {recipient_email}",
    )

    db.commit()

    return {
        "message": "Document shared successfully",
        "filename": document.filename,
        "shared_with": recipient_email,
    }


# -------------------- VIEW SHARE PERMISSIONS --------------------

@app.get("/documents/{document_id}/shares")
def list_document_shares(
    document_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    owner = get_current_user(request, db)

    document = db.query(models.Document).filter(
        models.Document.id == document_id,
        models.Document.owner_id == owner.id,
    ).first()

    if not document:
        raise HTTPException(
            status_code=404,
            detail="Document not found or you are not the owner",
        )

    permissions = db.query(models.DocumentPermission).filter(
        models.DocumentPermission.document_id == document.id,
    ).all()

    results = []

    for permission in permissions:
        recipient = db.query(models.User).filter(
            models.User.id == permission.user_id,
        ).first()

        if recipient:
            results.append({
                "email": recipient.email,
                "can_view": permission.can_view,
                "revoked": permission.revoked,
            })

    return results


# -------------------- REVOKE SHARING --------------------

@app.delete("/documents/{document_id}/share/{recipient_email}")
def revoke_document_share(
    document_id: int,
    recipient_email: str,
    request: Request,
    db: Session = Depends(get_db),
):
    owner = get_current_user(request, db)

    document = db.query(models.Document).filter(
        models.Document.id == document_id,
        models.Document.owner_id == owner.id,
    ).first()

    if not document:
        raise HTTPException(
            status_code=404,
            detail="Document not found or you are not the owner",
        )

    email = recipient_email.strip().lower()

    recipient = db.query(models.User).filter(
        models.User.email == email,
    ).first()

    if not recipient:
        raise HTTPException(
            status_code=404,
            detail="Recipient not found",
        )

    permission = db.query(models.DocumentPermission).filter(
        models.DocumentPermission.document_id == document.id,
        models.DocumentPermission.user_id == recipient.id,
    ).first()

    if not permission or permission.revoked:
        raise HTTPException(
            status_code=404,
            detail="Active sharing permission not found",
        )

    permission.revoked = True

    add_audit_log(
        db,
        owner.id,
        "DOCUMENT_SHARE_REVOKED",
        document.id,
        f"Revoked sharing for {email}",
    )

    db.commit()

    return {
        "message": "Document access revoked successfully",
        "email": email,
    }


# -------------------- DOWNLOAD OWNED OR SHARED DOCUMENT --------------------

@app.get("/documents/{document_id}/download")
def download_document(
    document_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    user = get_current_user(request, db)

    document = get_accessible_document(
        document_id,
        user.id,
        db,
    )

    file_path = UPLOAD_DIR / document.storage_name

    if not file_path.is_file():
        raise HTTPException(
            status_code=404,
            detail="Stored file not found",
        )

    add_audit_log(
        db,
        user.id,
        "DOCUMENT_DOWNLOAD",
        document.id,
        f"Downloaded {document.filename}",
    )
    db.commit()

    return FileResponse(
        path=file_path,
        filename=document.filename,
        content_disposition_type="attachment",
    )
