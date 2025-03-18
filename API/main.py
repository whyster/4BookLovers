from datetime import datetime, timedelta
from typing import List, Optional
import os
import secrets
from passlib.context import CryptContext
from fastapi import FastAPI, Depends, HTTPException, status, Request, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Boolean, Text, ForeignKey, DateTime, func, select, insert, update
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from sqlalchemy.sql import text
from pydantic import BaseModel, EmailStr, Field, validator
import jwt
from contextlib import contextmanager
from datetime import timezone

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@db:5432/booklover")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI(
    title="4BookLovers API",
    description="Book lovers community API",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  #
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), default=func.now())
    last_login = Column(DateTime(timezone=True), nullable=True)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True)
    
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    shelves = relationship("Shelf", back_populates="user", cascade="all, delete-orphan")
    reviews = relationship("Review", back_populates="user", cascade="all, delete-orphan")

class Session(Base):
    __tablename__ = "sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    session_token = Column(String(255), unique=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=func.now())
    last_active = Column(DateTime(timezone=True), default=func.now())
    expires_at = Column(DateTime(timezone=True))
    device_info = Column(Text)
    
    user = relationship("User", back_populates="sessions")

class Book(Base):
    __tablename__ = "books"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    author = Column(String(255), nullable=False)
    isbn = Column(String(20), unique=True)
    publisher = Column(String(100))
    publication_year = Column(Integer)
    description = Column(Text)
    cover_image_url = Column(Text)
    page_count = Column(Integer)
    language = Column(String(50))
    created_at = Column(DateTime(timezone=True), default=func.now())
    
    tags = relationship("Tag", secondary="book_tags", back_populates="books")
    shelves = relationship("Shelf", secondary="shelf_books", back_populates="books")
    reviews = relationship("Review", back_populates="book", cascade="all, delete-orphan")

class Tag(Base):
    __tablename__ = "tags"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, nullable=False)
    description = Column(String(1000))
    
    books = relationship("Book", secondary="book_tags", back_populates="tags")

class BookTag(Base):
    __tablename__ = "book_tags"
    
    book_id = Column(Integer, ForeignKey("books.id", ondelete="CASCADE"), primary_key=True)
    tag_id = Column(Integer, ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True)
    created_at = Column(DateTime(timezone=True), default=func.now())

class Shelf(Base):
    __tablename__ = "shelves"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    name = Column(String(100), nullable=False)
    description = Column(Text)
    is_default = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=func.now())
    
    user = relationship("User", back_populates="shelves")
    books = relationship("Book", secondary="shelf_books", back_populates="shelves")

class ShelfBook(Base):
    __tablename__ = "shelf_books"
    
    shelf_id = Column(Integer, ForeignKey("shelves.id", ondelete="CASCADE"), primary_key=True)
    book_id = Column(Integer, ForeignKey("books.id", ondelete="CASCADE"), primary_key=True)
    added_at = Column(DateTime(timezone=True), default=func.now())

class Review(Base):
    __tablename__ = "reviews"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    book_id = Column(Integer, ForeignKey("books.id", ondelete="CASCADE"))
    rating = Column(Integer)
    review_text = Column(Text)
    created_at = Column(DateTime(timezone=True), default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    user = relationship("User", back_populates="reviews")
    book = relationship("Book", back_populates="reviews")

# Pydantic Models
class UserBase(BaseModel):
    username: str
    email: EmailStr

class UserCreate(UserBase):
    password: str
    
    @validator('password')
    def password_validation(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        return v

class UserResponse(UserBase):
    id: int
    created_at: datetime
    
    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None
    session_id: Optional[int] = None

class TagBase(BaseModel):
    name: str
    description: Optional[str] = None

class TagCreate(TagBase):
    pass

class TagResponse(TagBase):
    id: int
    
    class Config:
        orm_mode = True

class BookBase(BaseModel):
    title: str
    author: str
    isbn: Optional[str] = None
    publisher: Optional[str] = None
    publication_year: Optional[int] = None
    description: Optional[str] = None
    cover_image_url: Optional[str] = None
    page_count: Optional[int] = None
    language: Optional[str] = None

class BookCreate(BookBase):
    tags: Optional[List[int]] = []

class BookResponse(BookBase):
    id: int
    created_at: datetime
    tags: List[TagResponse]
    
    class Config:
        orm_mode = True

class ShelfBase(BaseModel):
    name: str
    description: Optional[str] = None

class ShelfCreate(ShelfBase):
    pass

class ShelfResponse(ShelfBase):
    id: int
    user_id: int
    is_default: bool
    created_at: datetime
    
    class Config:
        orm_mode = True

class ReviewBase(BaseModel):
    book_id: int
    rating: int = Field(..., ge=1, le=5)
    review_text: Optional[str] = Field(None, max_length=1000)

class ReviewCreate(ReviewBase):
    pass

class ReviewResponse(ReviewBase):
    id: int
    user_id: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        orm_mode = True

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user_by_username(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

def authenticate_user(db: Session, username: str, password: str):
    user = get_user_by_username(db, username)
    if not user:
        return False
    
    # Check if user is locked out
    if user.locked_until and user.locked_until > datetime.now(timezone.utc):
        return False
    
    if not verify_password(password, user.password_hash):
        # Increment failed login attempts
        user.failed_login_attempts += 1
        
        # Lock account after 5 failed attempts
        if user.failed_login_attempts >= 5:
            user.locked_until = datetime.now(timezone.utc) + timedelta(hours=24)
        
        db.commit()
        return False
    
    # Reset failed login attempts on successful login
    user.failed_login_attempts = 0
    user.last_login = datetime.now(timezone.utc)
    db.commit()
    
    return user

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        session_id: int = payload.get("session_id")
        if username is None or session_id is None:
            raise credentials_exception
        token_data = TokenData(username=username, session_id=session_id)
    except jwt.PyJWTError:
        raise credentials_exception
    
    user = get_user_by_username(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    
    # Check if session exists and is valid
    session = db.query(Session).filter(
        Session.id == token_data.session_id,
        Session.user_id == user.id,
        Session.expires_at > datetime.now(timezone.utc)
    ).first()
    
    if not session:
        raise credentials_exception
    
    # Update session last_active time
    session.last_active = datetime.now(timezone.utc)
    session.expires_at = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    db.commit()
    
    return user

# Middleware to check for inactive sessions
@app.middleware("http")
async def check_session_timeout(request: Request, call_next):
    response = await call_next(request)
    
    # Skip token auth paths
    if request.url.path in ["/token", "/docs", "/openapi.json"]:
        return response
    
    # Get token from header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            session_id = payload.get("session_id")
            
            # Get DB session
            db = SessionLocal()
            try:
                # Check if session exists and update last_active
                session = db.query(Session).filter(Session.id == session_id).first()
                if session:
                    # If last_active is older than 30 minutes, invalidate session
                    if (datetime.now(timezone.utc) - session.last_active) > timedelta(minutes=30):
                        session.expires_at = datetime.now(timezone.utc)
                        db.commit()
                        return Response(
                            status_code=status.HTTP_401_UNAUTHORIZED,
                            content="Session expired due to inactivity",
                            headers={"WWW-Authenticate": "Bearer"}
                        )
            finally:
                db.close()
        except Exception:
            pass
    
    return response

# Auth endpoints
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Check if user has reached max sessions
    active_sessions = db.query(Session).filter(
        Session.user_id == user.id,
        Session.expires_at > datetime.now(timezone.utc)
    ).count()
    
    if active_sessions >= 5:
        # Find oldest session and expire it
        oldest_session = db.query(Session).filter(
            Session.user_id == user.id
        ).order_by(Session.last_active).first()
        
        if oldest_session:
            oldest_session.expires_at = datetime.now(timezone.utc)
            db.commit()
    
    # Create new session
    session = Session(
        user_id=user.id,
        session_token=secrets.token_urlsafe(32),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        device_info=form_data.client_id if hasattr(form_data, 'client_id') else None
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    
    # Create access token with session ID
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "session_id": session.id},
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/logout")
async def logout(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Get token from request
    token = None
    for cookie in db.cookies:
        if cookie.key == "token":
            token = cookie.value
            break
    
    if token:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            session_id: int = payload.get("session_id")
            
            # Expire the session
            session = db.query(Session).filter(Session.id == session_id).first()
            if session:
                session.expires_at = datetime.now(timezone.utc)
                db.commit()
        except:
            pass
    
    return {"message": "Successfully logged out"}

# User endpoints
@app.post("/users/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    db_email = db.query(User).filter(User.email == user.email).first()
    if db_email:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = get_password_hash(user.password)
    db_user = User(
        username=user.username,
        email=user.email,
        password_hash=hashed_password
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    # Create default shelves for the user
    default_shelves = [
        Shelf(user_id=db_user.id, name="Want to Read", description="Books you want to read", is_default=True),
        Shelf(user_id=db_user.id, name="Currently Reading", description="Books you are currently reading", is_default=True),
        Shelf(user_id=db_user.id, name="Read", description="Books you have finished reading", is_default=True)
    ]
    db.add_all(default_shelves)
    db.commit()
    
    return db_user

@app.get("/users/me", response_model=UserResponse)
def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

# Book endpoints
@app.post("/books/", response_model=BookResponse, status_code=status.HTTP_201_CREATED)
def create_book(book: BookCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_book = Book(
        title=book.title,
        author=book.author,
        isbn=book.isbn,
        publisher=book.publisher,
        publication_year=book.publication_year,
        description=book.description,
        cover_image_url=book.cover_image_url,
        page_count=book.page_count,
        language=book.language
    )
    db.add(db_book)
    db.commit()
    db.refresh(db_book)
    
    # Add tags if provided
    if book.tags:
        for tag_id in book.tags:
            tag = db.query(Tag).filter(Tag.id == tag_id).first()
            if tag:
                db_book.tags.append(tag)
        db.commit()
    
    return db_book

@app.get("/books/", response_model=List[BookResponse])
def get_books(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return db.query(Book).offset(skip).limit(limit).all()

@app.get("/books/{book_id}", response_model=BookResponse)
def get_book(book_id: int, db: Session = Depends(get_db)):
    db_book = db.query(Book).filter(Book.id == book_id).first()
    if db_book is None:
        raise HTTPException(status_code=404, detail="Book not found")
    return db_book

# Tag endpoints
@app.post("/tags/", response_model=TagResponse, status_code=status.HTTP_201_CREATED)
def create_tag(tag: TagCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_tag = db.query(Tag).filter(Tag.name == tag.name).first()
    if db_tag:
        raise HTTPException(status_code=400, detail="Tag already exists")
    
    db_tag = Tag(name=tag.name, description=tag.description)
    db.add(db_tag)
    db.commit()
    db.refresh(db_tag)
    return db_tag

@app.get("/tags/", response_model=List[TagResponse])
def get_tags(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return db.query(Tag).offset(skip).limit(limit).all()

# Shelf endpoints
@app.post("/shelves/", response_model=ShelfResponse, status_code=status.HTTP_201_CREATED)
def create_shelf(shelf: ShelfCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Check if user already has a shelf with this name
    db_shelf = db.query(Shelf).filter(
        Shelf.user_id == current_user.id,
        Shelf.name == shelf.name
    ).first()
    if db_shelf:
        raise HTTPException(status_code=400, detail="Shelf with this name already exists")
    
    # Check if user has reached the limit of custom shelves
    custom_shelves_count = db.query(Shelf).filter(
        Shelf.user_id == current_user.id,
        Shelf.is_default == False
    ).count()
    if custom_shelves_count >= 20:
        raise HTTPException(status_code=400, detail="You have reached the maximum number of custom shelves (20)")
    
    db_shelf = Shelf(
        user_id=current_user.id,
        name=shelf.name,
        description=shelf.description,
        is_default=False
    )
    db.add(db_shelf)
    db.commit()
    db.refresh(db_shelf)
    return db_shelf

@app.get("/shelves/", response_model=List[ShelfResponse])
def get_shelves(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Shelf).filter(Shelf.user_id == current_user.id).all()

@app.post("/shelves/{shelf_id}/books/{book_id}")
def add_book_to_shelf(
    shelf_id: int, 
    book_id: int, 
    db: Session = Depends(get_db), 
    current_user: User = Depends(get_current_user)
):
    # Check if shelf exists and belongs to user
    db_shelf = db.query(Shelf).filter(
        Shelf.id == shelf_id,
        Shelf.user_id == current_user.id
    ).first()
    if not db_shelf:
        raise HTTPException(status_code=404, detail="Shelf not found or doesn't belong to you")
    
    # Check if book exists
    db_book = db.query(Book).filter(Book.id == book_id).first()
    if not db_book:
        raise HTTPException(status_code=404, detail="Book not found")
    
    # Check if book is already on the shelf
    shelf_book = db.query(ShelfBook).filter(
        ShelfBook.shelf_id == shelf_id,
        ShelfBook.book_id == book_id
    ).first()
    if shelf_book:
        raise HTTPException(status_code=400, detail="Book already on this shelf")
    
    # Check if shelf has reached the limit of books
    books_count = db.query(ShelfBook).filter(ShelfBook.shelf_id == shelf_id).count()
    if books_count >= 350:
        raise HTTPException(status_code=400, detail="This shelf has reached the maximum number of books (350)")
    
    # Add book to shelf
    db_shelf_book = ShelfBook(shelf_id=shelf_id, book_id=book_id)
    db.add(db_shelf_book)
    db.commit()
    
    return {"message": "Book added to shelf successfully"}

# Review endpoints
@app.post("/reviews/", response_model=ReviewResponse, status_code=status.HTTP_201_CREATED)
def create_review(
    review: ReviewCreate, 
    db: Session = Depends(get_db), 
    current_user: User = Depends(get_current_user)
):
    # Check if book exists
    db_book = db.query(Book).filter(Book.id == review.book_id).first()
    if not db_book:
        raise HTTPException(status_code=404, detail="Book not found")
    
    # Check if user already reviewed this book
    db_review = db.query(Review).filter(
        Review.user_id == current_user.id,
        Review.book_id == review.book_id
    ).first()
    if db_review:
        raise HTTPException(status_code=400, detail="You have already reviewed this book")
    
    # Check review text length
    if review.review_text and len(review.review_text) > 1000:
        raise HTTPException(status_code=400, detail="Review text must be at most 1000 characters")
    
    db_review = Review(
        user_id=current_user.id,
        book_id=review.book_id,
        rating=review.rating,
        review_text=review.review_text
    )
    db.add(db_review)
    db.commit()
    db.refresh(db_review)
    return db_review

@app.get("/reviews/", response_model=List[ReviewResponse])
def get_reviews(
    book_id: Optional[int] = None,
    user_id: Optional[int] = None,
    skip: int = 0, 
    limit: int = 100, 
    db: Session = Depends(get_db)
):
    query = db.query(Review)
    
    if book_id:
        query = query.filter(Review.book_id == book_id)
    if user_id:
        query = query.filter(Review.user_id == user_id)
    
    return query.offset(skip).limit(limit).all()

# Root endpoint
@app.get("/")
async def root():
    return {
        "message": "Welcome to 4BookLovers API",
        "documentation": "/docs",
        "version": "1.0.0"
    }

