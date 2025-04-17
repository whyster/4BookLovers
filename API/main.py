from datetime import datetime, timedelta
from typing import List, Optional
import os
import secrets
from passlib.context import CryptContext
from fastapi import FastAPI, Depends, HTTPException, status, Request, Response, Query
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

# importing all the necessary libraries and modules for our api

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@db:5432/booklover")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# setting up our database connection with sqlalchemy

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# security setup for password hashing and jwt tokens

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI(
    title="4BookLovers API",
    description="Book lovers community API",
    version="1.0.0"
)

# creating our fastapi app instance

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # allowing all origins for development
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
    password_hash = Column(String(255), nullable=False) # we store hashed passwords for security
    created_at = Column(DateTime(timezone=True), default=func.now())
    last_login = Column(DateTime(timezone=True), nullable=True)
    failed_login_attempts = Column(Integer, default=0) # track login attempts for account security
    locked_until = Column(DateTime(timezone=True), nullable=True) # implements account lockout after failed attempts
    is_active = Column(Boolean, default=True)
    
    # defining relationships with other tables
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    shelves = relationship("Shelf", back_populates="user", cascade="all, delete-orphan")
    reviews = relationship("Review", back_populates="user", cascade="all, delete-orphan")
    notes = relationship("BookNote", back_populates="user", cascade="all, delete-orphan")

class Session(Base):
    __tablename__ = "sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    session_token = Column(String(255), unique=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=func.now())
    last_active = Column(DateTime(timezone=True), default=func.now()) # tracks when user was last active
    expires_at = Column(DateTime(timezone=True)) # used to enforce session timeout
    device_info = Column(Text) # stores info about the device used for login
    
    user = relationship("User", back_populates="sessions")

class Book(Base):
    __tablename__ = "books"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    author = Column(String(255), nullable=False)
    isbn = Column(String(20), unique=True) # international standard book number for unique identification
    publisher = Column(String(100))
    publication_year = Column(Integer)
    description = Column(Text)
    cover_image_url = Column(Text) # url to book cover image
    page_count = Column(Integer)
    language = Column(String(50))
    created_at = Column(DateTime(timezone=True), default=func.now())
    
    # many-to-many relationships with tags and shelves
    tags = relationship("Tag", secondary="book_tags", back_populates="books")
    shelves = relationship("Shelf", secondary="shelf_books", back_populates="books")
    reviews = relationship("Review", back_populates="book", cascade="all, delete-orphan")
    notes = relationship("BookNote", back_populates="book", cascade="all, delete-orphan")

class Tag(Base):
    __tablename__ = "tags"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, nullable=False) # tags must be unique
    description = Column(String(1000))
    
    # many-to-many relationship with books
    books = relationship("Book", secondary="book_tags", back_populates="tags")

class BookTag(Base):
    __tablename__ = "book_tags"
    
    # this is a junction table for the many-to-many relationship between books and tags
    book_id = Column(Integer, ForeignKey("books.id", ondelete="CASCADE"), primary_key=True)
    tag_id = Column(Integer, ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True)
    created_at = Column(DateTime(timezone=True), default=func.now())

class Shelf(Base):
    __tablename__ = "shelves"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    name = Column(String(100), nullable=False)
    description = Column(Text)
    is_default = Column(Boolean, default=False) # indicates if this is a system shelf like 'want to read'
    created_at = Column(DateTime(timezone=True), default=func.now())
    
    # relationships
    user = relationship("User", back_populates="shelves")
    books = relationship("Book", secondary="shelf_books", back_populates="shelves")

class ShelfBook(Base):
    __tablename__ = "shelf_books"
    
    # junction table for the many-to-many relationship between shelves and books
    shelf_id = Column(Integer, ForeignKey("shelves.id", ondelete="CASCADE"), primary_key=True)
    book_id = Column(Integer, ForeignKey("books.id", ondelete="CASCADE"), primary_key=True)
    added_at = Column(DateTime(timezone=True), default=func.now()) # tracks when a book was added to a shelf

class Review(Base):
    __tablename__ = "reviews"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    book_id = Column(Integer, ForeignKey("books.id", ondelete="CASCADE"))
    rating = Column(Integer) # 1-5 star rating
    review_text = Column(Text) # actual review content
    created_at = Column(DateTime(timezone=True), default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now()) # updates automatically when review is edited
    
    # relationships
    user = relationship("User", back_populates="reviews")
    book = relationship("Book", back_populates="reviews")

class BookNote(Base):
    __tablename__ = "book_notes"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    book_id = Column(Integer, ForeignKey("books.id", ondelete="CASCADE"))
    note_text = Column(Text) # personal notes about a book
    is_private = Column(Boolean, default=True) # controls whether other users can see this note
    created_at = Column(DateTime(timezone=True), default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now()) # updates automatically when note is edited
    
    # relationships
    user = relationship("User", back_populates="notes")
    book = relationship("Book", back_populates="notes")

# Pydantic Models
class UserBase(BaseModel):
    username: str
    email: EmailStr # ensures email validation

class UserCreate(UserBase):
    password: str
    
    @validator('password')
    def password_validation(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        return v
    # validates password meets minimum requirements

class UserResponse(UserBase):
    id: int
    created_at: datetime
    
    class Config:
        orm_mode = True # allows conversion from sqlalchemy model to pydantic model

class Token(BaseModel):
    access_token: str # jwt token
    token_type: str # usually "bearer"

class TokenData(BaseModel):
    username: Optional[str] = None
    session_id: Optional[int] = None
    # data stored in the jwt token payload

class TagBase(BaseModel):
    name: str
    description: Optional[str] = None

class TagCreate(TagBase):
    pass # just inherits from base model, no additional fields

class TagResponse(TagBase):
    id: int
    
    class Config:
        orm_mode = True # allows conversion from orm model to json

class BookBase(BaseModel):
    title: str
    author: str
    isbn: Optional[str] = None # isbn is optional when creating a book
    publisher: Optional[str] = None
    publication_year: Optional[int] = None
    description: Optional[str] = None
    cover_image_url: Optional[str] = None
    page_count: Optional[int] = None
    language: Optional[str] = None

class BookCreate(BookBase):
    tags: Optional[List[int]] = [] # list of tag ids to assign to the book

class BookResponse(BookBase):
    id: int
    created_at: datetime
    tags: List[TagResponse] # includes the full tag objects, not just ids
    
    class Config:
        orm_mode = True # enables orm instance to json conversion

class ShelfBase(BaseModel):
    name: str
    description: Optional[str] = None

class ShelfCreate(ShelfBase):
    pass # inherits all fields from base

class ShelfResponse(ShelfBase):
    id: int
    user_id: int
    is_default: bool # indicates if this is a system shelf
    created_at: datetime
    
    class Config:
        orm_mode = True # enables conversion to json

class ReviewBase(BaseModel):
    book_id: int
    rating: int = Field(..., ge=1, le=5) # rating must be between 1 and 5
    review_text: Optional[str] = Field(None, max_length=1000) # limits review length

class ReviewCreate(ReviewBase):
    pass # inherits all fields from base

class ReviewResponse(ReviewBase):
    id: int
    user_id: int
    created_at: datetime
    updated_at: Optional[datetime] = None # may be null if never updated
    
    class Config:
        orm_mode = True # enables conversion to json

class BookNoteBase(BaseModel):
    book_id: int
    note_text: str = Field(..., max_length=2000) # limits note length to 2000 chars
    is_private: bool = True # defaults to private

class BookNoteCreate(BookNoteBase):
    pass # inherits all fields from base

class BookNoteResponse(BookNoteBase):
    id: int
    user_id: int
    created_at: datetime
    updated_at: Optional[datetime] = None # may be null if never updated
    
    class Config:
        orm_mode = True # enables conversion to json

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db # provides a db session to the request
    finally:
        db.close() # ensures session is closed even if there's an exception

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password) # checks if password matches hash

def get_password_hash(password):
    return pwd_context.hash(password) # creates secure password hash

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire}) # adds expiration time to token payload
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt # returns the jwt token

def get_user_by_username(db: Session, username: str):
    return db.query(User).filter(User.username == username).first() # finds user by username

def authenticate_user(db: Session, username: str, password: str):
    user = get_user_by_username(db, username)
    if not user:
        return False
    
    # account lockout functionality
    if user.locked_until and user.locked_until > datetime.now(timezone.utc):
        return False # account is locked
    
    if not verify_password(password, user.password_hash):
        # brute force protection
        user.failed_login_attempts += 1
        
        # lock account after 5 failed attempts
        if user.failed_login_attempts >= 5:
            user.locked_until = datetime.now(timezone.utc) + timedelta(hours=24)
        
        db.commit()
        return False
    
    # successful login
    user.failed_login_attempts = 0 # reset counter on success
    user.last_login = datetime.now(timezone.utc) # update last login timestamp
    db.commit()
    
    return user

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # decode the jwt token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        session_id: int = payload.get("session_id")
        if username is None or session_id is None:
            raise credentials_exception
        token_data = TokenData(username=username, session_id=session_id)
    except jwt.PyJWTError:
        raise credentials_exception # invalid token
    
    # get the user from database
    user = get_user_by_username(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    
    # validate that the session exists and hasn't expired
    session = db.query(Session).filter(
        Session.id == token_data.session_id,
        Session.user_id == user.id,
        Session.expires_at > datetime.now(timezone.utc)
    ).first()
    
    if not session:
        raise credentials_exception # invalid or expired session
    
    # extend session lifetime on activity
    session.last_active = datetime.now(timezone.utc)
    session.expires_at = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    db.commit()
    
    return user

# Middleware to check for inactive sessions
@app.middleware("http")
async def check_session_timeout(request: Request, call_next):
    response = await call_next(request)
    
    # skip auth for these paths
    if request.url.path in ["/token", "/docs", "/openapi.json"]:
        return response
    
    # extract token from authorization header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            session_id = payload.get("session_id")
            
            # create a new db session for the middleware
            db = SessionLocal()
            try:
                # check if user has been inactive for too long
                session = db.query(Session).filter(Session.id == session_id).first()
                if session:
                    # auto-logout after 30 minutes of inactivity
                    if (datetime.now(timezone.utc) - session.last_active) > timedelta(minutes=30):
                        session.expires_at = datetime.now(timezone.utc) # invalidate session
                        db.commit()
                        return Response(
                            status_code=status.HTTP_401_UNAUTHORIZED,
                            content="Session expired due to inactivity",
                            headers={"WWW-Authenticate": "Bearer"}
                        )
            finally:
                db.close() # always close the db session
        except Exception:
            pass # ignore errors in middleware
    
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
    
    #limit users to max 5 sessions
    active_sessions = db.query(Session).filter(
        Session.user_id == user.id,
        Session.expires_at > datetime.now(timezone.utc)
    ).count()
    
    if active_sessions >= 5:
        #if at session limit, expire the oldest one
        oldest_session = db.query(Session).filter(
            Session.user_id == user.id
        ).order_by(Session.last_active).first()
        
        if oldest_session:
            oldest_session.expires_at = datetime.now(timezone.utc) #invalidate oldest session
            db.commit()
    
    #create a new session record
    session = Session(
        user_id=user.id,
        session_token=secrets.token_urlsafe(32), #generate random token
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        device_info=form_data.client_id if hasattr(form_data, 'client_id') else None
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    
    #generate jwt token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "session_id": session.id},
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/logout")
async def logout(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    #get token from request cookies
    token = None
    for cookie in db.cookies:
        if cookie.key == "token":
            token = cookie.value
            break
    
    if token:
        try:
            #decode token to get session id
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            session_id: int = payload.get("session_id")
            
            #invalidate the session
            session = db.query(Session).filter(Session.id == session_id).first()
            if session:
                session.expires_at = datetime.now(timezone.utc) #mark session as expired
                db.commit()
        except:
            pass #ignore errors during logout
    
    return {"message": "Successfully logged out"}

# User endpoints
@app.post("/users/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    #check if username is taken
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    #check if email is taken
    db_email = db.query(User).filter(User.email == user.email).first()
    if db_email:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    #hash the password before storing
    hashed_password = get_password_hash(user.password)
    db_user = User(
        username=user.username,
        email=user.email,
        password_hash=hashed_password
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    #automatically create the standard shelves for new users
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
    return current_user #returns the authenticated user's profile

# Book endpoints
@app.post("/books/", response_model=BookResponse, status_code=status.HTTP_201_CREATED)
def create_book(book: BookCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    #create a new book record
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
    
    #associate tags with the book if provided
    if book.tags:
        for tag_id in book.tags:
            tag = db.query(Tag).filter(Tag.id == tag_id).first()
            if tag:
                db_book.tags.append(tag) #add tag to book's tags
        db.commit()
    
    return db_book

class BookWithNoteStatus(BookResponse):
    has_note: bool = False #tracks if the current user has notes for this book

@app.get("/books/", response_model=List[BookWithNoteStatus])
def get_books(
    query: Optional[str] = None,
    search_by: Optional[str] = "all",  # all, title, author, isbn
    skip: int = 0, 
    limit: int = 100,
    sort_field: Optional[str] = None,  # title, author, year
    sort_direction: Optional[str] = "asc",  # asc, desc
    year_from: Optional[int] = None,
    year_to: Optional[int] = None,
    language: Optional[str] = None,
    shelf_ids: List[int] = Query([]),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    # Start with a base query
    base_query = db.query(Book)
    
    # Apply search filter if query is provided
    if query:
        if search_by == "title" or search_by == "all":
            title_query = base_query.filter(Book.title.ilike(f"%{query}%"))
            if search_by == "title":
                base_query = title_query
            else:
                # Search by multiple fields when search_by is "all"
                author_query = db.query(Book).filter(Book.author.ilike(f"%{query}%"))
                isbn_query = db.query(Book).filter(Book.isbn.ilike(f"%{query}%"))
                description_query = db.query(Book).filter(Book.description.ilike(f"%{query}%"))
                base_query = title_query.union(author_query, isbn_query, description_query)
        elif search_by == "author":
            base_query = base_query.filter(Book.author.ilike(f"%{query}%"))
        elif search_by == "isbn":
            base_query = base_query.filter(Book.isbn.ilike(f"%{query}%"))
    
    # Apply advanced filters if provided
    if year_from is not None:
        base_query = base_query.filter(Book.publication_year >= year_from)
    
    if year_to is not None:
        base_query = base_query.filter(Book.publication_year <= year_to)
    
    if language:
        base_query = base_query.filter(Book.language.ilike(f"%{language}%"))
    
    # Filter by shelves if provided
    if shelf_ids and current_user:
        # Get books that are in any of the selected shelves
        shelf_books_query = db.query(ShelfBook.book_id).filter(
            ShelfBook.shelf_id.in_(shelf_ids)
        ).distinct()
        
        shelf_book_ids = [book_id for (book_id,) in shelf_books_query]
        
        if shelf_book_ids:
            base_query = base_query.filter(Book.id.in_(shelf_book_ids))
        else:
            # If no books are in the selected shelves, return empty list
            return []
    
    # Apply sorting if specified
    if sort_field:
        if sort_field == "title":
            order_column = Book.title
        elif sort_field == "author":
            order_column = Book.author
        elif sort_field == "year":
            order_column = Book.publication_year
        else:
            order_column = Book.id  # Default sort by ID
        
        if sort_direction.lower() == "desc":
            base_query = base_query.order_by(order_column.desc())
        else:
            base_query = base_query.order_by(order_column.asc())
    else:
        # Default sort by id (newest first)
        base_query = base_query.order_by(Book.id.desc())
    
    # Apply pagination and get results
    books = base_query.offset(skip).limit(limit).all()
    
    # Mark books that the user has notes for
    if current_user:
        book_ids = [book.id for book in books]
        
        if book_ids:  # Only query if there are books
            user_notes = db.query(BookNote.book_id).filter(
                BookNote.user_id == current_user.id,
                BookNote.book_id.in_(book_ids)
            ).all()
            
            user_note_book_ids = [note[0] for note in user_notes]
            
            # Add has_note flag to each book
            for book in books:
                setattr(book, "has_note", book.id in user_note_book_ids)
        else:
            # No books to annotate
            pass
    
    return books

@app.get("/books/{book_id}", response_model=BookResponse)
def get_book(book_id: int, db: Session = Depends(get_db)):
    #get a specific book by id
    db_book = db.query(Book).filter(Book.id == book_id).first()
    if db_book is None:
        raise HTTPException(status_code=404, detail="Book not found")
    return db_book

# Tag endpoints
@app.post("/tags/", response_model=TagResponse, status_code=status.HTTP_201_CREATED)
def create_tag(tag: TagCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    #check if tag already exists
    db_tag = db.query(Tag).filter(Tag.name == tag.name).first()
    if db_tag:
        raise HTTPException(status_code=400, detail="Tag already exists")
    
    #create a new tag
    db_tag = Tag(name=tag.name, description=tag.description)
    db.add(db_tag)
    db.commit()
    db.refresh(db_tag)
    return db_tag

@app.get("/tags/", response_model=List[TagResponse])
def get_tags(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return db.query(Tag).offset(skip).limit(limit).all() #return paginated list of tags

# Shelf endpoints
@app.post("/shelves/", response_model=ShelfResponse, status_code=status.HTTP_201_CREATED)
def create_shelf(shelf: ShelfCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    #check for duplicate shelf names
    db_shelf = db.query(Shelf).filter(
        Shelf.user_id == current_user.id,
        Shelf.name == shelf.name
    ).first()
    if db_shelf:
        raise HTTPException(status_code=400, detail="Shelf with this name already exists")
    
    #enforce limit of 20 custom shelves per user
    custom_shelves_count = db.query(Shelf).filter(
        Shelf.user_id == current_user.id,
        Shelf.is_default == False
    ).count()
    if custom_shelves_count >= 20:
        raise HTTPException(status_code=400, detail="You have reached the maximum number of custom shelves (20)")
    
    #create new shelf
    db_shelf = Shelf(
        user_id=current_user.id,
        name=shelf.name,
        description=shelf.description,
        is_default=False #user-created shelves are not default
    )
    db.add(db_shelf)
    db.commit()
    db.refresh(db_shelf)
    return db_shelf

@app.get("/shelves/", response_model=List[ShelfResponse])
def get_shelves(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Shelf).filter(Shelf.user_id == current_user.id).all() #get all shelves for current user

@app.post("/shelves/{shelf_id}/books/{book_id}")
def add_book_to_shelf(
    shelf_id: int, 
    book_id: int, 
    db: Session = Depends(get_db), 
    current_user: User = Depends(get_current_user)
):
    #verify shelf belongs to the current user
    db_shelf = db.query(Shelf).filter(
        Shelf.id == shelf_id,
        Shelf.user_id == current_user.id
    ).first()
    if not db_shelf:
        raise HTTPException(status_code=404, detail="Shelf not found or doesn't belong to you")
    
    #verify book exists
    db_book = db.query(Book).filter(Book.id == book_id).first()
    if not db_book:
        raise HTTPException(status_code=404, detail="Book not found")
    
    #prevent duplicate books on a shelf
    shelf_book = db.query(ShelfBook).filter(
        ShelfBook.shelf_id == shelf_id,
        ShelfBook.book_id == book_id
    ).first()
    if shelf_book:
        raise HTTPException(status_code=400, detail="Book already on this shelf")
    
    #check for shelf capacity (max 350 books)
    books_count = db.query(ShelfBook).filter(ShelfBook.shelf_id == shelf_id).count()
    if books_count >= 350:
        raise HTTPException(status_code=400, detail="This shelf has reached the maximum number of books (350)")
    
    #add the book to shelf
    db_shelf_book = ShelfBook(shelf_id=shelf_id, book_id=book_id)
    db.add(db_shelf_book)
    db.commit()
    
    return {"message": "Book added to shelf successfully"}

@app.delete("/shelves/{shelf_id}/books/{book_id}")
def remove_book_from_shelf(
    shelf_id: int, 
    book_id: int, 
    db: Session = Depends(get_db), 
    current_user: User = Depends(get_current_user)
):
    #verify shelf belongs to current user
    db_shelf = db.query(Shelf).filter(
        Shelf.id == shelf_id,
        Shelf.user_id == current_user.id
    ).first()
    if not db_shelf:
        raise HTTPException(status_code=404, detail="Shelf not found or doesn't belong to you")
    
    #verify book exists
    db_book = db.query(Book).filter(Book.id == book_id).first()
    if not db_book:
        raise HTTPException(status_code=404, detail="Book not found")
    
    #verify book is actually on this shelf
    shelf_book = db.query(ShelfBook).filter(
        ShelfBook.shelf_id == shelf_id,
        ShelfBook.book_id == book_id
    ).first()
    if not shelf_book:
        raise HTTPException(status_code=404, detail="Book not found on this shelf")
    
    #remove the book from shelf
    db.delete(shelf_book)
    db.commit()
    
    return {"message": "Book removed from shelf successfully"}

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

# Book Notes endpoints
@app.post("/book-notes/", response_model=BookNoteResponse, status_code=status.HTTP_201_CREATED)
def create_book_note(
    note: BookNoteCreate, 
    db: Session = Depends(get_db), 
    current_user: User = Depends(get_current_user)
):
    # Check if book exists
    db_book = db.query(Book).filter(Book.id == note.book_id).first()
    if not db_book:
        raise HTTPException(status_code=404, detail="Book not found")
    
    # Check if user already has a note for this book
    db_note = db.query(BookNote).filter(
        BookNote.user_id == current_user.id,
        BookNote.book_id == note.book_id
    ).first()
    
    # If note exists, update it
    if db_note:
        db_note.note_text = note.note_text
        db_note.is_private = note.is_private
        db_note.updated_at = datetime.now(timezone.utc)
    else:
        # Create new note
        db_note = BookNote(
            user_id=current_user.id,
            book_id=note.book_id,
            note_text=note.note_text,
            is_private=note.is_private
        )
        db.add(db_note)
    
    db.commit()
    db.refresh(db_note)
    return db_note

@app.get("/book-notes/", response_model=List[BookNoteResponse])
def get_book_notes(
    book_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Only return the current user's notes or public notes from others
    query = db.query(BookNote).filter(
        (BookNote.user_id == current_user.id) | (BookNote.is_private == False)
    )
    
    if book_id:
        query = query.filter(BookNote.book_id == book_id)
    
    return query.all()

@app.get("/book-notes/{book_id}", response_model=BookNoteResponse)
def get_book_note(
    book_id: int, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Get the note for the specific book for the current user
    db_note = db.query(BookNote).filter(
        BookNote.user_id == current_user.id,
        BookNote.book_id == book_id
    ).first()
    
    if not db_note:
        raise HTTPException(status_code=404, detail="Note not found for this book")
    
    return db_note

@app.delete("/book-notes/{book_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_book_note(
    book_id: int, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Get the note for the specific book for the current user
    db_note = db.query(BookNote).filter(
        BookNote.user_id == current_user.id,
        BookNote.book_id == book_id
    ).first()
    
    if not db_note:
        raise HTTPException(status_code=404, detail="Note not found for this book")
    
    db.delete(db_note)
    db.commit()
    
    return Response(status_code=status.HTTP_204_NO_CONTENT)

@app.get("/shelves/{shelf_id}/books", response_model=List[BookWithNoteStatus])
def get_books_by_shelf(
    shelf_id: int,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    #verify shelf belongs to current user
    db_shelf = db.query(Shelf).filter(
        Shelf.id == shelf_id,
        Shelf.user_id == current_user.id
    ).first()
    if not db_shelf:
        raise HTTPException(status_code=404, detail="Shelf not found or doesn't belong to you")
    
    #get books from specified shelf
    books = db.query(Book).join(
        ShelfBook, Book.id == ShelfBook.book_id
    ).filter(
        ShelfBook.shelf_id == shelf_id
    ).offset(skip).limit(limit).all() #paginate results
    
    #add has_note flag to show if user has notes for each book
    if books:
        book_ids = [book.id for book in books]
        user_notes = db.query(BookNote.book_id).filter(
            BookNote.user_id == current_user.id,
            BookNote.book_id.in_(book_ids)
        ).all()
        
        user_note_book_ids = [note[0] for note in user_notes]
        
        #mark books that have notes
        for book in books:
            setattr(book, "has_note", book.id in user_note_book_ids)
    
    return books

# Root endpoint
@app.get("/")
async def root():
    return {
        "message": "Welcome to 4BookLovers API",
        "documentation": "/docs",
        "version": "1.0.0"
    }

