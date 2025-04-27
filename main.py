"""
REST-сервис для управления библиотекой книг.

Этот проект реализует REST API для выполнения CRUD-операций с пользователями,
книгами и заимствованиями. Включает аутентификацию, авторизацию и бизнес-логику
для рекомендации популярных книг на основе количества заимствований.

Основные компоненты:
1. Регистрация и авторизация пользователей.
2. CRUD-операции для управления каталогом книг.
3. Функционал заимствования и возврата книг.
4. Рекомендация популярных книг.

Технологии:
- FastAPI: Для создания REST API.
- SQLAlchemy: Для работы с базой данных.
- Pydantic: Для валидации данных.
- JWT: Для аутентификации и авторизации.
"""

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import List, Optional, Generator, Union
from database import Base, engine, SessionLocal
from models import User, Book, BorrowedBook
from schemas import UserCreate, UserInDB, Token, BookCreate, BookResponse, BorrowedBookResponse, BorrowBookRequest

app = FastAPI()

SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

Base.metadata.create_all(bind=engine)

def get_db() -> Generator[Session, None, None]:
    """
        Создает и предоставляет сессию базы данных через генератор.

        Сессия используется для выполнения операций с базой данных.
        После завершения работы сессия автоматически закрывается.

        Yields:
            Session: Объект сессии SQLAlchemy.
        """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password) -> bool:
    """
        Проверяет, соответствует ли обычный пароль хэшированному паролю.

        Args:
            plain_password (str): Пароль в открытом виде.
            hashed_password (str): Хэшированный пароль из базы данных.

        Returns:
            bool: True, если пароли совпадают, иначе False.
    """
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password) -> str:
    """
        Создает хэш для заданного пароля.

        Args:
            password (str): Пароль в открытом виде.

        Returns:
            str: Хэшированный пароль.
    """
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
        Создает JWT-токен доступа на основе входных данных.

        Args:
            data (dict): Данные для кодирования в токен (например, username).
            expires_delta (Optional[timedelta]): Время жизни токена. Если не указано,
                используется значение по умолчанию (15 минут).

        Returns:
            str: Закодированный JWT-токен.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now() + expires_delta
    else:
        expire = datetime.now() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def authenticate_user(db: Session, username: str, password: str) -> Union[User, bool]:
    """
        Аутентифицирует пользователя по имени пользователя и паролю.

        Args:
            db (Session): Сессия базы данных.
            username (str): Имя пользователя.
            password (str): Пароль пользователя.

        Returns:
            Union[User, bool]: Объект пользователя, если аутентификация успешна,
                иначе False.
    """
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        return False
    return user

async def get_current_user(
        token: str = Depends(oauth2_scheme),
        db: Session = Depends(get_db)
) -> User:
    """
       Получает текущего пользователя на основе JWT-токена.

       Args:
           token (str): JWT-токен доступа.
           db (Session): Сессия базы данных.

       Raises:
           HTTPException: Если токен недействителен или пользователь не найден.

       Returns:
           User: Объект текущего пользователя.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

@app.post("/register", response_model=UserInDB)
def register(user: UserCreate, db: Session = Depends(get_db)) -> User:
    """
        Регистрирует нового пользователя в системе.

        Args:
            user (UserCreate): Данные для регистрации нового пользователя (username и password).
            db (Session): Сессия базы данных.

        Raises:
            HTTPException: Если пользователь с таким именем уже зарегистрирован.

        Returns:
            User: Созданный объект пользователя.
    """
    existing_user = db.query(User).filter(User.username == user.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(user.password)
    db_user = User(username=user.username, password_hash=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/token", response_model=Token)
def login_for_access_token(
        form_data: OAuth2PasswordRequestForm = Depends(),
        db: Session = Depends(get_db)
) -> dict:
    """
        Аутентифицирует пользователя и выдает токен доступа.

        Args:
            form_data (OAuth2PasswordRequestForm): Данные формы для аутентификации (user и pass).
            db (Session): Сессия базы данных.

        Raises:
            HTTPException: Если имя пользователя или пароль неверны.

        Returns:
            dict: Токен доступа и его тип.
    """
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username},
                                       expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/books", response_model=BookResponse)
def create_book(
        book: BookCreate,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
) -> Book:
    """
    Создает новую книгу в базе данных.

    Args:
        book (BookCreate): Данные для создания книги (заголовок и автор).
        db (Session): Сессия базы данных для выполнения операций.
        current_user (User): Текущий авторизованный пользователь.

    Returns:
        Book: Созданный объект книги.
    """
    db_book = Book(title=book.title, author=book.author)
    db.add(db_book)
    db.commit()
    db.refresh(db_book)
    return db_book

@app.get("/books", response_model=List[BookResponse])
def read_books(skip: int = 0, limit: int = 10, db: Session = Depends(get_db)) -> Book:
    """
       Возвращает список книг с поддержкой пагинации.

       Args:
           skip (int): Количество записей, которые нужно пропустить.
           limit (int): Максимальное количество записей для возврата.
           db (Session): Сессия базы данных для выполнения операций.

       Returns:
           List[Book]: Список объектов книг.
    """
    books = db.query(Book).offset(skip).limit(limit).all()
    return books

@app.put("/books/{book_id}", response_model=BookResponse)
def update_book(
        book_id: int,
        book: BookCreate,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
) -> Book:
    """
    Обновляет данные книги по её ID.

    Args:
        book_id (int): ID книги, которую нужно обновить.
        book (BookCreate): Новые данные для книги (заголовок и автор).
        db (Session): Сессия базы данных для выполнения операций.
        current_user (User): Текущий авторизованный пользователь.

    Raises:
        HTTPException: Если книга с указанным ID не найдена.

    Returns:
        Book: Обновленный объект книги.
    """
    db_book = db.query(Book).filter(Book.id == book_id).first()
    if db_book is None:
        raise HTTPException(status_code=404, detail="Book not found")
    db_book.title = book.title
    db_book.author = book.author
    db.commit()
    db.refresh(db_book)
    return db_book

@app.delete("/books/{book_id}")
def delete_book(
        book_id: int,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
) -> dict:
    """
    Удаляет книгу по её ID.

    Args:
        book_id (int): ID книги, которую нужно удалить.
        db (Session): Сессия базы данных для выполнения операций.
        current_user (User): Текущий авторизованный пользователь.

    Raises:
        HTTPException: Если книга с указанным ID не найдена.

    Returns:
        dict: Сообщение об успешном удалении.
    """
    db_book = db.query(Book).filter(Book.id == book_id).first()
    if db_book is None:
        raise HTTPException(status_code=404, detail="Book not found")
    db.delete(db_book)
    db.commit()
    return {"detail": "Book deleted"}

@app.post("/borrow", response_model=BorrowedBookResponse)
def borrow_book(
    request: BorrowBookRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> BorrowedBook:
    """
    Позволяет пользователю заимствовать книгу.

    Args:
        request (BorrowBookRequest): Запрос на заимствование книги (ID книги).
        db (Session): Сессия базы данных для выполнения операций.
        current_user (User): Текущий авторизованный пользователь.

    Raises:
        HTTPException: Если книга не найдена или уже заимствована.

    Returns:
        BorrowedBook: Созданная запись о заимствовании.
    """
    book = db.query(Book).filter(Book.id == request.book_id).first()
    if not book:
        raise HTTPException(status_code=404, detail="Book not found")

    existing_borrow = db.query(BorrowedBook).filter(
        BorrowedBook.book_id == request.book_id,
        BorrowedBook.returned_at.is_(None)
    ).first()
    if existing_borrow:
        raise HTTPException(status_code=400, detail="Book is already borrowed")

    borrowed_book = BorrowedBook(
        user_id=current_user.id,
        book_id=request.book_id,
        borrowed_at=datetime.utcnow()
    )
    db.add(borrowed_book)

    book.borrow_count += 1
    db.commit()
    db.refresh(borrowed_book)

    return borrowed_book

@app.post("/return", response_model=BorrowedBookResponse)
def return_book(
    request: BorrowBookRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> BorrowedBook:
    """
    Позволяет пользователю вернуть заимствованную книгу.

    Args:
        request (BorrowBookRequest): Запрос на возврат книги (ID книги).
        db (Session): Сессия базы данных для выполнения операций.
        current_user (User): Текущий авторизованный пользователь.

    Raises:
        HTTPException: Если книга не была заимствована текущим пользователем.

    Returns:
        BorrowedBook: Обновленная запись о заимствовании с временем возврата.
    """
    borrowed_book = db.query(BorrowedBook).filter(
        BorrowedBook.book_id == request.book_id,
        BorrowedBook.user_id == current_user.id,
        BorrowedBook.returned_at.is_(None)
    ).first()

    if not borrowed_book:
        raise HTTPException(status_code=400, detail="Book was not borrowed by this user")

    borrowed_book.returned_at = datetime.utcnow()
    db.commit()
    db.refresh(borrowed_book)

    return borrowed_book

@app.get("/recommendations", response_model=List[BookResponse])
def recommend_books(db: Session = Depends(get_db)) -> List[Book]:
    """
       Возвращает список из 5 самых популярных книг на основе количества заимствований.

       Args:
           db (Session): Сессия базы данных.

       Returns:
           List[Book]: Список объектов книг, отсортированных по убыванию borrow_count.
    """
    books = db.query(Book).order_by(Book.borrow_count.desc()).limit(5).all()
    return books

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)