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
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Optional, Generator, Union
from database import Base, engine, SessionLocal
from models import User

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

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
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
