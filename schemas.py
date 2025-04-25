from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class UserCreate(BaseModel):
    username: str
    password: str

class UserInDB(BaseModel):
    id: int
    username: str

    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str

class BookCreate(BaseModel):
    title: str
    author: str

class BookResponse(BaseModel):
    id: int
    title: str
    author: str
    borrow_count: int

    class Config:
        orm_mode = True

class BorrowBookRequest(BaseModel):
    book_id: int

class BorrowedBookResponse(BaseModel):
    id: int
    user_id: int
    book_id: int
    borrowed_at: datetime
    returned_at: Optional[datetime]

    class Config:
        orm_mode = True