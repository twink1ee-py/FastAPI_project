from fastapi.testclient import TestClient
from main import app
from database import SessionLocal, engine
from models import Base
import pytest

client = TestClient(app)

def override_get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()

@pytest.fixture(scope="module", autouse=True)
def setup_database():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

def test_register_user():
    response = client.post(
        "/register",
        json={"username": "testuser", "password": "testpass"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "id" in data
    assert data["username"] == "testuser"


def test_login():
    client.post("/register", json={"username": "testuser", "password": "testpass"})
    response = client.post(
        "/token",
        data={"username": "testuser", "password": "testpass"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

def test_crud_operations():
    response = client.post(
        "/token",
        data={"username": "testuser", "password": "testpass"}
    )
    token = response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    response = client.post(
        "/books",
        json={"title": "Test Book", "author": "Test Author"},
        headers=headers
    )
    assert response.status_code == 200
    book_id = response.json()["id"]

    response = client.get(f"/books/{book_id}", headers=headers)
    assert response.status_code == 200
    assert response.json()["title"] == "Test Book"

    response = client.put(
        f"/books/{book_id}",
        json={"title": "Updated Book", "author": "Updated Author"},
        headers=headers
    )
    assert response.status_code == 200
    assert response.json()["title"] == "Updated Book"

    response = client.delete(f"/books/{book_id}", headers=headers)
    assert response.status_code == 200
    assert response.json()["detail"] == "Book deleted"

def test_borrow_and_return_book():
    response = client.post(
        "/token",
        data={"username": "testuser", "password": "testpass"}
    )
    token = response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    response = client.post(
        "/books",
        json={"title": "Borrowable Book", "author": "Test Author"},
        headers=headers
    )
    book_id = response.json()["id"]

    response = client.post(
        "/borrow",
        json={"book_id": book_id},
        headers=headers
    )
    assert response.status_code == 200
    assert response.json()["returned_at"] is None

    response = client.post(
        "/return",
        json={"book_id": book_id},
        headers=headers
    )
    assert response.status_code == 200
    assert response.json()["returned_at"] is not None

def test_recommendations():
    response = client.post(
        "/token",
        data={"username": "testuser", "password": "testpass"}
    )
    token = response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    client.post("/books", json={"title": "Book 1", "author": "Author 1"}, headers=headers)
    client.post("/books", json={"title": "Book 2", "author": "Author 2"}, headers=headers)

    response = client.get("/recommendations", headers=headers)
    assert response.status_code == 200
    books = response.json()
    assert len(books) > 0