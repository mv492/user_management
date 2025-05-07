from builtins import str
import pytest
from httpx import AsyncClient
from app.main import app
from app.models.user_model import User, UserRole
from app.utils.nickname_gen import generate_nickname
from app.utils.security import hash_password
from app.services.jwt_service import decode_token  # Import your FastAPI app
from app.models.user_model import PasswordResetToken
from app.services.user_service import UserService
from app.dependencies import get_email_service
from datetime import datetime, timedelta
from sqlalchemy import select

# Example of a test function using the async_client fixture
@pytest.mark.asyncio
async def test_create_user_access_denied(async_client, user_token, email_service):
    headers = {"Authorization": f"Bearer {user_token}"}
    # Define user data for the test
    user_data = {
        "nickname": generate_nickname(),
        "email": "test@example.com",
        "password": "sS#fdasrongPassword123!",
    }
    # Send a POST request to create a user
    response = await async_client.post("/users/", json=user_data, headers=headers)
    # Asserts
    assert response.status_code == 403

# You can similarly refactor other test functions to use the async_client fixture
@pytest.mark.asyncio
async def test_retrieve_user_access_denied(async_client, verified_user, user_token):
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.get(f"/users/{verified_user.id}", headers=headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_retrieve_user_access_allowed(async_client, admin_user, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.get(f"/users/{admin_user.id}", headers=headers)
    assert response.status_code == 200
    assert response.json()["id"] == str(admin_user.id)

@pytest.mark.asyncio
async def test_update_user_email_access_denied(async_client, verified_user, user_token):
    updated_data = {"email": f"updated_{verified_user.id}@example.com"}
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.put(f"/users/{verified_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_update_user_email_access_allowed(async_client, admin_user, admin_token):
    updated_data = {"email": f"updated_{admin_user.id}@example.com"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["email"] == updated_data["email"]


@pytest.mark.asyncio
async def test_delete_user(async_client, admin_user, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    delete_response = await async_client.delete(f"/users/{admin_user.id}", headers=headers)
    assert delete_response.status_code == 204
    # Verify the user is deleted
    fetch_response = await async_client.get(f"/users/{admin_user.id}", headers=headers)
    assert fetch_response.status_code == 404

@pytest.mark.asyncio
async def test_create_user_duplicate_email(async_client, verified_user):
    user_data = {
        "email": verified_user.email,
        "password": "AnotherPassword123!",
        "role": UserRole.ADMIN.name
    }
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 400
    assert "Email already exists" in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_create_user_invalid_email(async_client):
    user_data = {
        "email": "notanemail",
        "password": "ValidPassword123!",
    }
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 422

import pytest
from app.services.jwt_service import decode_token
from urllib.parse import urlencode

@pytest.mark.asyncio
async def test_login_success(async_client, verified_user):
    # Attempt to login with the test user
    form_data = {
        "username": verified_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    
    # Check for successful login response
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

    # Use the decode_token method from jwt_service to decode the JWT
    decoded_token = decode_token(data["access_token"])
    assert decoded_token is not None, "Failed to decode token"
    assert decoded_token["role"] == "AUTHENTICATED", "The user role should be AUTHENTICATED"

@pytest.mark.asyncio
async def test_login_user_not_found(async_client):
    form_data = {
        "username": "nonexistentuser@here.edu",
        "password": "DoesNotMatter123!"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401
    assert "Incorrect email or password." in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_login_incorrect_password(async_client, verified_user):
    form_data = {
        "username": verified_user.email,
        "password": "IncorrectPassword123!"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401
    assert "Incorrect email or password." in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_login_unverified_user(async_client, unverified_user):
    form_data = {
        "username": unverified_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_login_locked_user(async_client, locked_user):
    form_data = {
        "username": locked_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 400
    assert "Account locked due to too many failed login attempts." in response.json().get("detail", "")
@pytest.mark.asyncio
async def test_delete_user_does_not_exist(async_client, admin_token):
    non_existent_user_id = "00000000-0000-0000-0000-000000000000"  # Valid UUID format
    headers = {"Authorization": f"Bearer {admin_token}"}
    delete_response = await async_client.delete(f"/users/{non_existent_user_id}", headers=headers)
    assert delete_response.status_code == 404

@pytest.mark.asyncio
async def test_update_user_github(async_client, admin_user, admin_token):
    updated_data = {"github_profile_url": "http://www.github.com/kaw393939"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["github_profile_url"] == updated_data["github_profile_url"]

@pytest.mark.asyncio
async def test_update_user_linkedin(async_client, admin_user, admin_token):
    updated_data = {"linkedin_profile_url": "http://www.linkedin.com/kaw393939"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["linkedin_profile_url"] == updated_data["linkedin_profile_url"]

@pytest.mark.asyncio
async def test_list_users_as_admin(async_client, admin_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    assert 'items' in response.json()

@pytest.mark.asyncio
async def test_list_users_as_manager(async_client, manager_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {manager_token}"}
    )
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_list_users_unauthorized(async_client, user_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert response.status_code == 403  # Forbidden, as expected for regular user

@pytest.mark.asyncio
async def test_login_with_invalid_credentials_returns_500(async_client):
    """
    QA Issue: Login should not return 500 on invalid credentials.
    This test verifies that currently (pre‑fix) an invalid login
    yields a 500 Internal Server Error.
    """
    # Attempt login with a non‑existent user / wrong password
    resp = await async_client.post(
        "/login/",
        data={"username": "doesnotexist@example.com", "password": "wrongpassword"}
    )
    assert resp.status_code == 401, (
        f"Expected 401 for invalid credentials, got {resp.status_code}"
    )
    assert resp.json().get("detail") == "Incorrect email or password."

@pytest.mark.asyncio
async def test_create_user_with_invalid_role_returns_422(async_client, email_service, admin_token):
    """
    POST /users/ should 422 if role isn't one of the UserRole values.
    """
    payload = {
        "nickname": "testnick",
        "email": "rolefail@example.com",
        "password": "ValidPass123!",
        "role": "SUPERUSER"   # not in UserRole
    }
    resp = await async_client.post(
        "/users/",
        json=payload,
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert resp.status_code == 422
    # Check that the error mentions 'role'
    assert any(err["loc"][-1] == "role" for err in resp.json()["detail"])   
    
@pytest.mark.asyncio
async def test_update_user_with_invalid_role_returns_422(async_client, admin_token, user):
    """
    PUT /users/{id} should 422 on bad role.
    """
    payload = {"role": "POWERUSER"}  # invalid
    resp = await async_client.put(
        f"/users/{user.id}",
        json=payload,
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert resp.status_code == 422
    # again, ensure the failure is on the 'role' field
    assert any(err["loc"][-1] == "role" for err in resp.json()["detail"])

@pytest.mark.asyncio
async def test_registration_rejects_too_short_password(async_client, email_service):
    payload = {
        "nickname": "shortpw",
        "email": "shortpw@example.com",
        "password": "Ab1",             # too short
        "role": "AUTHENTICATED"
    }
    resp = await async_client.post(
        "/register/",
        json=payload
    )
    assert resp.status_code == 422
    # ensure error is about password length
    errs = resp.json()["detail"]
    assert any(e["loc"][-1] == "password" for e in errs)
    assert any("at least 8" in e["msg"] for e in errs), f"Password length error not found in: {errs}"


@pytest.mark.asyncio
async def test_registration_rejects_password_without_digit(async_client, email_service):
    payload = {
        "nickname": "nodigitpw",
        "email": "nodigit@example.com",
        "password": "NoDigitsHere!",   # letters but no digit
        "role": "AUTHENTICATED"
    }
    resp = await async_client.post(
        "/register/",
        json=payload
    )
    assert resp.status_code == 422
    errs = resp.json()["detail"]
    assert any(e["loc"][-1] == "password" for e in errs)
    assert any("must contain at least one digit" in e["msg"] for e in errs)


@pytest.mark.asyncio
async def test_registration_rejects_password_without_letter(async_client, email_service):
    payload = {
        "nickname": "noletterpw",
        "email": "noletter@example.com",
        "password": "12345678",        # digits only
        "role": "AUTHENTICATED"
    }
    resp = await async_client.post(
        "/register/",
        json=payload
    )
    assert resp.status_code == 422
    errs = resp.json()["detail"]
    assert any(e["loc"][-1] == "password" for e in errs)
    assert any("must contain at least one letter" in e["msg"] for e in errs)

@pytest.mark.asyncio
async def test_create_user_duplicate_email_returns_400(async_client, admin_token, verified_user):
    """
    POST /users/ (admin) should reject a duplicate email with 400.
    """
    payload = {
        "nickname": "new_nick",
        "email": verified_user.email,     # already in DB
        "password": "ValidPass123!",
        "role": "AUTHENTICATED"
    }
    resp = await async_client.post(
        "/users/",
        json=payload,
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Email already exists"


@pytest.mark.asyncio
async def test_register_duplicate_email_returns_400(async_client, verified_user):
    """
    POST /register/ should also reject duplicate email with 400.
    """
    payload = {
        "nickname": "another_nick",
        "email": verified_user.email,     # already in DB
        "password": "ValidPass123!",
        "role": "AUTHENTICATED"
    }
    resp = await async_client.post(
        "/register/",
        json=payload
    )
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Email already exists"

@pytest.mark.asyncio
async def test_register_returns_201_created(async_client, email_service):
    """
    POST /register/ should return 201 Created on successful registration.
    """
    payload = {
        "nickname": "newuser",
        "email": "newuser@example.com",
        "password": "StrongPass123!",
        "role": "AUTHENTICATED"
    }
    resp = await async_client.post("/register/", json=payload)
    assert resp.status_code == 201, f"Expected 201, got {resp.status_code}"
    body = resp.json()
    assert body["email"] == payload["email"]
    assert "id" in body

@pytest.mark.asyncio
async def test_password_reset_request_nonexistent_email(async_client):
    """
    POST /users/password-reset with an email not in the system should return 404.
    """
    resp = await async_client.post("/users/password-reset", json={"email": "noone@example.com"})
    assert resp.status_code == 404
    assert resp.json()["detail"] == "No such user"

@pytest.mark.asyncio
async def test_password_reset_request_success(async_client, db_session, verified_user, email_service):
    """
    POST /users/password-reset with a valid email should return 200
    and create a PasswordResetToken in the database.
    """
    # override the email service so send_user_email() is a no-op
    async_client.app.dependency_overrides[get_email_service] = lambda: email_service

    resp = await async_client.post(
        "/users/password-reset",
        json={"email": verified_user.email}
    )
    assert resp.status_code == 200

    # inspect the DB for a new reset token
    result = await db_session.execute(
        select(PasswordResetToken).filter_by(user_id=verified_user.id)
    )
    pr = result.scalars().first()
    assert pr is not None
    assert pr.expires_at > datetime.utcnow()

    async_client.app.dependency_overrides.clear()

@pytest.mark.asyncio
async def test_reset_link_validation_invalid_token(async_client):
    """
    GET /users/password-reset/verify?token=bad should return 400.
    """
    resp = await async_client.get("/users/password-reset/verify", params={"token": "badtoken"})
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Invalid token"

@pytest.mark.asyncio
async def test_reset_link_validation_expired_token(async_client, db_session, verified_user):
    """
    GET /users/password-reset/verify?token=expired should return 410.
    """
    # insert an already-expired token
    expired = PasswordResetToken(
        token="expiredtoken",
        user_id=verified_user.id,
        created_at=datetime.utcnow() - timedelta(days=2),
        expires_at=datetime.utcnow() - timedelta(days=1),
    )
    db_session.add(expired)
    await db_session.commit()

    resp = await async_client.get("/users/password-reset/verify", params={"token": "expiredtoken"})
    assert resp.status_code == 410
    assert resp.json()["detail"] == "Token expired"

@pytest.mark.asyncio
async def test_password_update_success_and_login(async_client, db_session, verified_user):
    """
    POST /users/password-reset/confirm with a valid token and new strong password → 200,
    and then logging in with the new password succeeds.
    """
    # generate a valid reset token
    token = await UserService.create_password_reset(db_session, verified_user.email)
    new_pw = "NewStrongPass123!"

    resp = await async_client.post(
        "/users/password-reset/confirm",
        json={"token": token, "new_password": new_pw}
    )
    assert resp.status_code == 200

    # now try logging in with the new password
    login = await async_client.post(
        "/login/",
        data={"username": verified_user.email, "password": new_pw}
    )
    assert login.status_code == 200
    assert "access_token" in login.json()

@pytest.mark.asyncio
async def test_password_update_enforces_complexity(async_client, db_session, verified_user):
    """
    POST /users/password-reset/confirm with too-short new password → 422.
    """
    token = await UserService.create_password_reset(db_session, verified_user.email)
    resp = await async_client.post(
        "/users/password-reset/confirm",
        json={"token": token, "new_password": "short"}
    )
    assert resp.status_code == 422
    # Detail comes back as a plain string
    detail = resp.json()["detail"]
    assert detail == "Password must be at least 8 characters"