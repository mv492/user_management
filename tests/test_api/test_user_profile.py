import pytest
from fastapi import status
from app.dependencies import get_email_service

@pytest.mark.asyncio
async def test_update_own_profile(async_client, verified_user, user_token):
    resp = await async_client.patch(
        "/users/me",
        json={"bio": "New bio", "first_name": "Alice"},
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["bio"] == "New bio"
    assert data["first_name"] == "Alice"

@pytest.mark.asyncio
async def test_update_profile_unauthenticated(async_client):
    resp = await async_client.patch("/users/me", json={"bio": "X"})
    assert resp.status_code == status.HTTP_401_UNAUTHORIZED

@pytest.mark.asyncio
async def test_manager_can_set_professional_status(
    async_client, manager_token, verified_user, db_session, email_service
):
    # override email svc so no real send
    async_client.app.dependency_overrides[get_email_service] = lambda: email_service

    resp = await async_client.post(
        f"/users/{verified_user.id}/professional-status",
        json={"is_professional": True},
        headers={"Authorization": f"Bearer {manager_token}"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_professional"] is True

    # check timestamp in DB
    from app.models.user_model import User
    user = await db_session.get(User, verified_user.id)
    assert user.is_professional
    assert user.professional_status_updated_at is not None

@pytest.mark.asyncio
async def test_non_manager_cannot_set_professional_status(
    async_client, user_token, verified_user
):
    resp = await async_client.post(
        f"/users/{verified_user.id}/professional-status",
        json={"is_professional": True},
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert resp.status_code == status.HTTP_403_FORBIDDEN

@pytest.mark.asyncio
async def test_professional_status_email_sent(
    async_client, manager_token, verified_user, email_service
):
    # Use mock email service
    async_client.app.dependency_overrides[get_email_service] = lambda: email_service

    await async_client.post(
        f"/users/{verified_user.id}/professional-status",
        json={"is_professional": False},
        headers={"Authorization": f"Bearer {manager_token}"}
    )
    # email_service.send_user_email called once with our type
    email_service.send_user_email.assert_awaited_once()
