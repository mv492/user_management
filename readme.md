# README: User Profile Management, QA Issues, Comprehensive Testing & DockerHub Deployment

📌 Implemented Feature: Self-Service Profile Updates & Professional Status Management
We’ve added two powerful profile‑centric capabilities:

Self‑Service Profile Updates (PATCH /users/me)
Authenticated users can now edit their own profile fields—first/last name, bio, and social links—directly via API, with validation via a new UserProfileUpdate schema.

Professional Status Management (POST /users/{user_id}/professional-status)
Administrators and Managers can toggle any user’s professional status. Each change updates the is_professional flag, stamps professional_status_updated_at with UTC, and fires an email notification (professional_status type) to the affected user.

## QA Issues
# 1. Registration Status Code: 200 OK → 201 Created

Problem:
The public registration endpoint (POST /register/) was returning 200 OK on success, violating REST conventions for resource creation.

Fix:
Updated the decorator on /register/ to specify status_code=201

# 2. Duplicate‑Email Registration: Silent Success → 400 Bad Request
Problem:
Creating a user with an email that already existed simply returned None (and ultimately 500), instead of rejecting the request.

Fix:
In UserService.create(), detect existing email and raise an HTTPException(400)

# 3. Password Complexity on Registration: 
Problem:
Passwords like “1234” or “onlyletters” were accepted during registration, undermining security.

Fix:
Added Pydantic validation in UserCreate schema

# 4. Role Enum Validation: 
Problem:
Endpoints accepted any string in the role field (e.g. “superuser”), leading to invalid entries.

Fix:
Changed role in UserCreate and UserUpdate schemas to Optional[UserRole] (the SQLAlchemy‑backed enum), so Pydantic rejects unknown value

# 5. Login Error Code: 500 → 401 Unauthorized
Problem:
Invalid credentials (wrong email/password) surfaced as a 500 Internal Server Error due to uncaught exceptions.

Fix:
Wrapped the /login/ logic in try/except, re‑raising HTTPException(401) for bad creds and catching all other errors to return 401