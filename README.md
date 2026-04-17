# Secure Notes Vault

A cybersecurity lab final project: Secure Authentication System with Two-Factor Verification and Protected Notes Dashboard.

## Features

- Username and password authentication
- Password hashing with bcrypt
- Two-factor authentication using OTP
- Account lockout after 3 failed login attempts
- Password recovery with expiring reset token
- Strong password validation
- New device login notification simulation
- PostgreSQL database support through Supabase or Neon
- SQL Injection protection using parameterized queries
- XSS protection using Jinja escaping and input sanitization
- CSRF protection using Flask-WTF
- Secure session handling
- Notes dashboard with create, edit, delete, and search
- Activity log

## Deploy using Render Free + Supabase PostgreSQL

1. Create a free Supabase project.
2. Copy your Supabase PostgreSQL connection string.
3. Upload this project to GitHub.
4. Create a Render Web Service from the GitHub repository.
5. Use:

```text
Build Command: pip install -r requirements.txt
Start Command: gunicorn app:app
```

6. Add Render environment variables:

```text
SECRET_KEY = any long random string
DATABASE_URL = your Supabase PostgreSQL connection string
```

7. Deploy.

## Important

Use the Supabase **Session pooler** connection string if the direct connection string causes connection problems on Render.

OTP, password reset link, and new-device notification are printed in Render Logs for lab demonstration.
# secure_notes_vault
