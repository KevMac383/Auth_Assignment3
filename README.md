# CSEC 472 — Assignment 3, Task 1: README

## How to Run

1. Open `auth_system.ipynb` in Jupyter Notebook or JupyterLab.
2. Run **Cell 1** to install dependencies (`argon2-cffi`).
3. Run **Cell 2** to define all functions.
4. Run **Cell 3** to launch the interactive menu.

> **Note:** If running locally on Windows, install the dependency manually first:
> ```
> python -m pip install argon2-cffi
> ```

---

## Implementation Map

All line numbers reference **Cell 2** of the notebook unless marked *(Cell 3)*.

> **Tip:** To view line numbers in Jupyter Notebook, go to **View → Toggle Line Numbers**.

---

### Task 1-A: Secure Password Storage

| Requirement | Function | Lines |
|---|---|---|
| 1-A-A: Implement Argon2 hashing to securely store passwords | `hash_password()` | Cell 2, `return ph.hash(password)` |
| 1-A-B: Store only the hashed password in a JSON file | `register_user()` | Cell 2, `'hashed_password': hashed` in the user record dict |
| 1-A-C: Use Argon2's salt and work factor to enhance security | `PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)` | Cell 2, top-level constant after imports |

---

### Task 1-B: User Login and Brute-Force Protection

| Requirement | Function | Lines |
|---|---|---|
| 1-B-A: Implement a login system that verifies user credentials securely | `login_user()` | Cell 2 |
| 1-B-B: Password strength check (min 16 chars, cannot equal username) | `check_password_strength()` | Cell 2; called inside `register_user()` |
| 1-B-C: Lock accounts for 15 minutes after 5 failed login attempts | `record_failed_attempt()`, `is_account_locked()` | Cell 2; counter incremented on each failure, lockout timestamp set at MAX_FAILURES |
| 1-B-D: Prevent timing attacks using constant-time comparison | `verify_password()`, `login_user()` | Cell 2; `ph.verify()` is constant-time; dummy hash used for non-existent usernames |

---

### Task 1-C: Two-Factor Authentication (TOTP)

| Requirement | Function | Lines |
|---|---|---|
| 1-C-A: Generate a 6-digit TOTP based on HMAC(time, key) | `generate_totp()` | Cell 2; full RFC 6238 implementation using `hmac`, `hashlib.sha1`, `struct` |
| 1-C-B: Store the TOTP with a one-minute expiration in a JSON file | `store_totp()` | Cell 2; saves `totp_code` and `totp_expiry = time.time() + 60` |
| 1-C-C: Simulate authenticator app by printing TOTP to console | `login_user()` | Cell 2; `print(f'[Authenticator App] Your TOTP code is: {totp_code}')` |
| 1-C-D: Require users to enter the TOTP to complete login | `verify_totp()`, `main()` | Cell 2 (`verify_totp`), Cell 3 (`main` prompts user and calls `verify_totp`) |

---

### Task 1-D: JSON-Based User Data Storage

| Requirement | Function | Lines |
|---|---|---|
| 1-D-A: Store user credentials in a JSON file securely | `load_user_data()`, `save_user_data()` | Cell 2 |
| 1-D-B: Securely erase memory used for plaintext passwords after verification | `secure_erase()` | Cell 2; called in both `register_user()` and `login_user()` after password is no longer needed |
| 1-D-C: Track hashed passwords, failed attempts, OTPs, lockout time, and reset tokens | `register_user()` | Cell 2; user record contains all six fields: `hashed_password`, `failed_attempts`, `lockout_until`, `totp_code`, `totp_expiry`, `reset_token` |
| 1-D-D: Ensure the database persists between program runs | `save_user_data()`, `load_user_data()` | Cell 2; writes to `users.json` on every update; reads it on every access |

---

### Task 1-E: Main Function

| Requirement | Function | Lines |
|---|---|---|
| 1-E-A: Present a menu with Register / Login / View User Data / Exit | `main()` | Cell 3; `while True` loop with printed menu options |
| 1-E-B: Register prompts for username and password, calls `register_user()` | `main()` | Cell 3; `choice == '1'` branch |
| 1-E-C: Login prompts for credentials, calls `login_user()` | `main()` | Cell 3; `choice == '2'` branch |
| 1-E-D: Generate/display TOTP, prompt user, validate with `verify_totp()` | `main()` | Cell 3; after `login_user()` returns True, prompts for TOTP and calls `verify_totp()` |
| 1-E-E: Handle invalid attempts, enforce lockouts, provide clear feedback and error handling | `record_failed_attempt()`, `is_account_locked()`, `verify_password()` | Cell 2 (logic); Cell 3 (feedback messages via `print('[!] ...')` throughout) |
| 1-E-F: View User Data calls `load_user_data()` and prints its output | `main()` | Cell 3; `choice == '3'` branch |
| 1-E-G: Menu loops until Exit is chosen | `main()` | Cell 3; `while True` loop; `break` on `choice == '4'` |
