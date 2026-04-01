"""
CSEC 472 - Assignment 3, Task 1
Secure Authentication System with Two-Factor Authentication
Windows-compatible version

Run in terminal: python auth_system.py
Install dependencies first: python -m pip install argon2-cffi
"""

import json         # For reading/writing the user data JSON file
import os           # For generating random secrets and file checks
import hmac         # For constant-time comparison (timing attack prevention)
import hashlib      # Used internally by TOTP computation
import time         # For lockout timestamps and TOTP time window
import struct       # For packing the time counter into bytes for HOTP
import ctypes       # For securely erasing plaintext passwords from memory
from argon2 import PasswordHasher    # Argon2 password hashing
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

"""
CONSTANTS
"""

DB_FILE          = 'users.json'   # Path to the persistent JSON user database
MAX_FAILURES     = 5              # Failed attempts before account lockout
LOCKOUT_SECONDS  = 15 * 60        # Lockout duration: 15 minutes
TOTP_EXPIRY      = 60             # TOTP validity window: 60 seconds
MIN_PW_LENGTH    = 16             # Minimum required password length
TOTP_DIGITS      = 6              # Number of digits in the generated OTP

"""
Argon2 password hasher
   - time_cost    : number of iterations (work factor)
   - memory_cost  : memory usage in kibibytes
   - parallelism  : degree of parallelism
 Argon2 automatically manages a unique random salt per hash.
"""
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)


"""
SECTION A: JSON-Based User Data Storage  (Task 1-D)
"""


def load_user_data() -> dict:
    """
    Load and return the full user database from the JSON file.
    If the file does not exist yet, return an empty dict.
    Task 1-D-A / Task 1-D-D: Persistent storage between runs.
    """
    if not os.path.exists(DB_FILE):
        return {}
    with open(DB_FILE, 'r') as f:
        return json.load(f)


def save_user_data(data: dict) -> None:
    """
    Persist the entire user database to the JSON file.
    Uses indent=2 for human-readable formatting.
    Task 1-D-D: ensure the database persists between program runs.
    """
    with open(DB_FILE, 'w') as f:
        json.dump(data, f, indent=2)


def secure_erase(s: str) -> None:
    """
    Attempt to overwrite the memory backing a Python string with null bytes.
    Python strings are immutable and interned, so full erasure is not
    guaranteed, but this is a best-effort mitigation.
    Task 1-D-B: securely erase memory used for plaintext passwords.
    """
    try:
        buf_len = len(s.encode('utf-8'))
        ctypes.memset(id(s), 0, buf_len)
    except Exception:
        pass  # Silently ignore if the platform prevents direct memory access


"""
SECTION B: Password Policy & Secure Storage  (Task 1-A)
"""

def check_password_strength(username: str, password: str) -> tuple:
    """
    Enforce the password policy:
      - Minimum 16 characters
      - Must not equal the username
    Returns (True, '') on success, (False, reason) on failure.
    Task 1-B-B: password strength check.
    """
    # Task 1-B-B-i: length check
    if len(password) < MIN_PW_LENGTH:
        return False, f'Password must be at least {MIN_PW_LENGTH} characters long.'
    # Task 1-B-B-ii: username equality check
    if password == username:
        return False, 'Password must not be the same as the username.'
    return True, ''


def hash_password(password: str) -> str:
    """
    Hash the plaintext password using Argon2id.
    Argon2 embeds a unique random salt and work-factor parameters
    inside the returned hash string — no separate salt storage needed.
    Task 1-A-A / Task 1-A-C: Argon2 hashing with salt and work factor.
    """
    return ph.hash(password)


def verify_password(stored_hash: str, candidate: str) -> bool:
    """
    Securely verify a candidate password against the stored Argon2 hash.
    argon2-cffi's verify() is already constant-time.
    Task 1-B-D: prevent timing attacks with constant-time comparison.
    Returns True if the password matches, False otherwise.
    """
    try:
        return ph.verify(stored_hash, candidate)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        # Return False for any mismatch or malformed hash — never raise
        return False


"""
SECTION C: TOTP Generation & Verification  (Task 1-C)
"""

def generate_totp(secret: bytes) -> str:
    """
    Generate a 6-digit TOTP using HMAC-SHA1 over the current 30-second
    time step, following RFC 6238 / HOTP (RFC 4226).

    Steps:
      1. Compute T = floor(current_unix_time / 30)  - the time counter
      2. Pack T as a big-endian 8-byte integer
      3. Compute HMAC-SHA1(secret, T_bytes)
      4. Dynamic truncation: extract a 4-byte slice from the HMAC digest
      5. Mask to 31 bits, then take modulo 10^6 for 6 digits

    Task 1-C-A: generate 6-digit TOTP based on HMAC(time, key).
    """
    # Step 1 & 2: time counter as big-endian 8 bytes
    T = int(time.time()) // 30
    T_bytes = struct.pack('>Q', T)

    # Step 3: HMAC-SHA1
    mac = hmac.new(secret, T_bytes, hashlib.sha1).digest()

    # Step 4: dynamic truncation - use the low nibble of the last byte as offset
    offset = mac[-1] & 0x0F
    truncated = struct.unpack('>I', mac[offset:offset + 4])[0]

    # Step 5: mask to 31 bits and reduce to TOTP_DIGITS digits
    code = (truncated & 0x7FFFFFFF) % (10 ** TOTP_DIGITS)
    return str(code).zfill(TOTP_DIGITS)


def store_totp(username: str, totp_code: str) -> None:
    """
    Save the generated TOTP and its expiry timestamp into the user record.
    Task 1-C-B: store TOTP with a one-minute expiration in the JSON file.
    """
    data = load_user_data()
    if username in data:
        data[username]['totp_code']   = totp_code
        data[username]['totp_expiry'] = time.time() + TOTP_EXPIRY
        save_user_data(data)


def verify_totp(username: str, entered_code: str) -> bool:
    """
    Verify that the user-supplied TOTP:
      - Matches the stored code (constant-time comparison)
      - Has not expired (within the one-minute window)
    Clears the stored TOTP after a successful verification to prevent reuse.
    Task 1-C-D / Task 1-D-C: validate TOTP and track expiry.
    """
    data = load_user_data()
    user = data.get(username, {})

    stored_code = user.get('totp_code', '')
    totp_expiry = user.get('totp_expiry', 0)

    # Check expiry first
    if time.time() > totp_expiry:
        print('  [!] TOTP has expired. Please log in again.')
        return False

    # Constant-time comparison to prevent timing attacks
    if not hmac.compare_digest(stored_code, entered_code.strip()):
        print('  [!] Incorrect TOTP.')
        return False

    # Invalidate the used TOTP so it cannot be replayed
    data[username]['totp_code']   = ''
    data[username]['totp_expiry'] = 0
    save_user_data(data)
    return True


"""
SECTION D: User Registration  (Task 1-A, Task 1-D)
"""

def register_user(username: str, password: str) -> bool:
    """
    Register a new user:
      1. Reject duplicate usernames
      2. Enforce password policy
      3. Hash the password with Argon2 (salt + work factor embedded)
      4. Store only the hash in the JSON database
      5. Securely erase the plaintext password from memory

    User record schema (Task 1-D-C):
      hashed_password   : Argon2 hash string
      failed_attempts   : consecutive failed login count
      lockout_until     : unix timestamp of lockout expiry (0 = not locked)
      totp_code         : current pending TOTP ('' = none)
      totp_expiry       : unix timestamp when TOTP expires
      reset_token       : placeholder for future password-reset flow

    Task 1-A-A/B/C: Argon2 hashing with salt, store only hash.
    Task 1-D-A/B/C: JSON storage, memory erasure, field tracking.
    """
    data = load_user_data()

    # Reject duplicate usernames
    if username in data:
        print(f'  [!] Username "{username}" is already taken.')
        return False

    # Enforce password policy (Task 1-B-B)
    ok, reason = check_password_strength(username, password)
    if not ok:
        print(f'  [!] Weak password: {reason}')
        secure_erase(password)
        return False

    # Hash using Argon2 - salt is generated internally and embedded in the hash
    hashed = hash_password(password)

    # Build the user record with all required tracking fields
    data[username] = {
        'hashed_password': hashed,  # Task 1-A-B: only the hash is stored
        'failed_attempts': 0,
        'lockout_until':   0,
        'totp_code':       '',
        'totp_expiry':     0,
        'reset_token':     ''
    }
    save_user_data(data)

    # Best-effort memory erasure of the plaintext password (Task 1-D-B)
    secure_erase(password)

    print(f'  [+] User "{username}" registered successfully.')
    return True


"""
SECTION E: Login & Brute-Force Protection  (Task 1-B)
"""

def is_account_locked(user_record: dict) -> bool:
    """
    Return True if the account is currently locked out.
    Task 1-B-C: lock accounts for 15 minutes after 5 failed attempts.
    """
    lockout_until = user_record.get('lockout_until', 0)
    return time.time() < lockout_until


def record_failed_attempt(username: str, data: dict) -> None:
    """
    Increment the failed-attempt counter for a user.
    If MAX_FAILURES is reached, set the lockout timestamp.
    Task 1-B-C: brute-force lockout after 5 failures.
    """
    data[username]['failed_attempts'] += 1
    if data[username]['failed_attempts'] >= MAX_FAILURES:
        data[username]['lockout_until'] = time.time() + LOCKOUT_SECONDS
        print(f'  [!] Account locked for {LOCKOUT_SECONDS // 60} minutes '
              f'due to too many failed attempts.')
    save_user_data(data)


def reset_failed_attempts(username: str, data: dict) -> None:
    """
    Clear the failed-attempt counter after a successful password verification.
    """
    data[username]['failed_attempts'] = 0
    data[username]['lockout_until']   = 0
    save_user_data(data)


def login_user(username: str, password: str) -> bool:
    """
    Authenticate a user with their username and password:
      1. Look up the user record - use a dummy hash for non-existent users
         to avoid username-enumeration timing leaks
      2. Verify the account is not locked out
      3. Verify the password (constant-time via argon2-cffi)
      4. On failure: increment failed-attempt counter
      5. On success: reset counter, generate and store TOTP

    Returns True if the password stage passed (TOTP still required).
    Task 1-B-A/C/D: login, lockout, timing-attack prevention.
    """
    data = load_user_data()

    # Retrieve record - or fabricate a dummy to run verify in constant time
    user_exists = username in data
    user_record = data.get(username, {'hashed_password': ph.hash('dummy_value_xXx!')})

    # Lockout check (only meaningful for real accounts)
    if user_exists and is_account_locked(user_record):
        remaining = int(user_record['lockout_until'] - time.time())
        print(f'  [!] Account is locked. Try again in {remaining // 60}m {remaining % 60}s.')
        secure_erase(password)
        return False

    # Constant-time password verification (Task 1-B-D)
    password_ok = verify_password(user_record['hashed_password'], password)

    # Securely erase the plaintext password now that it's no longer needed (Task 1-D-B)
    secure_erase(password)

    if not password_ok or not user_exists:
        if user_exists:
            record_failed_attempt(username, data)
        print('  [!] Invalid username or password.')
        return False

    # Password verified - reset lockout counters
    reset_failed_attempts(username, data)

    # Generate TOTP and simulate authenticator app by printing to console (Task 1-C-C)
    secret = username.encode('utf-8')   # Deterministic secret derived from username
    totp_code = generate_totp(secret)   # RFC-6238 TOTP
    store_totp(username, totp_code)     # Persist with expiry (Task 1-C-B)

    print(f'\n  [Authenticator App] Your TOTP code is: {totp_code}')
    print(f'  (Valid for {TOTP_EXPIRY} seconds)')
    return True


"""
SECTION F: Interactive Menu / Main Loop  (Task 1-E)
"""

def main():
    """
    Entry point for the authentication system.
    Presents a looping menu with four options:
      1. Register  - create a new account
      2. Login     - authenticate and complete 2FA
      3. View User Data - print the raw JSON database (admin view)
      4. Exit      - terminate the program
    Task 1-E-A through Task 1-E-G.
    """
    print('=' * 50)
    print('   Secure Authentication System with 2FA')
    print('=' * 50)

    while True:  # Task 1-E-G: loop until user selects Exit
        print('\nMenu:')
        print('  1) Register')
        print('  2) Login')
        print('  3) View User Data')
        print('  4) Exit')

        choice = input('\nSelect an option [1-4]: ').strip()

        # -------------------------------------------------------
        # Option 1: Register  (Task 1-E-B)
        # -------------------------------------------------------
        if choice == '1':
            print('\n--- Register ---')
            username = input('  Username: ').strip()
            password = input('  Password: ')   # No .strip() - preserve intentional spaces

            if not username or not password:
                print('  [!] Username and password cannot be empty.')
                continue

            register_user(username, password)

        # -------------------------------------------------------
        # Option 2: Login + 2FA  (Task 1-E-C / Task 1-E-D)
        # -------------------------------------------------------
        elif choice == '2':
            print('\n--- Login ---')
            username = input('  Username: ').strip()
            password = input('  Password: ')

            if not username or not password:
                print('  [!] Username and password cannot be empty.')
                continue

            # Stage 1: password verification
            if not login_user(username, password):
                continue

            # Stage 2: TOTP verification  (Task 1-E-D)
            totp_input = input('  Enter the 6-digit TOTP code: ').strip()

            if verify_totp(username, totp_input):
                print(f'\n  [+] Welcome, {username}! You are now logged in.')
            else:
                # TOTP failed - treat as a failed login attempt
                data = load_user_data()
                if username in data:
                    record_failed_attempt(username, data)
                print('  [!] Login failed: invalid or expired TOTP.')

        # -------------------------------------------------------
        # Option 3: View User Data  (Task 1-E-F)
        # -------------------------------------------------------
        elif choice == '3':
            print('\n--- User Data (Admin View) ---')
            user_data = load_user_data()
            if not user_data:
                print('  (No users registered yet.)')
            else:
                print(json.dumps(user_data, indent=2))

        # -------------------------------------------------------
        # Option 4: Exit  (Task 1-E-G)
        # -------------------------------------------------------
        elif choice == '4':
            print('\nGoodbye!')
            break

        # -------------------------------------------------------
        # Invalid menu option
        # -------------------------------------------------------
        else:
            print('  [!] Invalid option. Please enter 1, 2, 3, or 4.')


# Windows-safe entry point guard
if __name__ == '__main__':
    main()
