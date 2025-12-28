# Guide 05: Password Hashing and Validation

**Phase 1: Foundation** | **Week 1-2** | **Task 5 of 5**

## Overview

Implement secure password handling using BCrypt hashing, understand why password security matters, and set up password validation rules to protect user accounts.

---

## What You'll Build

- Password hashing with BCrypt
- Password strength validation
- Secure password comparison
- Password encoder configuration in Spring Security
- Password policy enforcement

---

## Why Password Security Matters

### The Danger of Plain Text Passwords

**Never store passwords in plain text** because:
- **Data breaches happen**: Even large companies get hacked
- **Password reuse**: Users often reuse passwords across sites
- **Legal requirements**: GDPR, CCPA, and other regulations require proper data protection
- **Trust**: Users trust you with their credentials

### Real-World Impact

When a database is compromised:
- **Plain text**: Attacker has all passwords immediately
- **Simple hashing (MD5, SHA1)**: Attacker can crack millions of passwords per second
- **BCrypt**: Attacker can only test thousands per second (60,000x slower)

**Learn More**: https://auth0.com/blog/hashing-passwords-one-way-road-to-security/

---

## Step 1: Understand Hashing vs Encryption

### Encryption (Two-Way)

**Process**: Plaintext → Encrypted → Decrypted back to plaintext

**Use cases**: Credit card numbers, SSN, sensitive data you need to retrieve

**Not for passwords**: If you can decrypt, so can an attacker who gets your key

### Hashing (One-Way)

**Process**: Plaintext → Hash (irreversible)

**How it works**:
1. User registers: password → hash → store hash
2. User logs in: submitted password → hash → compare with stored hash
3. Match = authenticated, no match = reject

**Key property**: Given a hash, you cannot determine the original password

---

## Step 2: Understanding BCrypt

### What is BCrypt?

BCrypt is a **password hashing function** designed specifically for passwords:
- **Adaptive**: Increases work factor as computers get faster
- **Salted**: Each hash includes a random salt (prevents rainbow table attacks)
- **Slow by design**: Takes time to compute (prevents brute force)

### BCrypt Hash Anatomy

Example BCrypt hash:
```
$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy
```

Breaking it down:
- **$2a$**: BCrypt algorithm version
- **10**: Cost factor (2^10 = 1024 rounds)
- **N9qo8uLOickgx2ZMRZoMye**: Salt (22 characters)
- **IjZAgcfl7p92ldGxad68LJZdL17lhWy**: Actual hash

### Cost Factor

The cost factor determines how many iterations:
- **10**: ~100ms to hash (recommended for most apps)
- **12**: ~400ms to hash (higher security, slower)
- **14**: ~1.6s to hash (very secure, may impact UX)

*Why it matters*: Higher cost = slower hashing = harder to brute force, but also slower user experience

**TypeScript analogy**: Similar to `bcrypt.hash(password, saltRounds)` in Node.js

---

## Step 3: Configure BCrypt in Spring Security

### Create PasswordEncoder Bean

Location: `src/main/java/com/learning/idp/config/SecurityConfig.java`

### Implementation

In your existing `SecurityConfig` class, add a method that returns a `PasswordEncoder` bean.

### Annotation Needed

- **@Bean**: Tells Spring to manage this object and inject it where needed

### What to Return

Return a new instance of `BCryptPasswordEncoder`

### Optional: Custom Strength

You can specify the cost factor:
```java
new BCryptPasswordEncoder(12)  // More secure, slower
```

Default is 10 (recommended for most applications).

### Why This Works

Spring Security automatically uses this `PasswordEncoder` bean:
- When creating users (hashing passwords)
- When authenticating (comparing passwords)
- In `UserDetailsService` implementations

---

## Step 4: Update UserService to Hash Passwords

### Inject PasswordEncoder

In `UserService`, inject the `PasswordEncoder`:

```java
private final PasswordEncoder passwordEncoder;
```

Use `@RequiredArgsConstructor` (Lombok) or constructor injection.

### Hash Password on Registration

In your `registerUser` method:

**Before saving**:
1. Get plain password from request
2. Hash it using `passwordEncoder.encode(plainPassword)`
3. Set hashed password on User entity
4. Save to database

### Example Flow

```
User submits: "password123"
↓
passwordEncoder.encode("password123")
↓
Returns: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
↓
Store in database
```

### Important

**Never** store the plain password anywhere:
- Don't log it
- Don't return it in responses
- Don't keep it in variables longer than necessary

---

## Step 5: Implement Password Validation

### Create PasswordValidator Utility

Location: `src/main/java/com/learning/idp/security/PasswordValidator.java`

### Password Requirements

Define minimum requirements:
- **Length**: At least 8 characters (12+ recommended)
  - *Why*: Longer = exponentially harder to crack
- **Complexity**: Mix of character types
  - At least one uppercase letter
  - At least one lowercase letter
  - At least one number
  - At least one special character (optional but recommended)

### Validation Method

Create a method: `validatePassword(String password)`

**Returns**: `ValidationResult` or throws exception with specific error

### Regex Pattern

Use regular expressions to check requirements:

**Pattern examples**:
- Length: `password.length() >= 8`
- Uppercase: `password.matches(".*[A-Z].*")`
- Lowercase: `password.matches(".*[a-z].*")`
- Digit: `password.matches(".*\\d.*")`
- Special char: `password.matches(".*[!@#$%^&*()].*")`

### Common Weak Passwords

Check against a list of common passwords:
- "password", "123456", "qwerty", etc.

You can maintain a blacklist or use a library like Passay.

**Learn More**: https://github.com/vhyza/awesome-password-strength

---

## Step 6: Add Custom Validation Annotation

### Create @ValidPassword Annotation

Location: `src/main/java/com/learning/idp/validation/ValidPassword.java`

### Purpose

A custom Bean Validation annotation to validate password strength.

### How to Create

1. **Define annotation interface** with `@interface`
2. **Add meta-annotations**:
   - `@Constraint(validatedBy = PasswordConstraintValidator.class)`
   - `@Target({ElementType.FIELD})`
   - `@Retention(RetentionPolicy.RUNTIME)`
3. **Define message** property for error message

### Create Validator Class

Location: `src/main/java/com/learning/idp/validation/PasswordConstraintValidator.java`

**Implement**: `ConstraintValidator<ValidPassword, String>`

**Override**: `isValid(String password, ConstraintValidatorContext context)`

**Logic**:
- Check length, complexity, common passwords
- Return `true` if valid, `false` otherwise
- Optionally, customize error message using context

### Use the Annotation

In `RegistrationRequest` DTO:

```java
@ValidPassword
private String password;
```

Now Spring automatically validates password strength on all registration requests.

---

## Step 7: Understand Password Comparison

### How Spring Security Compares Passwords

During login:
1. User submits username and password
2. `UserDetailsService` loads user from database (with hashed password)
3. `PasswordEncoder.matches(rawPassword, encodedPassword)` is called
4. BCrypt hashes the raw password with the **same salt** from stored hash
5. Compares the two hashes
6. If equal → authentication succeeds

### Why This Works

BCrypt hash **includes the salt**, so:
- Same password + same salt = same hash
- Different password + same salt = different hash

### Important: Timing Attacks

BCrypt comparison is **constant time** - takes same amount of time whether passwords match or not. This prevents attackers from using timing to guess passwords.

---

## Step 8: Implement Password Change Functionality

### Create Change Password Endpoint

**Endpoint**: `POST /api/auth/change-password`

**Requirements**:
1. User must be authenticated
2. Must provide current password (verify they know it)
3. Must provide new password (validated for strength)
4. Must confirm new password (must match)

### Request DTO

Create `ChangePasswordRequest`:
- `currentPassword` (String)
- `newPassword` (String, with @ValidPassword)
- `confirmNewPassword` (String)

### Service Method Implementation

**Steps**:
1. Get current user from SecurityContext
2. Verify current password matches stored hash
3. Validate new password strength
4. Check new password != current password (optional, but good practice)
5. Hash new password
6. Update user entity
7. Save to database

### Security Consideration

**Invalidate all sessions** after password change:
- Prevents session hijacking if old password was compromised
- Force user to re-login with new password

---

## Step 9: Implement Password Reset Flow

### High-Level Flow

1. **Request reset**: User enters email
2. **Generate token**: Create random, secure token
3. **Send email**: Email user with reset link (contains token)
4. **Verify token**: User clicks link, submits new password
5. **Reset password**: Validate token, update password

### Reset Token Requirements

- **Random**: Use `SecureRandom` or UUID
- **Expiring**: Valid for limited time (e.g., 1 hour)
- **One-time use**: Invalidate after use
- **Secure**: Store hash of token, not plain token

### Database Table

Create migration: `V7__create_password_reset_tokens_table.sql`

**Columns**:
- `id`: Primary key
- `token`: Hashed token
- `user_id`: Foreign key to users
- `expires_at`: Expiration timestamp
- `used`: Boolean flag

### Implementation Notes

**For this learning project**, you can skip actual email sending:
- Just log the reset token to console
- Or return it in response (dev mode only!)
- In production, use JavaMail or a service like SendGrid

**Learn More**: https://www.baeldung.com/spring-security-registration-password-encoding-bcrypt

---

## Step 10: Testing Password Security

### Test Cases to Verify

#### Registration with Weak Password
- **Test**: Register with "password"
- **Expected**: 400 Bad Request with validation error

#### Registration with Strong Password
- **Test**: Register with "MyP@ssw0rd123"
- **Expected**: 201 Created, password hashed in database

#### Login with Correct Password
- **Test**: Login with correct password
- **Expected**: 200 OK, authenticated

#### Login with Incorrect Password
- **Test**: Login with wrong password
- **Expected**: 401 Unauthorized

#### Change Password
- **Test**: Change password while authenticated
- **Expected**: Password updated, old password no longer works

### Verify in Database

```sql
SELECT username, password FROM users;
```

**Check**:
- All passwords start with `$2a$` or `$2b$` (BCrypt)
- All passwords are different (even if same input password - different salts)
- Passwords are ~60 characters long

---

## Understanding Security Trade-offs

### Hashing Strength vs Performance

**Stronger hashing**:
- ✅ Harder to crack
- ❌ Slower login/registration

**Weaker hashing**:
- ✅ Faster user experience
- ❌ Easier to crack if database is stolen

**Recommendation**: Use BCrypt cost factor 10-12 for web applications. Users won't notice ~100-400ms delay during login.

### Password Requirements vs Usability

**Strict requirements** (must have uppercase, numbers, special chars):
- ✅ Stronger passwords
- ❌ Users forget complex passwords
- ❌ Users write passwords down
- ❌ Users reuse variations ("Password1!", "Password2!")

**Better approach**:
- **Length over complexity**: Require 12+ characters
- **Check against common passwords**: Prevent "Password123!"
- **Allow passphrases**: "correct horse battery staple" is stronger than "P@ssw0rd1"

**Learn More**: https://www.ncsc.gov.uk/collection/passwords

---

## Common Security Mistakes

### ❌ DON'T: Use MD5 or SHA-1 for Passwords

These are cryptographic hashes, **not** password hashes:
- Too fast (millions of hashes per second)
- No built-in salt
- Vulnerable to rainbow tables

### ❌ DON'T: Create Your Own Hashing Algorithm

Cryptography is hard. Use established, peer-reviewed algorithms like BCrypt, Argon2, or scrypt.

### ❌ DON'T: Store Passwords Encrypted

If you can decrypt, so can an attacker who gets your encryption key.

### ❌ DON'T: Log Passwords

Never log passwords, even accidentally:
```java
log.info("User registered with password: " + password);  // NO!
```

### ✅ DO: Use Parameterized Queries

Always use JPA/Hibernate or parameterized SQL to prevent SQL injection:
```java
// Good - JPA
userRepository.findByUsername(username);

// Bad - String concatenation
query = "SELECT * FROM users WHERE username = '" + username + "'";  // SQL INJECTION!
```

---

## What You've Accomplished

✅ Configured BCrypt password hashing
✅ Implemented secure password storage
✅ Created password strength validation
✅ Built password change functionality
✅ Understood password comparison process
✅ Learned security best practices

**Phase 1 Complete!** 🎉

---

## Next Steps

**Proceed to Phase 2 - Guide 06**: Implement Authorization Endpoint

Before moving on, ensure:
- [ ] Passwords are hashed with BCrypt in database
- [ ] Login works with hashed passwords
- [ ] Weak passwords are rejected
- [ ] Password change functionality works
- [ ] No passwords are logged or exposed in API responses

---

## Key Concepts Learned

### Hashing vs Encryption
- Hashing is one-way (cannot reverse)
- Encryption is two-way (can decrypt)
- Passwords must be hashed, not encrypted

### Salt
- Random data added to password before hashing
- Prevents rainbow table attacks
- BCrypt includes salt in the hash automatically

### Work Factor
- Controls how many iterations of hashing
- Higher factor = slower but more secure
- Adjustable as hardware improves

### Defense in Depth
- Hash passwords (protect against DB theft)
- Validate password strength (protect against brute force)
- Use HTTPS (protect in transit)
- Rate limit login attempts (protect against online attacks)

---

## Additional Resources

- **BCrypt Explained**: https://auth0.com/blog/hashing-in-action-understanding-bcrypt/
- **Password Hashing Competition**: https://password-hashing.net/
- **OWASP Password Storage Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- **NIST Password Guidelines**: https://pages.nist.gov/800-63-3/sp800-63b.html
- **Spring Security Password Encoding**: https://docs.spring.io/spring-security/reference/features/authentication/password-storage.html
- **Passay (Password Validation Library)**: https://www.passay.org/
