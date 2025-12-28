# Guide 03: Implement User Registration and Login

**Phase 1: Foundation** | **Week 1-2** | **Task 3 of 5**

## Overview

Build basic user authentication using Spring Security. Create user registration endpoints, login functionality, and understand how Spring Security handles authentication under the hood.

---

## What You'll Build

- User entity (JPA model)
- User repository (database access)
- User service (business logic)
- Registration endpoint
- Login endpoint
- Spring Security configuration for form-based authentication

---

## Why Start with Basic Auth?

Before implementing OAuth 2.0, you need a working user authentication system. OAuth builds on top of user authentication - users must log in before they can authorize client applications to access their resources.

---

## Step 1: Create the User Entity

### Create User.java

Location: `src/main/java/com/learning/idp/model/User.java`

### What to Include

Your User entity needs:
- **Primary Key**: Auto-generated ID
  - *Why*: Unique identifier for each user in the database
- **Username**: Unique username (email or custom)
  - *Why*: User's login identifier
- **Password**: Hashed password (never store plain text!)
  - *Why*: Authentication credential
- **Email**: User's email address
  - *Why*: Contact information and can be used as username
- **Enabled**: Boolean flag for account activation
  - *Why*: Allows disabling accounts without deletion
- **Timestamps**: Created date, updated date
  - *Why*: Audit trail and debugging

### JPA Annotations to Use

- **@Entity**: Marks class as a database table
- **@Table**: Specifies table name (e.g., `users`)
- **@Id**: Marks the primary key field
- **@GeneratedValue**: Auto-increments the ID
- **@Column**: Configures column properties (unique, nullable, length)
- **@CreationTimestamp**: Auto-sets creation time (Hibernate feature)
- **@UpdateTimestamp**: Auto-updates modification time

### Lombok Annotations (Reduces Boilerplate)

- **@Data**: Generates getters, setters, toString, equals, hashCode
- **@NoArgsConstructor**: Generates no-argument constructor (required by JPA)
- **@AllArgsConstructor**: Generates constructor with all fields

### Best Practices

- Never expose password in JSON responses (use `@JsonIgnore`)
- Use `@Column(unique = true)` for username/email
- Use `@Column(nullable = false)` for required fields
- Consider adding fields like `accountNonExpired`, `accountNonLocked`, `credentialsNonExpired` for advanced security

---

## Step 2: Create the User Repository

### Create UserRepository.java

Location: `src/main/java/com/learning/idp/repository/UserRepository.java`

### What This Does

Spring Data JPA repositories provide database operations without writing SQL. This is similar to TypeORM repositories in TypeScript.

### Create an Interface

- **Extend**: `JpaRepository<User, Long>`
  - Generic types: `<EntityType, IDType>`
  - *Why*: Provides built-in methods like `save()`, `findById()`, `findAll()`, `delete()`

### Custom Query Methods

Add methods for:
- **findByUsername(String username)**: Find user by username
  - *Why*: Spring Security needs this for authentication
- **findByEmail(String email)**: Find user by email
  - *Why*: Useful for registration validation and password reset
- **existsByUsername(String username)**: Check if username exists
  - *Why*: Validate uniqueness during registration

### Spring Data Magic

Spring Data JPA auto-implements these methods by parsing method names:
- `findBy` + `Username` → SELECT * FROM users WHERE username = ?
- `existsBy` + `Email` → SELECT COUNT(*) > 0 FROM users WHERE email = ?

No need to write SQL! Spring Data generates queries from method names.

**Learn More**: https://docs.spring.io/spring-data/jpa/docs/current/reference/html/#jpa.query-methods

---

## Step 3: Create Data Transfer Objects (DTOs)

### Why DTOs?

Never expose entity classes directly in REST APIs:
- **Security**: Prevents accidentally exposing sensitive fields (like password)
- **Flexibility**: API structure can differ from database structure
- **Validation**: Apply validation rules to inputs

### Create RegistrationRequest DTO

Location: `src/main/java/com/learning/idp/dto/RegistrationRequest.java`

#### Fields Needed:
- `username` (String)
- `password` (String)
- `email` (String)

#### Validation Annotations:
- **@NotBlank**: Field cannot be null or empty
  - Use on: username, password, email
- **@Email**: Validates email format
  - Use on: email
- **@Size**: Limits string length
  - Use on: username (min=3, max=50), password (min=8, max=100)

*Why validation?*: Input validation prevents invalid data from reaching your database and improves security (prevents SQL injection, data corruption).

### Create UserResponse DTO

Location: `src/main/java/com/learning/idp/dto/UserResponse.java`

#### Fields Needed:
- `id` (Long)
- `username` (String)
- `email` (String)
- `createdAt` (LocalDateTime)

**Note**: Never include password in response DTOs!

---

## Step 4: Create the User Service

### Create UserService.java

Location: `src/main/java/com/learning/idp/service/UserService.java`

### Responsibilities

The service layer contains business logic:
- Validate registration data
- Check if username/email already exists
- Hash passwords before saving
- Transform entities to DTOs

### Key Methods to Implement

#### registerUser(RegistrationRequest request)
1. Check if username already exists → throw exception if exists
2. Check if email already exists → throw exception if exists
3. Create new User entity
4. Hash the password (use PasswordEncoder - covered in Guide 05)
5. Save user to database
6. Return UserResponse DTO

*Why hash passwords?*: Never store plain text passwords. Hashing is one-way encryption - you can verify passwords but not decrypt them.

#### loadUserByUsername(String username)
This method is required by Spring Security's `UserDetailsService` interface:
1. Find user by username
2. Throw `UsernameNotFoundException` if not found
3. Return a `UserDetails` object

*Why?*: Spring Security calls this method during authentication to load user details and verify credentials.

### Annotations to Use

- **@Service**: Marks class as a Spring service (business logic layer)
- **@RequiredArgsConstructor** (Lombok): Generates constructor for `final` fields (dependency injection)
- **@Transactional**: Makes methods atomic (if one part fails, rollback everything)

### Dependencies to Inject

- `UserRepository`: Database access
- `PasswordEncoder`: Hash passwords (configured in next guide)

---

## Step 5: Create the Registration Controller

### Create AuthController.java

Location: `src/main/java/com/learning/idp/controller/AuthController.java`

### Purpose

Handles HTTP requests for authentication operations.

### Endpoint to Create

#### POST /api/auth/register

**Request Body**: `RegistrationRequest` (JSON)
**Response**: `UserResponse` (JSON)
**HTTP Status**: 201 Created

#### Implementation Steps:
1. Validate request body (Spring does this automatically with `@Valid`)
2. Call `userService.registerUser(request)`
3. Return response with HTTP 201 status

### Annotations to Use

- **@RestController**: Combines `@Controller` + `@ResponseBody` (returns JSON, not HTML)
- **@RequestMapping("/api/auth")**: Base path for all endpoints in this controller
- **@PostMapping("/register")**: Maps POST requests to this method
- **@RequestBody**: Deserializes JSON to Java object
- **@Valid**: Triggers validation on the request object

### Error Handling

Create a custom exception for registration errors:
- **UsernameAlreadyExistsException**: Thrown when username is taken
- **EmailAlreadyExistsException**: Thrown when email is taken

Spring Boot automatically converts uncaught exceptions to HTTP 500. You'll want to create an `@ExceptionHandler` to return proper error responses (HTTP 400 with error message).

---

## Step 6: Configure Spring Security

### Create SecurityConfig.java

Location: `src/main/java/com/learning/idp/config/SecurityConfig.java`

### Purpose

Configure how Spring Security handles authentication and authorization.

### Configuration Needed

#### Security Filter Chain

Define which endpoints require authentication:
- **Public endpoints**: `/api/auth/register`, `/api/auth/login`
  - *Why*: Users need to access these without being logged in
- **Authenticated endpoints**: Everything else
  - *Why*: Protect sensitive resources

#### Form Login Configuration

Enable form-based authentication:
- **Login endpoint**: `/api/auth/login` (can customize)
- **Username parameter**: `username`
- **Password parameter**: `password`
- **Success response**: Return user details as JSON
- **Failure response**: Return error message

#### CSRF Configuration

For development, you might disable CSRF (Cross-Site Request Forgery protection):
- *Why disable?*: Simplifies testing with tools like Postman
- **Important**: Enable in production!

#### CORS Configuration

If your frontend runs on a different port, configure Cross-Origin Resource Sharing:
- Allow specific origins (e.g., `http://localhost:3000`)
- Allow credentials (cookies, authorization headers)

### Annotations to Use

- **@Configuration**: Marks class as configuration
- **@EnableWebSecurity**: Enables Spring Security
- **@Bean**: Defines Spring-managed beans

### Beans to Define

#### SecurityFilterChain
Configures HTTP security rules

#### PasswordEncoder
Returns a `BCryptPasswordEncoder` instance for hashing passwords

---

## Step 7: Test User Registration

### Using Postman or cURL

#### Test Registration Endpoint

**Request**:
```
POST http://localhost:8080/api/auth/register
Content-Type: application/json

{
  "username": "testuser",
  "password": "password123",
  "email": "test@example.com"
}
```

**Expected Response** (201 Created):
```json
{
  "id": 1,
  "username": "testuser",
  "email": "test@example.com",
  "createdAt": "2024-01-15T10:30:00"
}
```

#### Test Validation

**Try registering with invalid data**:
- Empty username → Should return 400 Bad Request
- Invalid email format → Should return 400 Bad Request
- Short password (< 8 chars) → Should return 400 Bad Request

#### Test Duplicate Registration

**Register the same username twice** → Should return 409 Conflict or 400 Bad Request with error message

---

## Step 8: Verify Database Storage

### Check PostgreSQL

```bash
docker compose exec postgres psql -U oauth_user -d oauth_idp
```

```sql
SELECT * FROM users;
```

You should see:
- Your registered user
- Hashed password (not plain text!)
- Timestamps

**Important**: If the password is stored as plain text, something is wrong with your password encoding configuration!

---

## Step 9: Test User Login

### Login Endpoint Behavior

Spring Security's default form login:
- **Endpoint**: `/login` (POST)
- **Parameters**: `username` and `password` (form data, not JSON)
- **Success**: Redirects to `/` or returns success
- **Failure**: Redirects to `/login?error` or returns 401

### Customize Login for JSON

To accept JSON login requests, you'll need to customize the authentication filter:

#### Create Custom Authentication Filter
- Extend `UsernamePasswordAuthenticationFilter`
- Override `attemptAuthentication()` to parse JSON
- Configure in `SecurityFilterChain`

*Why customize?*: Default Spring Security expects form data, but modern APIs use JSON.

### Test Login

**Request** (if using JSON):
```
POST http://localhost:8080/api/auth/login
Content-Type: application/json

{
  "username": "testuser",
  "password": "password123"
}
```

**Expected Response**:
- **Success**: 200 OK with user details or session cookie
- **Failure**: 401 Unauthorized with error message

---

## Step 10: Understand Authentication Flow

### What Happens During Login?

1. **User submits credentials** → HTTP POST to /login
2. **Authentication Filter** → Intercepts request
3. **Authentication Manager** → Coordinates authentication
4. **UserDetailsService** → Loads user from database (your `loadUserByUsername` method)
5. **Password Encoder** → Compares submitted password with stored hash
6. **Success** → Creates `Authentication` object, stores in `SecurityContext`
7. **Session Created** → Spring Security creates session (stored in Redis)

### Spring Security Components

- **SecurityContext**: Holds currently authenticated user
- **SecurityContextHolder**: Thread-local storage for SecurityContext
- **Authentication**: Represents authenticated user and authorities
- **UserDetails**: Interface representing user data
- **UserDetailsService**: Loads user data during authentication

**Learn More**: https://docs.spring.io/spring-security/reference/servlet/authentication/architecture.html

---

## Common Issues

### "There is no PasswordEncoder mapped for the id null"

**Cause**: No PasswordEncoder bean configured

**Solution**: Create `PasswordEncoder` bean in SecurityConfig returning `BCryptPasswordEncoder`

### User not found during login

**Cause**: `UserDetailsService` not properly configured

**Solution**:
- Ensure UserService implements `UserDetailsService`
- Configure it in SecurityConfig using `authenticationProvider`

### Validation errors not returned properly

**Cause**: No exception handler for `MethodArgumentNotValidException`

**Solution**: Create `@RestControllerAdvice` class with `@ExceptionHandler` methods

### Database constraint violation on username/email

**Cause**: Not checking for existing users before saving

**Solution**: Add existence checks in UserService before creating user

---

## What You've Accomplished

✅ Created User entity with JPA mappings
✅ Implemented User repository with Spring Data JPA
✅ Created DTOs for request/response separation
✅ Built UserService with registration logic
✅ Created registration endpoint
✅ Configured basic Spring Security
✅ Tested user registration and storage

---

## Next Steps

**Proceed to Guide 04**: Create User Database Schema (with Flyway migrations)

Before moving on, ensure:
- [ ] User registration works via API
- [ ] Passwords are hashed in database
- [ ] Validation errors return properly
- [ ] Duplicate usernames/emails are rejected
- [ ] User login works (even if basic)

---

## Key Concepts Learned

### JPA Entity Lifecycle
- **Transient**: New object, not associated with database
- **Managed**: Tracked by EntityManager, changes auto-saved
- **Detached**: Was managed, but no longer tracked
- **Removed**: Marked for deletion

### Spring Security Authentication
- Authentication happens before authorization
- UserDetailsService loads user data
- PasswordEncoder verifies credentials
- SecurityContext stores authenticated user

### DTO Pattern
- Entities represent database structure
- DTOs represent API contracts
- Separation prevents tight coupling
- Allows independent evolution of database and API

---

## Additional Resources

- **Spring Data JPA**: https://docs.spring.io/spring-data/jpa/docs/current/reference/html/
- **Spring Security Architecture**: https://spring.io/guides/topicals/spring-security-architecture
- **Bean Validation (JSR 380)**: https://beanvalidation.org/2.0/spec/
- **BCrypt Explained**: https://www.baeldung.com/spring-security-registration-password-encoding-bcrypt
- **UserDetailsService**: https://docs.spring.io/spring-security/reference/servlet/authentication/passwords/user-details-service.html
