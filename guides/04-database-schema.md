# Guide 04: Create User Database Schema

**Phase 1: Foundation** | **Week 1-2** | **Task 4 of 5**

## Overview

Design and implement a proper database schema for the OAuth 2.0 Identity Provider using database migrations with Flyway. Learn why migrations are critical and how to manage schema changes over time.

---

## What You'll Build

- Database migration scripts using Flyway
- Users table with proper constraints
- Clients table for OAuth applications
- Indexes for query optimization
- Schema version control

---

## Why Database Migrations?

### The Problem with Auto-DDL

In Guide 03, you might have used Hibernate's `ddl-auto: update` setting. This is convenient but dangerous:
- **No version control**: Can't track what changed and when
- **Unpredictable**: Hibernate might drop columns or data
- **Not production-safe**: Never use auto-DDL in production
- **No rollback**: Can't undo schema changes

### The Solution: Migration Tools

Migration tools like Flyway or Liquibase:
- **Version control** for database schema (like Git for code)
- **Reproducible**: Same migrations = same schema on all environments
- **Reversible**: Can rollback changes
- **Auditable**: Know exactly what changed and when
- **Safe**: Review changes before applying

---

## Step 1: Add Flyway Dependency

### Update pom.xml

Add Flyway dependency in the `<dependencies>` section:

**Find at**: https://mvnrepository.com/ → Search "flyway-core"

**Why Flyway over Liquibase?**:
- Simpler to learn (plain SQL scripts)
- Widely used in Spring Boot projects
- Good Spring Boot integration
- Version-based migration naming is intuitive

---

## Step 2: Configure Flyway

### Update application.yml

Add Flyway configuration:

```yaml
spring:
  flyway:
    enabled: true
    baseline-on-migrate: true
    locations: classpath:db/migration
```

### Configuration Explained

- **enabled**: Turns on Flyway
- **baseline-on-migrate**: Allows Flyway to work with existing databases
  - *Why*: If you already have tables from Hibernate auto-DDL, this prevents conflicts
- **locations**: Where Flyway looks for migration scripts
  - Default: `src/main/resources/db/migration`

### Disable Hibernate Auto-DDL

**Important**: Change `ddl-auto` setting:

```yaml
spring:
  jpa:
    hibernate:
      ddl-auto: validate  # Changed from 'update'
```

**Why validate?**:
- Hibernate checks if entities match database schema
- Throws error if mismatch (prevents accidental schema drift)
- Forces you to use migrations for all schema changes

---

## Step 3: Understand Migration Naming Convention

### Flyway Naming Format

**Pattern**: `V{version}__{description}.sql`

**Examples**:
- `V1__create_users_table.sql`
- `V2__create_clients_table.sql`
- `V3__add_email_index.sql`

### Rules

- **Prefix**: Must start with `V` (uppercase)
- **Version**: Integer version number (1, 2, 3, etc.)
- **Separator**: Double underscore `__`
- **Description**: Human-readable description (underscores for spaces)
- **Extension**: `.sql`

### Why This Matters

Flyway executes migrations **in version order** and tracks which ones have run in a `flyway_schema_history` table. Once a migration runs, it never runs again.

**Learn More**: https://flywaydb.org/documentation/concepts/migrations#naming

---

## Step 4: Create Migration Directory

### Create Folder Structure

```
src/main/resources/
└── db/
    └── migration/
        ├── V1__create_users_table.sql
        ├── V2__create_clients_table.sql
        └── V3__create_authorization_codes_table.sql
```

Create the directories:
- `src/main/resources/db/`
- `src/main/resources/db/migration/`

---

## Step 5: Design the Users Table

### Create V1__create_users_table.sql

### Required Columns

| Column | Type | Constraints | Purpose |
|--------|------|-------------|---------|
| `id` | BIGSERIAL | PRIMARY KEY | Unique identifier |
| `username` | VARCHAR(50) | NOT NULL, UNIQUE | Login identifier |
| `password` | VARCHAR(100) | NOT NULL | BCrypt hash (60 chars, but allow buffer) |
| `email` | VARCHAR(255) | NOT NULL, UNIQUE | Email address |
| `enabled` | BOOLEAN | NOT NULL, DEFAULT TRUE | Account status |
| `account_non_expired` | BOOLEAN | NOT NULL, DEFAULT TRUE | Account expiration |
| `account_non_locked` | BOOLEAN | NOT NULL, DEFAULT TRUE | Account lock status |
| `credentials_non_expired` | BOOLEAN | NOT NULL, DEFAULT TRUE | Password expiration |
| `created_at` | TIMESTAMP | NOT NULL, DEFAULT CURRENT_TIMESTAMP | Creation time |
| `updated_at` | TIMESTAMP | NOT NULL, DEFAULT CURRENT_TIMESTAMP | Last update time |

### Indexes to Create

- **Primary key index**: Automatically created on `id`
- **Unique index on username**: Automatically created by UNIQUE constraint
- **Index on email**: For fast lookups during login and password reset

### SQL Script Structure

1. **CREATE TABLE** statement
2. **CREATE INDEX** statements (if needed beyond constraints)
3. **COMMENT ON** statements (optional, documents columns)

### Why These Columns?

- **BIGSERIAL**: Auto-incrementing 64-bit integer (supports billions of users)
- **VARCHAR lengths**: Based on expected data (usernames shorter than emails)
- **BOOLEAN flags**: Spring Security's UserDetails interface requires these
- **Timestamps**: Audit trail (who registered when, last updated)

---

## Step 6: Design the Clients Table

### Create V2__create_clients_table.sql

### Required Columns

| Column | Type | Constraints | Purpose |
|--------|------|-------------|---------|
| `id` | BIGSERIAL | PRIMARY KEY | Unique identifier |
| `client_id` | VARCHAR(100) | NOT NULL, UNIQUE | OAuth client identifier |
| `client_secret` | VARCHAR(255) | | Hashed secret (nullable for public clients) |
| `client_name` | VARCHAR(255) | NOT NULL | Display name |
| `redirect_uris` | TEXT | NOT NULL | Comma-separated redirect URIs |
| `grant_types` | VARCHAR(255) | NOT NULL | Comma-separated grant types |
| `scopes` | VARCHAR(255) | NOT NULL | Comma-separated allowed scopes |
| `is_public` | BOOLEAN | NOT NULL, DEFAULT FALSE | Public vs confidential client |
| `created_at` | TIMESTAMP | NOT NULL, DEFAULT CURRENT_TIMESTAMP | Creation time |
| `updated_at` | TIMESTAMP | NOT NULL, DEFAULT CURRENT_TIMESTAMP | Last update time |

### Why This Structure?

- **client_id**: Similar to username, but for applications
- **client_secret**: Like password, but for applications (null for public clients like mobile apps)
- **redirect_uris**: Where to send users after authorization
- **grant_types**: Which OAuth flows this client can use
- **scopes**: Maximum scopes this client can request
- **is_public**: Public clients (mobile/SPA) don't use client_secret

### Normalization Consideration

Storing comma-separated values (redirect_uris, grant_types, scopes) isn't fully normalized. For production, consider:
- Separate tables: `client_redirect_uris`, `client_grant_types`, `client_scopes`
- **Why for learning**: Simpler to start with, easier to query
- **When to normalize**: When you need to query/filter by individual values

---

## Step 7: Design OAuth-Specific Tables

### Create V3__create_authorization_codes_table.sql

### Authorization Codes Table

Stores temporary authorization codes:

| Column | Type | Constraints | Purpose |
|--------|------|-------------|---------|
| `id` | BIGSERIAL | PRIMARY KEY | Unique identifier |
| `code` | VARCHAR(255) | NOT NULL, UNIQUE | The authorization code |
| `client_id` | VARCHAR(100) | NOT NULL, FOREIGN KEY | Which client requested |
| `user_id` | BIGINT | NOT NULL, FOREIGN KEY | Which user authorized |
| `redirect_uri` | VARCHAR(500) | NOT NULL | Where to redirect after exchange |
| `scopes` | VARCHAR(255) | | Granted scopes |
| `code_challenge` | VARCHAR(255) | | PKCE code challenge (optional) |
| `code_challenge_method` | VARCHAR(10) | | PKCE method (S256 or plain) |
| `expires_at` | TIMESTAMP | NOT NULL | When code expires (typically 10 mins) |
| `created_at` | TIMESTAMP | NOT NULL, DEFAULT CURRENT_TIMESTAMP | Creation time |

### Why Short-Lived?

Authorization codes should expire quickly (5-10 minutes):
- **Security**: Reduces window for interception attacks
- **One-time use**: Once exchanged for tokens, code is invalidated
- **Cleanup**: Old codes can be deleted

### Foreign Keys

Add foreign key constraints:
- `client_id` → `clients(client_id)`
- `user_id` → `users(id)`

*Why*: Ensures referential integrity (can't have codes for non-existent users/clients)

---

## Step 8: Create Additional Tables

### Create V4__create_access_tokens_table.sql

### Access Tokens Table

| Column | Type | Constraints | Purpose |
|--------|------|-------------|---------|
| `id` | BIGSERIAL | PRIMARY KEY | Unique identifier |
| `token` | TEXT | NOT NULL, UNIQUE | The JWT or opaque token |
| `user_id` | BIGINT | NOT NULL, FOREIGN KEY | Token owner |
| `client_id` | VARCHAR(100) | NOT NULL, FOREIGN KEY | Client that obtained token |
| `scopes` | VARCHAR(255) | | Granted scopes |
| `expires_at` | TIMESTAMP | NOT NULL | Token expiration (typically 1 hour) |
| `created_at` | TIMESTAMP | NOT NULL, DEFAULT CURRENT_TIMESTAMP | Issuance time |

### Create V5__create_refresh_tokens_table.sql

### Refresh Tokens Table

| Column | Type | Constraints | Purpose |
|--------|------|-------------|---------|
| `id` | BIGSERIAL | PRIMARY KEY | Unique identifier |
| `token` | VARCHAR(255) | NOT NULL, UNIQUE | The refresh token |
| `access_token_id` | BIGINT | FOREIGN KEY | Associated access token |
| `user_id` | BIGINT | NOT NULL, FOREIGN KEY | Token owner |
| `client_id` | VARCHAR(100) | NOT NULL, FOREIGN KEY | Client that obtained token |
| `expires_at` | TIMESTAMP | NOT NULL | Token expiration (typically 30 days) |
| `revoked` | BOOLEAN | NOT NULL, DEFAULT FALSE | Revocation status |
| `created_at` | TIMESTAMP | NOT NULL, DEFAULT CURRENT_TIMESTAMP | Issuance time |

### Why Separate Tables?

- **Different lifecycles**: Access tokens are short-lived, refresh tokens are long-lived
- **Revocation**: Can revoke refresh tokens without affecting active access tokens
- **Auditing**: Track refresh token usage patterns

---

## Step 9: Run Migrations

### Start Your Application

When Spring Boot starts with Flyway enabled:
1. Flyway checks for `flyway_schema_history` table
2. Creates it if missing
3. Scans `db/migration/` for SQL files
4. Runs migrations that haven't been executed
5. Records each migration in `flyway_schema_history`

### Verify Migrations

#### Check Application Logs

Look for:
```
Flyway Migration to version 1 - create users table
Flyway Migration to version 2 - create clients table
...
Successfully applied 5 migrations
```

#### Check Database

```bash
docker compose exec postgres psql -U oauth_user -d oauth_idp
```

```sql
-- List all tables
\dt

-- View migration history
SELECT * FROM flyway_schema_history;

-- Describe users table
\d users
```

You should see all tables created with proper constraints and indexes.

---

## Step 10: Handling Migration Errors

### Common Issues

#### "Migration checksum mismatch"

**Cause**: You edited a migration file after it ran

**Solution**:
- **Never edit applied migrations**
- Create a new migration to fix issues
- Or: Delete `flyway_schema_history` and re-run (development only!)

#### "Found non-empty schema without schema history table"

**Cause**: Database has tables but no Flyway history

**Solution**: Enable `baseline-on-migrate: true` in configuration

#### Migration fails partway through

**Cause**: SQL syntax error or constraint violation

**Solution**:
1. Fix the migration file
2. Manually delete the failed migration from `flyway_schema_history`
3. Fix any partially applied changes in database
4. Restart application

### Best Practices

- **Test migrations locally** before committing
- **Make migrations idempotent** when possible (use `IF NOT EXISTS`)
- **Never modify applied migrations** in production
- **Back up database** before running migrations in production

---

## Step 11: Seed Initial Data

### Create V6__seed_initial_data.sql

### Add Test User

Insert a test user for development:

```sql
-- Insert test user (password: password123, BCrypt hashed)
INSERT INTO users (username, password, email, enabled) VALUES
('testuser', '$2a$10$...hash...', 'test@example.com', true);
```

**Note**: Generate BCrypt hash using:
- Online tool: https://bcrypt-generator.com/
- Or: Write a simple Java class using `BCryptPasswordEncoder`

### Add Test OAuth Client

```sql
-- Insert demo client
INSERT INTO clients (client_id, client_secret, client_name, redirect_uris, grant_types, scopes, is_public) VALUES
('demo-client', '$2a$10$...hash...', 'Demo Application', 'http://localhost:3000/callback', 'authorization_code,refresh_token', 'openid,profile,email', false);
```

### Why Seed Data?

- **Testing**: Immediately test OAuth flows without manual setup
- **Development**: Consistent test data across team members
- **Documentation**: Examples of valid data

---

## Understanding Schema Evolution

### Adding a New Column

**Create**: `V7__add_phone_number_to_users.sql`

```sql
ALTER TABLE users ADD COLUMN phone_number VARCHAR(20);
```

### Renaming a Column

**Dangerous**: Renaming breaks existing code

**Better approach**:
1. Add new column
2. Copy data from old to new
3. Update application code to use new column
4. Remove old column (in a later migration)

### Removing a Column

**Create**: `V8__remove_old_column.sql`

Only remove after ensuring no code references it.

---

## What You've Accomplished

✅ Set up Flyway for database migrations
✅ Created versioned migration scripts
✅ Designed normalized database schema for OAuth
✅ Added foreign key constraints for data integrity
✅ Created indexes for query performance
✅ Seeded initial test data
✅ Understood schema evolution best practices

---

## Next Steps

**Proceed to Guide 05**: Password Hashing and Validation

Before moving on, ensure:
- [ ] All migrations run successfully
- [ ] Tables exist with correct columns and constraints
- [ ] `flyway_schema_history` table shows all migrations
- [ ] Test data is inserted
- [ ] Foreign keys are properly configured

---

## Key Concepts Learned

### Database Migrations
- Version control for database schema
- Migrations are immutable (never edit after applying)
- Sequential execution ensures consistency

### Referential Integrity
- Foreign keys prevent orphaned records
- Cascading deletes can automate cleanup
- Trade-off: Performance vs data consistency

### Indexing Strategy
- Index columns used in WHERE clauses
- Unique constraints automatically create indexes
- Too many indexes slow down writes

### Schema Normalization
- Reduce data redundancy
- Separate concerns into different tables
- Trade-off: Simplicity vs query performance

---

## Additional Resources

- **Flyway Documentation**: https://flywaydb.org/documentation/
- **Database Migration Best Practices**: https://www.baeldung.com/database-migrations-with-flyway
- **PostgreSQL Indexes**: https://www.postgresql.org/docs/current/indexes.html
- **Database Normalization**: https://www.baeldung.com/java-database-normalization
- **Spring Boot Flyway**: https://docs.spring.io/spring-boot/docs/current/reference/html/howto.html#howto.data-initialization.migration-tool
