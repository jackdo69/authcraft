# Guide 02: Configure PostgreSQL and Redis with Docker

**Phase 1: Foundation** | **Week 1-2** | **Task 2 of 5**

## Overview

Set up PostgreSQL (database) and Redis (session storage) using Docker Compose. These infrastructure services will run in isolated containers, keeping your development environment clean and reproducible.

---

## What You'll Build

- Docker Compose configuration for PostgreSQL and Redis
- Network configuration for service communication
- Persistent data volumes
- Connection from Spring Boot application to both services

---

## Why Docker for Development?

### Benefits
- **No local installation mess**: PostgreSQL and Redis run in containers, not on your machine
- **Easy reset**: Delete containers and start fresh anytime
- **Consistent environment**: Same versions across different machines
- **Matches production**: Modern production systems use containers

### vs. Installing Locally
Installing PostgreSQL and Redis directly on your machine can cause:
- Port conflicts with other services
- Version compatibility issues
- Difficulty cleaning up completely
- Different behavior across team members' machines

---

## Step 1: Create docker-compose.yml

### Create File
In your project root (`authcraft/`), create a file named `docker-compose.yml`

### Add Configuration

You'll need to define two services:
1. **postgres**: PostgreSQL database
2. **redis**: Redis cache/session store

### Docker Compose Structure
```yaml
version: '3.8'

services:
  # Service definitions go here

volumes:
  # Volume definitions go here

networks:
  # Network definitions go here
```

---

## Step 2: Configure PostgreSQL Service

### What to Configure

#### Service Name
- Name: `postgres`
- *Why*: Other containers can connect using this hostname

#### Image
- Use: `postgres:15-alpine`
- *Why*: Alpine is a smaller Linux distribution, faster to download. Version 15 is stable and modern.

#### Container Name
- Set a specific name for easier management
- Makes it easier to see in `docker ps` output

#### Environment Variables
You need to configure:
- **POSTGRES_DB**: Database name (e.g., `oauth_idp`)
  - *Why*: PostgreSQL creates this database on first startup
- **POSTGRES_USER**: Database username (e.g., `oauth_user`)
  - *Why*: Creates a user with access to the database
- **POSTGRES_PASSWORD**: Database password (e.g., `oauth_password`)
  - *Why*: Sets the password for authentication (use strong passwords in production!)

#### Ports
- **Map**: `5432:5432`
  - *Why*: Exposes PostgreSQL's port to your host machine (format: `host:container`)
  - Your Spring Boot app will connect to `localhost:5432`

#### Volumes
- **Purpose**: Persist data between container restarts
- **Format**: `volume_name:/var/lib/postgresql/data`
- *Why*: Without volumes, all data is lost when the container stops

#### Networks
- **Purpose**: Allow services to communicate
- Services on the same network can discover each other by service name

---

## Step 3: Configure Redis Service

### What to Configure

#### Service Name
- Name: `redis`

#### Image
- Use: `redis:7-alpine`
- *Why*: Redis 7 is the latest stable version, Alpine keeps it lightweight

#### Container Name
- Set a specific name for easier identification

#### Ports
- **Map**: `6379:6379`
  - *Why*: Redis default port, exposes it to your host machine

#### Volumes
- **Purpose**: Persist Redis data (optional for development)
- **Format**: `volume_name:/data`
- *Why*: Maintains cache/session data across restarts

#### Networks
- Add to the same network as PostgreSQL

---

## Step 4: Define Volumes

### Volume Configuration

Create named volumes for:
1. **PostgreSQL data**: Stores database files
2. **Redis data**: Stores cache/session files

*Why named volumes?*:
- Docker manages the storage location
- Easier to back up and migrate
- Survives container deletion

---

## Step 5: Define Network

### Network Configuration

Create a bridge network:
- **Name**: `oauth-network` (or any descriptive name)
- **Driver**: `bridge`

*Why a custom network?*:
- Services can communicate using service names as hostnames
- Isolated from other Docker networks
- Better security and organization

---

## Step 6: Start the Services

### Commands

#### Start containers in background
```bash
docker compose up -d
```
- `-d`: Detached mode (runs in background)

#### View running containers
```bash
docker ps
```
You should see both `postgres` and `redis` containers running

#### View logs
```bash
docker compose logs -f
```
- `-f`: Follow mode (like `tail -f`)

#### View specific service logs
```bash
docker compose logs postgres
docker compose logs redis
```

---

## Step 7: Verify PostgreSQL

### Test Connection

#### Using Docker Exec (No PostgreSQL client needed)
```bash
docker compose exec postgres psql -U oauth_user -d oauth_idp
```
- **exec**: Run command inside running container
- **psql**: PostgreSQL interactive terminal
- **-U**: Username
- **-d**: Database name

You should see the `psql` prompt: `oauth_idp=#`

#### Test Commands
```sql
\l                  -- List all databases
\dt                 -- List tables (should be empty)
\q                  -- Quit psql
```

### Connection Details
Your Spring Boot app will connect using:
- **Host**: `localhost` (or `postgres` from inside Docker network)
- **Port**: `5432`
- **Database**: `oauth_idp`
- **Username**: `oauth_user`
- **Password**: `oauth_password`

---

## Step 8: Verify Redis

### Test Connection

#### Using Docker Exec
```bash
docker compose exec redis redis-cli
```

You should see the Redis prompt: `127.0.0.1:6379>`

#### Test Commands
```redis
PING              # Should respond with PONG
SET test "hello"  # Set a key
GET test          # Should return "hello"
DEL test          # Delete the key
QUIT              # Exit Redis CLI
```

### Connection Details
Your Spring Boot app will connect using:
- **Host**: `localhost` (or `redis` from inside Docker network)
- **Port**: `6379`
- **Password**: None (for development)

---

## Step 9: Configure Spring Boot Application

### Update application.yml

In `identity-provider/src/main/resources/application.yml`, add database and Redis configuration:

### Database Configuration
You need to configure:
- **JDBC URL**: Connection string to PostgreSQL
- **Username**: Database user
- **Password**: Database password
- **Driver Class**: PostgreSQL JDBC driver

### JPA/Hibernate Configuration
Configure:
- **DDL Auto**: How Hibernate manages schema (options: `none`, `validate`, `update`, `create`, `create-drop`)
  - *Why*: Controls if Hibernate can modify your database schema
  - For now, use `update` for development (Hibernate updates schema automatically)
  - Later, switch to `validate` and use Flyway for migrations
- **Show SQL**: Whether to log SQL queries (helpful for learning)
- **Dialect**: Database-specific SQL dialect (PostgreSQL)

### Redis Configuration
Configure:
- **Host**: Redis server address (`localhost` for Docker on host)
- **Port**: Redis port (`6379`)
- **Timeout**: Connection timeout

### Session Configuration
Configure:
- **Store Type**: Where to store sessions (`redis`)
- **Timeout**: Session expiration time (e.g., `30m` for 30 minutes)

### Server Configuration
Configure:
- **Port**: Which port your app runs on (`8080`)

---

## Step 10: Test Spring Boot Connection

### Run the Application

1. In IntelliJ, run `IdentityProviderApplication`
2. Watch the console logs

### What to Look For

#### Successful startup indicates:
- ✅ Connected to PostgreSQL
- ✅ Hibernate initialized
- ✅ Connected to Redis
- ✅ Server started on port 8080

#### Common Errors:

**"Unable to connect to database"**
- Check: Docker containers are running (`docker ps`)
- Check: Connection details in `application.yml` match docker-compose.yml
- Check: PostgreSQL is fully started (check logs: `docker compose logs postgres`)

**"org.postgresql.Driver not found"**
- Check: PostgreSQL dependency in `pom.xml`
- Try: Maven reload/reimport

**"Cannot connect to Redis"**
- Check: Redis container is running
- Check: Port 6379 is not in use by another service
- Check: Redis connection details in `application.yml`

---

## Step 11: Verify Hibernate Schema Creation

### Check Tables in PostgreSQL

1. **Connect to PostgreSQL**:
```bash
docker compose exec postgres psql -U oauth_user -d oauth_idp
```

2. **List tables**:
```sql
\dt
```

You should see Spring Security default tables (if Spring Security autoconfiguration ran) or an empty list.

3. **View table structure** (if tables exist):
```sql
\d table_name
```

### What's Happening?
Hibernate is reading your entity classes (which you haven't created yet) and creating database tables automatically. Once you create entity classes (User, Client, etc.), Hibernate will create corresponding tables.

---

## Step 12: Useful Docker Commands

### Managing Containers

#### Stop all services
```bash
docker compose down
```

#### Stop and remove volumes (deletes all data)
```bash
docker compose down -v
```

#### Restart a specific service
```bash
docker compose restart postgres
```

#### View resource usage
```bash
docker stats
```

#### Remove all stopped containers (cleanup)
```bash
docker container prune
```

### Debugging

#### Access container shell
```bash
docker compose exec postgres sh
docker compose exec redis sh
```

#### View container details
```bash
docker inspect <container-name>
```

#### Check container networking
```bash
docker network ls
docker network inspect oauth-network
```

---

## Understanding the Architecture

### Network Flow

```
Your Machine
│
├── Spring Boot App (Port 8080)
│   ├── Connects to → PostgreSQL (localhost:5432)
│   └── Connects to → Redis (localhost:6379)
│
└── Docker Network (oauth-network)
    ├── postgres container (internal: 5432)
    └── redis container (internal: 6379)
```

### Why This Works
- Docker exposes container ports to your host machine
- Your Spring Boot app (running on host) connects to `localhost:5432` and `localhost:6379`
- Docker forwards these to the containers
- If Spring Boot also ran in Docker, it would connect using service names (`postgres:5432`)

---

## Common Issues

### Port Already in Use
**Error**: `Bind for 0.0.0.0:5432 failed: port is already allocated`

**Solutions**:
- Check: `lsof -i :5432` to see what's using the port
- Option 1: Stop the conflicting service
- Option 2: Change the port mapping in docker-compose.yml (e.g., `5433:5432`)

### Container Exits Immediately
**Check logs**: `docker compose logs postgres`

**Common causes**:
- Incorrect environment variables
- Volume permission issues
- Corrupted data volume (solution: `docker compose down -v`)

### Cannot Connect from Spring Boot
**Checklist**:
- [ ] Containers are running: `docker ps`
- [ ] Ports are exposed: Check docker-compose.yml
- [ ] Credentials match: application.yml vs docker-compose.yml
- [ ] Network connectivity: Try `telnet localhost 5432`

---

## Data Persistence

### Where is Data Stored?

Docker stores named volumes in:
- **Mac/Linux**: `/var/lib/docker/volumes/`
- **Windows**: `\\wsl$\docker-desktop-data\version-pack-data\community\docker\volumes\`

### Backup/Restore

#### Backup PostgreSQL
```bash
docker compose exec postgres pg_dump -U oauth_user oauth_idp > backup.sql
```

#### Restore PostgreSQL
```bash
docker compose exec -T postgres psql -U oauth_user -d oauth_idp < backup.sql
```

---

## What You've Accomplished

✅ Created Docker Compose configuration for PostgreSQL and Redis
✅ Started both services in isolated containers
✅ Configured Spring Boot to connect to both services
✅ Verified database and cache connectivity
✅ Understood Docker networking and volumes

---

## Next Steps

**Proceed to Guide 03**: Implement User Registration and Login (Basic Spring Security)

Before moving on, ensure:
- [ ] Both containers are running (`docker ps`)
- [ ] Spring Boot connects successfully to PostgreSQL
- [ ] Spring Boot connects successfully to Redis
- [ ] You can access PostgreSQL via `psql`
- [ ] You can access Redis via `redis-cli`

---

## Key Concepts Learned

### Docker Compose Services
- Services are defined in `docker-compose.yml`
- Each service runs in an isolated container
- Services can communicate via custom networks

### Volumes vs Containers
- Containers are ephemeral (deleted when stopped)
- Volumes persist data across container lifecycles
- Named volumes are managed by Docker

### JDBC Connection Strings
Format: `jdbc:postgresql://host:port/database`
- `jdbc:postgresql://`: Protocol
- `localhost:5432`: Host and port
- `/oauth_idp`: Database name

---

## Additional Resources

- **Docker Compose Documentation**: https://docs.docker.com/compose/
- **PostgreSQL Docker Hub**: https://hub.docker.com/_/postgres
- **Redis Docker Hub**: https://hub.docker.com/_/redis
- **Spring Boot Database Configuration**: https://docs.spring.io/spring-boot/docs/current/reference/html/data.html#data.sql.datasource
- **PostgreSQL JDBC Driver Docs**: https://jdbc.postgresql.org/documentation/
