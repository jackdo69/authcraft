# Guide 33: Docker Deployment with HTTPS

**Advanced Topics** | **Task 33 of 45**

## Overview

Containerize your OAuth Identity Provider and deploy with HTTPS using Docker, Docker Compose, and SSL certificates (mkcert for development, Let's Encrypt for production).

---

## What You'll Build

- Dockerfiles for all services (IdP, Resource Server, Client)
- Multi-stage builds for optimization
- Docker Compose orchestration
- Nginx reverse proxy with SSL
- Environment variable management
- Production-ready deployment

---

## Why Containerization?

### Benefits

**Consistency**: Same environment dev → staging → production
**Isolation**: Dependencies contained per service
**Scalability**: Easy horizontal scaling
**Portability**: Run anywhere Docker runs
**Efficiency**: Share base images, layer caching

**Learn More**: https://docs.docker.com/get-started/overview/

---

## Step 1: Create Dockerfile for Identity Provider

### Multi-Stage Build

Create `identity-provider/Dockerfile`:

```dockerfile
# Stage 1: Build
FROM eclipse-temurin:17-jdk-alpine AS build
WORKDIR /app

# Copy Maven wrapper and pom.xml
COPY .mvn/ .mvn/
COPY mvnw pom.xml ./

# Download dependencies (cached layer)
RUN ./mvnw dependency:go-offline

# Copy source code
COPY src ./src

# Build application
RUN ./mvnw clean package -DskipTests

# Stage 2: Runtime
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app

# Create non-root user
RUN addgroup -S spring && adduser -S spring -G spring
USER spring:spring

# Copy JAR from build stage
COPY --from=build /app/target/*.jar app.jar

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=60s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/actuator/health || exit 1

# Run application
ENTRYPOINT ["java", \
  "-XX:MaxRAMPercentage=75.0", \
  "-Djava.security.egd=file:/dev/./urandom", \
  "-jar", "app.jar"]
```

### Why Multi-Stage?

- **Smaller image**: Final image only contains JRE + JAR (not Maven, source code)
- **Faster builds**: Dependencies cached separately
- **Security**: No build tools in production image

---

## Step 2: Create Dockerfiles for Other Services

### Resource Server Dockerfile

`resource-server/Dockerfile` (same structure as IdP)

### Client App Dockerfile  

`client-app/Dockerfile` (same structure as IdP)

### .dockerignore Files

Create `.dockerignore` in each service:

```
target/
.mvn/
*.iml
.idea/
.git/
README.md
```

*Why?*: Exclude unnecessary files from build context (faster builds)

---

## Step 3: Create Docker Compose Configuration

### docker-compose.yml

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    container_name: oauth-postgres
    environment:
      POSTGRES_DB: ${POSTGRES_DB:-oauth_idp}
      POSTGRES_USER: ${POSTGRES_USER:-oauth_user}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-changeme}
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - oauth-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER:-oauth_user}"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    container_name: oauth-redis
    command: redis-server --appendonly yes
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    networks:
      - oauth-network
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 3s
      retries: 5

  identity-provider:
    build:
      context: ./identity-provider
      dockerfile: Dockerfile
    container_name: oauth-idp
    environment:
      SPRING_PROFILES_ACTIVE: docker
      SPRING_DATASOURCE_URL: jdbc:postgresql://postgres:5432/${POSTGRES_DB:-oauth_idp}
      SPRING_DATASOURCE_USERNAME: ${POSTGRES_USER:-oauth_user}
      SPRING_DATASOURCE_PASSWORD: ${POSTGRES_PASSWORD:-changeme}
      SPRING_DATA_REDIS_HOST: redis
      SPRING_DATA_REDIS_PORT: 6379
      JWT_SECRET: ${JWT_SECRET}
      SERVER_PORT: 8080
    ports:
      - "8080:8080"
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks:
      - oauth-network
    restart: unless-stopped

  resource-server:
    build:
      context: ./resource-server
      dockerfile: Dockerfile
    container_name: oauth-resource-server
    environment:
      SPRING_PROFILES_ACTIVE: docker
      SPRING_SECURITY_OAUTH2_RESOURCESERVER_JWT_ISSUER_URI: http://identity-provider:8080
      SPRING_SECURITY_OAUTH2_RESOURCESERVER_JWT_JWK_SET_URI: http://identity-provider:8080/oauth2/jwks
      SERVER_PORT: 8081
    ports:
      - "8081:8081"
    depends_on:
      - identity-provider
    networks:
      - oauth-network
    restart: unless-stopped

  client-app:
    build:
      context: ./client-app
      dockerfile: Dockerfile
    container_name: oauth-client
    environment:
      SPRING_PROFILES_ACTIVE: docker
      SPRING_SECURITY_OAUTH2_CLIENT_PROVIDER_CUSTOM_IDP_ISSUER_URI: http://identity-provider:8080
      SPRING_SECURITY_OAUTH2_CLIENT_PROVIDER_CUSTOM_IDP_AUTHORIZATION_URI: http://localhost/oauth2/authorize
      SPRING_SECURITY_OAUTH2_CLIENT_PROVIDER_CUSTOM_IDP_TOKEN_URI: http://identity-provider:8080/oauth2/token
      SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_CUSTOM_IDP_CLIENT_ID: demo-client
      SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_CUSTOM_IDP_CLIENT_SECRET: ${CLIENT_SECRET}
      SERVER_PORT: 3000
    ports:
      - "3000:3000"
    depends_on:
      - identity-provider
    networks:
      - oauth-network
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    container_name: oauth-nginx
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/certs:/etc/nginx/certs:ro
    depends_on:
      - identity-provider
      - resource-server
      - client-app
    networks:
      - oauth-network
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:

networks:
  oauth-network:
    driver: bridge
```

---

## Step 4: Configure Nginx Reverse Proxy

### Create nginx.conf

`nginx/nginx.conf`:

```nginx
events {
    worker_connections 1024;
}

http {
    upstream identity-provider {
        server identity-provider:8080;
    }

    upstream resource-server {
        server resource-server:8081;
    }

    upstream client-app {
        server client-app:3000;
    }

    # HTTP redirect to HTTPS
    server {
        listen 80;
        server_name localhost;
        return 301 https://$server_name$request_uri;
    }

    # HTTPS server
    server {
        listen 443 ssl http2;
        server_name localhost;

        # SSL certificates
        ssl_certificate /etc/nginx/certs/cert.pem;
        ssl_certificate_key /etc/nginx/certs/key.pem;

        # SSL configuration
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers on;

        # Security headers
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection "1; mode=block" always;

        # Identity Provider
        location /oauth2/ {
            proxy_pass http://identity-provider;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        location /login {
            proxy_pass http://identity-provider;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        location /.well-known/ {
            proxy_pass http://identity-provider;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Resource Server API
        location /api/ {
            proxy_pass http://resource-server;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Client App
        location / {
            proxy_pass http://client-app;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
}
```

---

## Step 5: Generate SSL Certificates

### Development: mkcert

**Install mkcert**:
```bash
# macOS
brew install mkcert
mkcert -install

# Linux
wget https://github.com/FiloSottile/mkcert/releases/download/v1.4.4/mkcert-v1.4.4-linux-amd64
chmod +x mkcert-v1.4.4-linux-amd64
sudo mv mkcert-v1.4.4-linux-amd64 /usr/local/bin/mkcert
mkcert -install
```

**Generate certificates**:
```bash
mkdir -p nginx/certs
cd nginx/certs
mkcert localhost 127.0.0.1 ::1
mv localhost+2.pem cert.pem
mv localhost+2-key.pem key.pem
```

### Production: Let's Encrypt

**Using Certbot**:
```bash
# Install certbot
sudo apt-get install certbot

# Generate certificate
sudo certbot certonly --standalone -d yourdomain.com

# Certificates will be in:
# /etc/letsencrypt/live/yourdomain.com/fullchain.pem
# /etc/letsencrypt/live/yourdomain.com/privkey.pem
```

**Update docker-compose.yml**:
```yaml
nginx:
  volumes:
    - /etc/letsencrypt/live/yourdomain.com:/etc/nginx/certs:ro
```

**Auto-renewal**:
```bash
# Add to crontab
0 0 * * * certbot renew --quiet && docker-compose restart nginx
```

---

## Step 6: Environment Configuration

### Create .env File

```bash
# Database
POSTGRES_DB=oauth_idp
POSTGRES_USER=oauth_user
POSTGRES_PASSWORD=strong_password_here

# JWT
JWT_SECRET=your-very-long-secret-key-at-least-256-bits

# Client
CLIENT_SECRET=demo-client-secret-hashed

# Production
SPRING_PROFILES_ACTIVE=docker
```

### Create application-docker.yml

In each service, create `src/main/resources/application-docker.yml`:

```yaml
spring:
  datasource:
    url: ${SPRING_DATASOURCE_URL}
    username: ${SPRING_DATASOURCE_USERNAME}
    password: ${SPRING_DATASOURCE_PASSWORD}
  
  data:
    redis:
      host: ${SPRING_DATA_REDIS_HOST}
      port: ${SPRING_DATA_REDIS_PORT}

server:
  forward-headers-strategy: framework  # Trust proxy headers

logging:
  level:
    root: INFO
    com.learning.idp: DEBUG
```

---

## Step 7: Build and Run

### Build Images

```bash
docker-compose build
```

### Start Services

```bash
docker-compose up -d
```

### View Logs

```bash
docker-compose logs -f identity-provider
```

### Check Health

```bash
docker-compose ps
curl https://localhost/.well-known/openid-configuration
```

---

## Step 8: Production Optimizations

### Image Optimization

**Use specific base image versions**:
```dockerfile
FROM eclipse-temurin:17.0.9_9-jre-alpine
```

**Layer caching**:
```dockerfile
# Copy dependencies first (changes less frequently)
COPY pom.xml .
RUN mvn dependency:go-offline

# Copy source last (changes more frequently)
COPY src ./src
```

### Resource Limits

docker-compose.yml:
```yaml
identity-provider:
  deploy:
    resources:
      limits:
        cpus: '2'
        memory: 2G
      reservations:
        cpus: '1'
        memory: 1G
```

### Logging

```yaml
identity-provider:
  logging:
    driver: "json-file"
    options:
      max-size: "10m"
      max-file: "3"
```

---

## Step 9: Database Migrations

### Run Flyway on Startup

Ensure Flyway runs automatically:

application.yml:
```yaml
spring:
  flyway:
    enabled: true
    baseline-on-migrate: true
```

### Backup Strategy

```bash
# Backup script
docker exec oauth-postgres pg_dump -U oauth_user oauth_idp > backup.sql

# Restore
docker exec -i oauth-postgres psql -U oauth_user oauth_idp < backup.sql
```

---

## Step 10: Monitoring and Health Checks

### Add Spring Boot Actuator

pom.xml:
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-actuator</artifactId>
</dependency>
```

### Configure Endpoints

application.yml:
```yaml
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics,prometheus
  endpoint:
    health:
      show-details: always
```

### Prometheus Metrics

docker-compose.yml:
```yaml
prometheus:
  image: prom/prometheus:latest
  volumes:
    - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
    - prometheus_data:/prometheus
  ports:
    - "9090:9090"
  networks:
    - oauth-network

grafana:
  image: grafana/grafana:latest
  ports:
    - "3001:3000"
  volumes:
    - grafana_data:/var/lib/grafana
  networks:
    - oauth-network
```

---

## Testing Deployment

### Verify Services

```bash
# Check all services running
docker-compose ps

# Test HTTPS
curl -k https://localhost/.well-known/openid-configuration

# Test OAuth flow
open https://localhost
```

### Load Testing

```bash
# Using Apache Bench
ab -n 1000 -c 10 https://localhost/oauth2/token

# Using wrk
wrk -t4 -c100 -d30s https://localhost/
```

---

## Common Issues

### Port conflicts

**Error**: "port is already allocated"

**Solution**: Change port mapping or stop conflicting service

### Certificate not trusted

**Error**: "SSL certificate problem"

**Solution**: Install mkcert root CA: `mkcert -install`

### Container can't connect to database

**Error**: "Connection refused"

**Solution**: Use service names (postgres, not localhost) in Docker network

### Out of memory

**Error**: Container killed by OOM

**Solution**: Increase Docker memory limit or container limits

---

## What You've Accomplished

✅ Created Dockerfiles with multi-stage builds
✅ Configured Docker Compose orchestration
✅ Set up Nginx reverse proxy with SSL
✅ Generated SSL certificates (dev and prod)
✅ Implemented health checks and monitoring
✅ Optimized for production deployment

---

## Next Steps

**Proceed to Guide 34**: Audit Logging

Before moving on:
- [ ] All services containerized
- [ ] Docker Compose starts all services
- [ ] HTTPS working with valid certificates
- [ ] Health checks passing
- [ ] Services can communicate

---

## Key Concepts Learned

### Containerization
- Docker isolates application dependencies
- Images are immutable, containers are ephemeral
- Multi-stage builds reduce image size

### Orchestration
- Docker Compose manages multi-container apps
- Service discovery via container names
- Network isolation for security

### Reverse Proxy
- Nginx routes traffic to backend services
- SSL termination at proxy
- Single entry point for all services

### Production Deployment
- Environment-specific configuration
- Health checks for reliability
- Resource limits prevent runaway processes

---

## Additional Resources

- **Docker Best Practices**: https://docs.docker.com/develop/dev-best-practices/
- **Multi-Stage Builds**: https://docs.docker.com/build/building/multi-stage/
- **Docker Compose**: https://docs.docker.com/compose/
- **mkcert**: https://github.com/FiloSottile/mkcert
- **Let's Encrypt**: https://letsencrypt.org/getting-started/
- **Nginx Reverse Proxy**: https://docs.nginx.com/nginx/admin-guide/web-server/reverse-proxy/
