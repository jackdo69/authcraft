# Guide 38: Performance Testing and Load Testing

**Advanced Topics** | **Task 38 of 45**

## Overview

Perform comprehensive performance and load testing on your OAuth IdP to identify bottlenecks, measure capacity, and ensure it can handle production traffic. Learn to use Apache JMeter, Gatling, and k6 for testing authentication flows under load.

---

## What You'll Build

- JMeter test plans for OAuth flows
- Load testing scenarios
- Performance benchmarks
- Bottleneck identification
- Database query optimization
- Connection pool tuning
- Caching strategies
- Performance monitoring dashboards

---

## Why Performance Testing?

### Production Readiness

**Avoid Surprises**: Don't discover performance issues in production
**Capacity Planning**: Know how many users you can support
**SLA Compliance**: Meet performance SLAs (e.g., 99.9% uptime, <200ms response)
**Cost Optimization**: Right-size infrastructure

### Key Metrics

- **Throughput**: Requests per second (RPS)
- **Latency**: Response time (p50, p95, p99)
- **Error Rate**: Percentage of failed requests
- **Concurrency**: Simultaneous users
- **Resource Utilization**: CPU, memory, database connections

**Learn More**: https://jmeter.apache.org/usermanual/best-practices.html

---

## Step 1: Install Load Testing Tools

### Apache JMeter

```bash
# macOS
brew install jmeter

# Linux
wget https://dlcdn.apache.org//jmeter/binaries/apache-jmeter-5.6.2.tgz
tar -xzf apache-jmeter-5.6.2.tgz
cd apache-jmeter-5.6.2/bin
./jmeter
```

**Why JMeter?**: Industry standard, GUI for test plan creation, extensive protocols

### Gatling (Alternative)

```bash
# Install Gatling
wget https://repo1.maven.org/maven2/io/gatling/highcharts/gatling-charts-highcharts-bundle/3.9.5/gatling-charts-highcharts-bundle-3.9.5.zip
unzip gatling-charts-highcharts-bundle-3.9.5.zip
```

**Why Gatling?**: Scala-based, code-as-config, beautiful reports

### k6 (Modern Alternative)

```bash
# macOS
brew install k6

# Linux
sudo gpg -k
sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg \
  --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" | \
  sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update
sudo apt-get install k6
```

**Why k6?**: JavaScript-based, cloud-native, excellent for CI/CD

---

## Step 2: Create JMeter Test Plan for Login

### Login Flow Test

1. Open JMeter GUI: `jmeter`
2. Create Test Plan: Right-click Test Plan → Add → Threads → Thread Group
3. Configure Thread Group:
   - **Number of Threads**: 100 (concurrent users)
   - **Ramp-Up Period**: 10 seconds (gradual increase)
   - **Loop Count**: 10 (each user logs in 10 times)

4. Add HTTP Request:
   - Right-click Thread Group → Add → Sampler → HTTP Request
   - **Name**: Login Request
   - **Server**: localhost
   - **Port**: 8080
   - **Path**: `/login`
   - **Method**: POST
   - **Parameters**:
     - `username`: john@example.com
     - `password`: password123

5. Add Assertions:
   - Right-click HTTP Request → Add → Assertions → Response Assertion
   - **Response Code**: 200 or 302 (redirect)

6. Add Listeners:
   - Right-click Thread Group → Add → Listener → View Results Tree
   - Add → Listener → Summary Report
   - Add → Listener → Aggregate Report

**Run Test**: Click green "Start" button

---

## Step 3: Test OAuth Authorization Code Flow

### OAuth Flow Test Plan

Create test plan with these steps:

**1. GET /oauth2/authorize**:
```
GET /oauth2/authorize?
  response_type=code
  &client_id=demo-client
  &redirect_uri=http://localhost:3000/callback
  &scope=openid profile email
  &state=xyz123
```

Extract:
- CSRF token from response
- Session cookie

**2. POST /login**:
```
POST /login
Headers:
  Cookie: JSESSIONID=${session_cookie}
Body:
  username=john@example.com
  password=password123
  _csrf=${csrf_token}
```

Extract:
- Authorization code from redirect location

**3. POST /oauth2/token**:
```
POST /oauth2/token
Headers:
  Authorization: Basic ${base64(client_id:client_secret)}
Body:
  grant_type=authorization_code
  code=${authorization_code}
  redirect_uri=http://localhost:3000/callback
```

Extract:
- access_token
- refresh_token

**JMeter Implementation**:
- Use Regular Expression Extractor for parsing
- Use JSON Extractor for token response
- Use ForEach Controller for loops

---

## Step 4: Create k6 Load Test Script

### k6 Test Script

Create `oauth-load-test.js`:

```javascript
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');

// Test configuration
export const options = {
  stages: [
    { duration: '1m', target: 50 },   // Ramp up to 50 users
    { duration: '3m', target: 50 },   // Stay at 50 users
    { duration: '1m', target: 100 },  // Ramp to 100 users
    { duration: '3m', target: 100 },  // Stay at 100 users
    { duration: '1m', target: 0 },    // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'], // 95% requests under 500ms
    http_req_failed: ['rate<0.01'],   // Error rate under 1%
    errors: ['rate<0.05'],             // Custom error rate under 5%
  },
};

const BASE_URL = 'http://localhost:8080';

export default function () {
  // Step 1: GET authorization endpoint
  let authResponse = http.get(
    `${BASE_URL}/oauth2/authorize?response_type=code&client_id=demo-client&redirect_uri=http://localhost:3000/callback&scope=openid+profile+email&state=xyz123`,
    { redirects: 0 } // Don't follow redirects
  );

  check(authResponse, {
    'auth endpoint status 302': (r) => r.status === 302,
  });

  // Extract session cookie and CSRF token
  const sessionCookie = authResponse.cookies.JSESSIONID[0].value;
  const csrfToken = authResponse.html().find('input[name="_csrf"]').attr('value');

  // Step 2: POST login
  const loginPayload = {
    username: 'john@example.com',
    password: 'password123',
    _csrf: csrfToken,
  };

  let loginResponse = http.post(
    `${BASE_URL}/login`,
    loginPayload,
    {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Cookie: `JSESSIONID=${sessionCookie}`,
      },
      redirects: 0,
    }
  );

  check(loginResponse, {
    'login status 302': (r) => r.status === 302,
  });

  // Extract authorization code from redirect
  const location = loginResponse.headers['Location'];
  const codeMatch = location.match(/code=([^&]+)/);
  const authCode = codeMatch ? codeMatch[1] : null;

  if (!authCode) {
    errorRate.add(1);
    return;
  }

  // Step 3: POST token endpoint
  const tokenPayload = {
    grant_type: 'authorization_code',
    code: authCode,
    redirect_uri: 'http://localhost:3000/callback',
    client_id: 'demo-client',
    client_secret: 'demo-secret',
  };

  let tokenResponse = http.post(
    `${BASE_URL}/oauth2/token`,
    tokenPayload,
    {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    }
  );

  const success = check(tokenResponse, {
    'token endpoint status 200': (r) => r.status === 200,
    'has access token': (r) => r.json('access_token') !== undefined,
  });

  if (!success) {
    errorRate.add(1);
  }

  sleep(1); // Think time between iterations
}
```

**Run test**:
```bash
k6 run oauth-load-test.js
```

**Output**:
```
     ✓ auth endpoint status 302
     ✓ login status 302
     ✓ token endpoint status 200
     ✓ has access token

     checks.........................: 100.00% ✓ 4000  ✗ 0
     data_received..................: 12 MB   40 kB/s
     data_sent......................: 8.2 MB  27 kB/s
     http_req_duration..............: avg=85ms  min=20ms med=75ms max=450ms p(95)=180ms p(99)=350ms
     http_reqs......................: 3000    10/s
     iteration_duration.............: avg=1.1s  min=1s   med=1.08s max=1.5s
```

---

## Step 5: Database Performance Testing

### Identify Slow Queries

Enable query logging in PostgreSQL:

```sql
-- In postgresql.conf
log_statement = 'all'
log_duration = on
log_min_duration_statement = 100  -- Log queries > 100ms
```

**Or use `pg_stat_statements`**:

```sql
-- Enable extension
CREATE EXTENSION pg_stat_statements;

-- View slow queries
SELECT
  query,
  calls,
  total_exec_time,
  mean_exec_time,
  max_exec_time
FROM pg_stat_statements
ORDER BY mean_exec_time DESC
LIMIT 10;
```

### Add Missing Indexes

```sql
-- Example: Index on user email lookups
CREATE INDEX idx_users_email ON users(email);

-- Index on token lookups
CREATE INDEX idx_access_tokens_token ON access_tokens(token_value);

-- Index on authorization codes
CREATE INDEX idx_auth_codes_code ON authorization_codes(code);

-- Composite index for user + client queries
CREATE INDEX idx_refresh_tokens_user_client ON refresh_tokens(user_id, client_id);
```

### Query Optimization

**Before**:
```sql
SELECT * FROM users WHERE email = 'john@example.com';
```

**After** (select only needed fields):
```sql
SELECT id, email, password_hash, enabled FROM users WHERE email = 'john@example.com';
```

---

## Step 6: Connection Pool Tuning

### HikariCP Configuration

Update `application.yml`:

```yaml
spring:
  datasource:
    hikari:
      maximum-pool-size: 20          # Max connections
      minimum-idle: 5                 # Min idle connections
      connection-timeout: 30000       # 30 seconds
      idle-timeout: 600000            # 10 minutes
      max-lifetime: 1800000           # 30 minutes
      leak-detection-threshold: 60000 # Detect leaks after 60s
```

**Formula**: `maximum-pool-size = ((core_count * 2) + effective_spindle_count)`

For 4-core server with SSD: `(4 * 2) + 1 = 9` (round up to 10-20)

### Monitor Pool

```java
@Component
public class HikariPoolMonitor {

    @Autowired
    private DataSource dataSource;

    @Scheduled(fixedRate = 60000) // Every minute
    public void logPoolStats() {
        if (dataSource instanceof HikariDataSource) {
            HikariDataSource hikari = (HikariDataSource) dataSource;
            HikariPoolMXBean poolBean = hikari.getHikariPoolMXBean();

            log.info("HikariCP Stats - Active: {}, Idle: {}, Total: {}, Waiting: {}",
                poolBean.getActiveConnections(),
                poolBean.getIdleConnections(),
                poolBean.getTotalConnections(),
                poolBean.getThreadsAwaitingConnection()
            );
        }
    }
}
```

---

## Step 7: Caching Strategy

### Add Redis Caching

**User Cache**:
```java
@Service
public class UserService {

    @Cacheable(value = "users", key = "#email")
    public User findByEmail(String email) {
        return userRepository.findByEmail(email).orElse(null);
    }

    @CacheEvict(value = "users", key = "#user.email")
    public void updateUser(User user) {
        userRepository.save(user);
    }
}
```

**Client Cache**:
```java
@Cacheable(value = "oauth_clients", key = "#clientId")
public OAuth2Client findByClientId(String clientId) {
    return clientRepository.findByClientId(clientId).orElse(null);
}
```

**JWKS Cache** (expensive RSA key operations):
```java
@Cacheable(value = "jwks", key = "'current'")
public String getJWKS() {
    return jwksGenerator.generate();
}
```

### Cache Configuration

```yaml
spring:
  cache:
    type: redis
    redis:
      time-to-live: 600000  # 10 minutes
      cache-null-values: false

  data:
    redis:
      host: localhost
      port: 6379
      lettuce:
        pool:
          max-active: 8
          max-idle: 8
          min-idle: 0
```

---

## Step 8: Analyze Results and Identify Bottlenecks

### Key Metrics to Track

**Response Time Percentiles**:
- **p50 (median)**: 50% of requests faster than this
- **p95**: 95% of requests faster (captures most users)
- **p99**: 99% of requests faster (worst-case experience)
- **max**: Slowest request

**Example**:
```
p50: 80ms   ← Good
p95: 200ms  ← Acceptable
p99: 800ms  ← Concerning (outliers)
max: 5000ms ← Bad (needs investigation)
```

**Throughput**:
- Login endpoint: 100 req/s
- Token endpoint: 150 req/s
- UserInfo endpoint: 200 req/s

### Common Bottlenecks

**1. Database**:
- **Symptom**: High p99 latency, connection pool exhausted
- **Solution**: Add indexes, optimize queries, increase pool size

**2. BCrypt Password Hashing**:
- **Symptom**: Login endpoint slow (BCrypt is CPU-intensive)
- **Solution**: Tune BCrypt rounds (10-12), or use faster algorithm for load testing

**3. JWT Signing**:
- **Symptom**: Token endpoint slow (RSA signing expensive)
- **Solution**: Cache public keys, use HMAC for non-federated scenarios

**4. Session Storage**:
- **Symptom**: High Redis latency
- **Solution**: Use connection pooling, consider in-memory cache

**5. Network Latency**:
- **Symptom**: High latency across all endpoints
- **Solution**: Deploy closer to users, use CDN for static assets

---

## Step 9: Set Performance Baselines

### Define SLAs

**Login Endpoint**:
- p95 response time: <300ms
- p99 response time: <500ms
- Throughput: >100 req/s
- Error rate: <0.1%

**Token Endpoint**:
- p95 response time: <200ms
- p99 response time: <400ms
- Throughput: >200 req/s
- Error rate: <0.1%

**UserInfo Endpoint**:
- p95 response time: <100ms
- p99 response time: <200ms
- Throughput: >500 req/s
- Error rate: <0.1%

### Continuous Performance Testing

Add to CI/CD pipeline:

```yaml
# .github/workflows/performance.yml
name: Performance Tests

on:
  push:
    branches: [main]

jobs:
  performance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Start services
        run: docker-compose up -d

      - name: Run k6 tests
        run: |
          k6 run --out json=results.json oauth-load-test.js

      - name: Check thresholds
        run: |
          # Fail if p95 > 500ms
          p95=$(jq '.metrics.http_req_duration.values.p95' results.json)
          if (( $(echo "$p95 > 500" | bc -l) )); then
            echo "FAIL: p95 ($p95ms) exceeds threshold (500ms)"
            exit 1
          fi
```

---

## Step 10: Stress Testing and Capacity Planning

### Stress Test

Push system beyond expected load to find breaking point:

```javascript
// k6 stress test
export const options = {
  stages: [
    { duration: '2m', target: 100 },   // Normal load
    { duration: '5m', target: 500 },   // Peak load
    { duration: '2m', target: 1000 },  // Stress
    { duration: '3m', target: 1500 },  // Breaking point
    { duration: '2m', target: 0 },     // Recovery
  ],
};
```

**Find**:
- Maximum throughput before errors spike
- Resource saturation point (CPU, memory, DB connections)
- Recovery time after load drops

### Spike Testing

Sudden traffic increase:

```javascript
export const options = {
  stages: [
    { duration: '1m', target: 100 },   // Normal
    { duration: '10s', target: 1000 }, // Sudden spike
    { duration: '3m', target: 1000 },  // Sustained spike
    { duration: '1m', target: 100 },   // Return to normal
  ],
};
```

**Test**:
- Auto-scaling response time
- Circuit breaker activation
- Graceful degradation

---

## Common Issues

### Out of Memory

**Problem**: Application crashes under load with `OutOfMemoryError`

**Solutions**:
- Increase JVM heap: `-Xmx2g`
- Fix memory leaks (unclosed connections)
- Reduce session size
- Use pagination for large datasets

### Connection Pool Exhausted

**Problem**: "HikariPool - Connection is not available"

**Solutions**:
- Increase `maximum-pool-size`
- Fix connection leaks (always close in try-with-resources)
- Optimize slow queries
- Add read replicas

### High CPU Usage

**Problem**: CPU at 100% during load test

**Solutions**:
- Profile with VisualVM or YourKit
- Reduce BCrypt rounds for password hashing
- Cache expensive computations
- Scale horizontally (add more servers)

### Redis Timeouts

**Problem**: "Redis command timed out"

**Solutions**:
- Increase connection pool size
- Check network latency to Redis
- Use Redis cluster for horizontal scaling
- Reduce TTL to free memory

---

## What You've Accomplished

✅ Installed load testing tools (JMeter, k6)
✅ Created test plans for OAuth flows
✅ Performed load testing on all endpoints
✅ Identified and optimized database queries
✅ Tuned connection pools and caching
✅ Set performance baselines and SLAs
✅ Conducted stress and spike testing
✅ Established continuous performance monitoring

---

## Next Steps

**Proceed to Guide 39**: Advanced Security Features

Before moving on:
- [ ] Load tests passing for all endpoints
- [ ] Database queries optimized
- [ ] Connection pools tuned
- [ ] Caching implemented
- [ ] Performance baselines documented
- [ ] CI/CD includes performance tests

---

## Key Concepts Learned

### Performance Metrics

- **Throughput**: Requests handled per second
- **Latency**: Time to process request (p50, p95, p99)
- **Error Rate**: Percentage of failed requests
- **Resource Utilization**: CPU, memory, disk, network

### Optimization Strategies

- **Database**: Indexes, query optimization, connection pooling
- **Caching**: Redis, in-memory, CDN
- **Application**: Async processing, thread pooling
- **Infrastructure**: Horizontal scaling, load balancing

### Testing Types

- **Load Testing**: Expected production load
- **Stress Testing**: Beyond capacity to find breaking point
- **Spike Testing**: Sudden traffic increases
- **Endurance Testing**: Sustained load over time

---

## Additional Resources

- **Apache JMeter**: https://jmeter.apache.org/
- **k6 Documentation**: https://k6.io/docs/
- **Gatling**: https://gatling.io/docs/
- **HikariCP Best Practices**: https://github.com/brettwooldridge/HikariCP/wiki/About-Pool-Sizing
- **PostgreSQL Performance Tuning**: https://wiki.postgresql.org/wiki/Performance_Optimization
- **Redis Performance**: https://redis.io/docs/management/optimization/
- **Spring Boot Performance**: https://spring.io/blog/2015/12/10/spring-boot-memory-performance
