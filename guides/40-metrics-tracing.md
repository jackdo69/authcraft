# Guide 40: Monitoring, Metrics, and Distributed Tracing

**Advanced Topics** | **Task 40 of 45**

## Overview

Implement comprehensive observability for your OAuth IdP using Prometheus metrics, Grafana dashboards, distributed tracing with OpenTelemetry/Jaeger, and structured logging with ELK stack. Essential for production operations.

---

## What You'll Build

- Prometheus metrics export
- Custom business metrics
- Grafana dashboards
- Distributed tracing with Jaeger/Zipkin
- ELK stack integration (Elasticsearch, Logstash, Kibana)
- Health checks and readiness probes
- Alerting rules (AlertManager)
- SLO/SLI monitoring

---

## Why Monitoring & Observability?

### The Three Pillars

**Metrics**: Numerical measurements over time (CPU, request rate, latency)
**Logs**: Discrete events with context (errors, audit trail)
**Traces**: Request journey across services (distributed tracing)

### Benefits

- **Proactive**: Detect issues before users report them
- **Debugging**: Quickly identify root causes
- **Capacity Planning**: Understand resource usage trends
- **SLA Compliance**: Track and prove uptime/performance SLAs

**Learn More**: https://opentelemetry.io/docs/concepts/observability-primer/

---

## Step 1: Add Prometheus Metrics

### Dependencies

```xml
<dependencies>
    <!-- Actuator for metrics -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-actuator</artifactId>
    </dependency>

    <!-- Micrometer Prometheus registry -->
    <dependency>
        <groupId>io.micrometer</groupId>
        <artifactId>micrometer-registry-prometheus</artifactId>
    </dependency>
</dependencies>
```

### Configuration

`application.yml`:
```yaml
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics,prometheus
  endpoint:
    health:
      show-details: always
    metrics:
      enabled: true
  metrics:
    tags:
      application: oauth-idp
      environment: production
    export:
      prometheus:
        enabled: true
```

### Custom Metrics

```java
@Service
public class OAuth2MetricsService {

    private final Counter loginSuccessCounter;
    private final Counter loginFailureCounter;
    private final Counter tokenIssuedCounter;
    private final Timer authorizationTimer;
    private final Gauge activeSessionsGauge;

    public OAuth2MetricsService(MeterRegistry registry) {
        this.loginSuccessCounter = Counter.builder("oauth.login.success")
            .description("Successful login attempts")
            .tag("type", "password")
            .register(registry);

        this.loginFailureCounter = Counter.builder("oauth.login.failure")
            .description("Failed login attempts")
            .tag("type", "password")
            .register(registry);

        this.tokenIssuedCounter = Counter.builder("oauth.token.issued")
            .description("Tokens issued")
            .tag("grant_type", "authorization_code")
            .register(registry);

        this.authorizationTimer = Timer.builder("oauth.authorization.duration")
            .description("Authorization flow duration")
            .register(registry);

        this.activeSessionsGauge = Gauge.builder("oauth.sessions.active", sessionRegistry::getSessionCount)
            .description("Active user sessions")
            .register(registry);
    }

    public void recordLoginSuccess(String method) {
        loginSuccessCounter.increment();
    }

    public void recordLoginFailure(String method, String reason) {
        Counter.builder("oauth.login.failure")
            .tag("method", method)
            .tag("reason", reason)
            .register(meterRegistry)
            .increment();
    }

    public void recordTokenIssued(String grantType, String clientId) {
        Counter.builder("oauth.token.issued")
            .tag("grant_type", grantType)
            .tag("client_id", clientId)
            .register(meterRegistry)
            .increment();
    }

    public <T> T timeAuthorization(Supplier<T> operation) {
        return authorizationTimer.record(operation);
    }
}
```

**Integrate with code**:
```java
@PostMapping("/login")
public String login(...) {
    try {
        // ... authentication logic
        metricsService.recordLoginSuccess("password");
    } catch (BadCredentialsException e) {
        metricsService.recordLoginFailure("password", "invalid_credentials");
        throw e;
    }
}
```

### Access Metrics

```bash
# Prometheus format
curl http://localhost:8080/actuator/prometheus

# Human-readable
curl http://localhost:8080/actuator/metrics/oauth.login.success
```

---

## Step 2: Set Up Prometheus

### Install Prometheus

```bash
# macOS
brew install prometheus

# Docker
docker run -d \
  --name prometheus \
  -p 9090:9090 \
  -v $(pwd)/prometheus.yml:/etc/prometheus/prometheus.yml \
  prom/prometheus
```

### Configure Prometheus

Create `prometheus.yml`:
```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'oauth-idp'
    metrics_path: '/actuator/prometheus'
    static_configs:
      - targets: ['localhost:8080']
        labels:
          application: 'oauth-idp'
          environment: 'production'

  - job_name: 'postgres-exporter'
    static_configs:
      - targets: ['localhost:9187']

  - job_name: 'redis-exporter'
    static_configs:
      - targets: ['localhost:9121']
```

**Access**: http://localhost:9090

### Query Examples

```promql
# Request rate (requests per second)
rate(http_server_requests_seconds_count[5m])

# 95th percentile latency
histogram_quantile(0.95, rate(http_server_requests_seconds_bucket[5m]))

# Error rate
rate(oauth_login_failure_total[5m]) / rate(oauth_login_success_total[5m])

# Active sessions
oauth_sessions_active
```

---

## Step 3: Create Grafana Dashboards

### Install Grafana

```bash
# macOS
brew install grafana
brew services start grafana

# Docker
docker run -d \
  --name grafana \
  -p 3000:3000 \
  grafana/grafana
```

**Access**: http://localhost:3000 (admin/admin)

### Add Prometheus Data Source

1. Configuration → Data Sources → Add data source
2. Select Prometheus
3. URL: http://localhost:9090
4. Click "Save & Test"

### Create Dashboard

**Panels to include**:

1. **Login Rate** (Graph):
   ```promql
   rate(oauth_login_success_total[5m])
   ```

2. **Failed Login Rate** (Graph):
   ```promql
   rate(oauth_login_failure_total[5m])
   ```

3. **Token Issuance Rate** (Graph):
   ```promql
   rate(oauth_token_issued_total[5m])
   ```

4. **Authorization Latency - p50, p95, p99** (Graph):
   ```promql
   histogram_quantile(0.50, rate(oauth_authorization_duration_bucket[5m]))
   histogram_quantile(0.95, rate(oauth_authorization_duration_bucket[5m]))
   histogram_quantile(0.99, rate(oauth_authorization_duration_bucket[5m]))
   ```

5. **Active Sessions** (Gauge):
   ```promql
   oauth_sessions_active
   ```

6. **Database Connection Pool** (Graph):
   ```promql
   hikaricp_connections_active
   hikaricp_connections_idle
   hikaricp_connections_pending
   ```

7. **JVM Memory** (Graph):
   ```promql
   jvm_memory_used_bytes{area="heap"}
   jvm_memory_max_bytes{area="heap"}
   ```

**Import pre-built dashboards**: https://grafana.com/grafana/dashboards/

- Spring Boot Dashboard: 12900
- JVM Dashboard: 4701

---

## Step 4: Distributed Tracing with OpenTelemetry

### Add Dependencies

```xml
<dependencies>
    <!-- OpenTelemetry -->
    <dependency>
        <groupId>io.opentelemetry</groupId>
        <artifactId>opentelemetry-api</artifactId>
        <version>1.30.1</version>
    </dependency>
    <dependency>
        <groupId>io.opentelemetry</groupId>
        <artifactId>opentelemetry-sdk</artifactId>
        <version>1.30.1</version>
    </dependency>
    <dependency>
        <groupId>io.opentelemetry</groupId>
        <artifactId>opentelemetry-exporter-jaeger</artifactId>
        <version>1.30.1</version>
    </dependency>

    <!-- Spring Boot integration -->
    <dependency>
        <groupId>io.micrometer</groupId>
        <artifactId>micrometer-tracing-bridge-otel</artifactId>
    </dependency>
</dependencies>
```

### Configure Tracing

```java
@Configuration
public class TracingConfig {

    @Bean
    public OpenTelemetry openTelemetry() {
        JaegerGrpcSpanExporter jaegerExporter = JaegerGrpcSpanExporter.builder()
            .setEndpoint("http://localhost:14250")
            .build();

        SdkTracerProvider tracerProvider = SdkTracerProvider.builder()
            .addSpanProcessor(BatchSpanProcessor.builder(jaegerExporter).build())
            .setResource(Resource.create(Attributes.of(
                ResourceAttributes.SERVICE_NAME, "oauth-idp"
            )))
            .build();

        return OpenTelemetrySdk.builder()
            .setTracerProvider(tracerProvider)
            .buildAndRegisterGlobal();
    }
}
```

### Add Custom Spans

```java
@Service
public class AuthorizationService {

    private final Tracer tracer;

    public AuthorizationService(OpenTelemetry openTelemetry) {
        this.tracer = openTelemetry.getTracer("oauth-idp");
    }

    public String generateAuthorizationCode(User user, String clientId) {
        Span span = tracer.spanBuilder("generateAuthorizationCode")
            .setAttribute("user.id", user.getId())
            .setAttribute("client.id", clientId)
            .startSpan();

        try (Scope scope = span.makeCurrent()) {
            // Generate code
            String code = codeGenerator.generate();

            // Save to database (this will be a child span)
            authCodeRepository.save(code, user.getId(), clientId);

            span.setAttribute("code.length", code.length());
            return code;
        } catch (Exception e) {
            span.recordException(e);
            span.setStatus(StatusCode.ERROR, e.getMessage());
            throw e;
        } finally {
            span.end();
        }
    }
}
```

### Install Jaeger

```bash
# Docker
docker run -d \
  --name jaeger \
  -p 5775:5775/udp \
  -p 6831:6831/udp \
  -p 6832:6832/udp \
  -p 5778:5778 \
  -p 16686:16686 \
  -p 14250:14250 \
  -p 14268:14268 \
  -p 9411:9411 \
  jaegertracing/all-in-one:latest
```

**Access UI**: http://localhost:16686

**View traces**:
- Select service: oauth-idp
- See full request flow from authorization → login → token issuance

---

## Step 5: Structured Logging with ELK Stack

### Install ELK Stack

`docker-compose.yml`:
```yaml
version: '3.8'

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.10.2
    environment:
      - discovery.type=single-node
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
      - xpack.security.enabled=false
    ports:
      - "9200:9200"

  logstash:
    image: docker.elastic.co/logstash/logstash:8.10.2
    volumes:
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf
    ports:
      - "5000:5000"
    depends_on:
      - elasticsearch

  kibana:
    image: docker.elastic.co/kibana/kibana:8.10.2
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch
```

### Configure Logstash

`logstash.conf`:
```
input {
  tcp {
    port => 5000
    codec => json_lines
  }
}

filter {
  # Parse log levels
  if [level] == "ERROR" {
    mutate {
      add_tag => ["error"]
    }
  }

  # Extract user ID from MDC
  if [mdc][userId] {
    mutate {
      add_field => { "user_id" => "%{[mdc][userId]}" }
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "oauth-idp-logs-%{+YYYY.MM.dd}"
  }
  stdout { codec => rubydebug }
}
```

### Configure App Logging

Add dependency:
```xml
<dependency>
    <groupId>net.logstash.logback</groupId>
    <artifactId>logstash-logback-encoder</artifactId>
    <version>7.4</version>
</dependency>
```

`logback-spring.xml`:
```xml
<configuration>
    <appender name="LOGSTASH" class="net.logstash.logback.appender.LogstashTcpSocketAppender">
        <destination>localhost:5000</destination>
        <encoder class="net.logstash.logback.encoder.LogstashEncoder">
            <includeMdc>true</includeMdc>
            <includeContext>true</includeContext>
            <includeTags>true</includeTags>
        </encoder>
    </appender>

    <root level="INFO">
        <appender-ref ref="LOGSTASH"/>
    </root>
</configuration>
```

**Access Kibana**: http://localhost:5601

**Create Index Pattern**: oauth-idp-logs-*

**Search logs**:
```
level:ERROR AND message:*authentication*
user_id:123 AND event_type:LOGIN
```

---

## Step 6: Health Checks and Readiness Probes

### Custom Health Indicators

```java
@Component
public class DatabaseHealthIndicator implements HealthIndicator {

    @Autowired
    private DataSource dataSource;

    @Override
    public Health health() {
        try (Connection conn = dataSource.getConnection()) {
            if (conn.isValid(1)) {
                return Health.up()
                    .withDetail("database", "PostgreSQL")
                    .withDetail("validationQuery", "SELECT 1")
                    .build();
            }
        } catch (Exception e) {
            return Health.down()
                .withDetail("error", e.getMessage())
                .build();
        }
        return Health.down().build();
    }
}

@Component
public class RedisHealthIndicator implements HealthIndicator {

    @Autowired
    private RedisTemplate<String, String> redisTemplate;

    @Override
    public Health health() {
        try {
            String pong = redisTemplate.getConnectionFactory()
                .getConnection()
                .ping();

            if ("PONG".equals(pong)) {
                return Health.up()
                    .withDetail("redis", "Connected")
                    .build();
            }
        } catch (Exception e) {
            return Health.down()
                .withDetail("error", e.getMessage())
                .build();
        }
        return Health.down().build();
    }
}
```

### Kubernetes Probes

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oauth-idp
spec:
  template:
    spec:
      containers:
      - name: oauth-idp
        image: oauth-idp:latest
        ports:
        - containerPort: 8080

        # Liveness probe - restart if unhealthy
        livenessProbe:
          httpGet:
            path: /actuator/health/liveness
            port: 8080
          initialDelaySeconds: 60
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3

        # Readiness probe - remove from load balancer if not ready
        readinessProbe:
          httpGet:
            path: /actuator/health/readiness
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 3
```

---

## Step 7: Alerting with Prometheus AlertManager

### Install AlertManager

```bash
docker run -d \
  --name alertmanager \
  -p 9093:9093 \
  -v $(pwd)/alertmanager.yml:/etc/alertmanager/alertmanager.yml \
  prom/alertmanager
```

### Configure Alerts

`prometheus_alerts.yml`:
```yaml
groups:
  - name: oauth-idp-alerts
    interval: 30s
    rules:
      # High error rate
      - alert: HighLoginFailureRate
        expr: rate(oauth_login_failure_total[5m]) > 10
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High login failure rate detected"
          description: "Login failure rate is {{ $value }} per second"

      # Latency SLO breach
      - alert: HighAuthorizationLatency
        expr: histogram_quantile(0.95, rate(oauth_authorization_duration_bucket[5m])) > 0.5
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Authorization latency SLO breach"
          description: "P95 latency is {{ $value }} seconds (SLO: <0.5s)"

      # Service down
      - alert: ServiceDown
        expr: up{job="oauth-idp"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "OAuth IdP is down"
          description: "The OAuth IdP service has been down for more than 1 minute"

      # Database connection pool exhausted
      - alert: ConnectionPoolExhausted
        expr: hikaricp_connections_pending > 5
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Database connection pool under pressure"
          description: "{{ $value }} connections waiting for pool"
```

### Configure Notifications

`alertmanager.yml`:
```yaml
global:
  resolve_timeout: 5m

route:
  group_by: ['alertname']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'email-notifications'

receivers:
  - name: 'email-notifications'
    email_configs:
      - to: 'ops-team@example.com'
        from: 'alertmanager@example.com'
        smarthost: smtp.gmail.com:587
        auth_username: 'alerts@example.com'
        auth_password: 'password'

  - name: 'slack-notifications'
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK'
        channel: '#oauth-alerts'
        title: 'OAuth IdP Alert'
        text: '{{ range .Alerts }}{{ .Annotations.description }}{{ end }}'
```

---

## Step 8: SLO/SLI Monitoring

### Define SLOs

**Service Level Indicators (SLIs)**:
- Availability: % of successful requests
- Latency: % of requests under threshold
- Quality: % of requests without errors

**Service Level Objectives (SLOs)**:
- 99.9% availability (8.76 hours downtime/year)
- 95% of requests < 200ms
- Error rate < 0.1%

### Track SLIs

```promql
# Availability SLI
sum(rate(http_server_requests_seconds_count{status=~"2.."}[30d]))
/
sum(rate(http_server_requests_seconds_count[30d]))

# Latency SLI
sum(rate(http_server_requests_seconds_bucket{le="0.2"}[30d]))
/
sum(rate(http_server_requests_seconds_count[30d]))

# Error budget
1 - ((1 - 0.999) - (1 - availability_sli))
```

**Error Budget**: If SLO is 99.9%, you have 0.1% error budget (43.8 minutes/month)

---

## What You've Accomplished

✅ Exposed Prometheus metrics
✅ Created Grafana dashboards
✅ Implemented distributed tracing
✅ Set up ELK stack for logging
✅ Added custom health checks
✅ Configured alerting rules
✅ Defined and tracked SLOs
✅ Built production-ready observability

---

## Next Steps

**Proceed to Guide 41**: Multi-Tenancy

Before moving on:
- [ ] Prometheus scraping metrics
- [ ] Grafana dashboard showing key metrics
- [ ] Distributed tracing working
- [ ] Logs flowing to ELK
- [ ] Health checks passing
- [ ] Alerts configured

---

## Key Concepts Learned

### The Four Golden Signals

1. **Latency**: Time to service requests
2. **Traffic**: Demand on the system
3. **Errors**: Rate of failed requests
4. **Saturation**: Resource utilization

### RED Method (for services)

- **Rate**: Requests per second
- **Errors**: Failed requests per second
- **Duration**: Latency distribution

### USE Method (for resources)

- **Utilization**: % time resource busy
- **Saturation**: Queue length
- **Errors**: Error count

---

## Additional Resources

- **Prometheus**: https://prometheus.io/docs/
- **Grafana**: https://grafana.com/docs/
- **OpenTelemetry**: https://opentelemetry.io/docs/
- **Jaeger**: https://www.jaegertracing.io/docs/
- **ELK Stack**: https://www.elastic.co/guide/
- **Google SRE Book**: https://sre.google/sre-book/monitoring-distributed-systems/
- **Micrometer**: https://micrometer.io/docs
