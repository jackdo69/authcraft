# Guide 29: API Rate Limiting

**Phase 6: Resource Server** | **Week 11-12** | **Task 29 of 30**

## Overview

Implement rate limiting to protect APIs from abuse and ensure fair resource usage across clients.

---

## What You'll Build

- Request rate limiting per client
- Redis-based distributed rate limiting
- Rate limit headers
- Different tiers for different clients

---

## Step 1: Add Bucket4j Dependency

```xml
<dependency>
    <groupId>com.github.vladimir-bukhtoyarov</groupId>
    <artifactId>bucket4j-core</artifactId>
    <version>8.0.1</version>
</dependency>
<dependency>
    <groupId>com.github.vladimir-bukhtoyarov</groupId>
    <artifactId>bucket4j-redis</artifactId>
    <version>8.0.1</version>
</dependency>
```

---

## Step 2: Create Rate Limit Interceptor

```java
@Component
public class RateLimitInterceptor implements HandlerInterceptor {
    
    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();
    
    @Override
    public boolean preHandle(HttpServletRequest request, 
                             HttpServletResponse response,
                             Object handler) {
        
        String clientId = extractClientId(request);
        
        Bucket bucket = buckets.computeIfAbsent(clientId, this::createBucket);
        
        if (bucket.tryConsume(1)) {
            // Request allowed
            addRateLimitHeaders(response, bucket);
            return true;
        } else {
            // Rate limit exceeded
            response.setStatus(429);
            response.addHeader("X-RateLimit-Retry-After", "60");
            return false;
        }
    }
    
    private Bucket createBucket(String clientId) {
        Bandwidth limit = Bandwidth.classic(100, Refill.intervally(100, Duration.ofMinutes(1)));
        return Bucket.builder()
            .addLimit(limit)
            .build();
    }
    
    private void addRateLimitHeaders(HttpServletResponse response, Bucket bucket) {
        response.addHeader("X-RateLimit-Limit", "100");
        response.addHeader("X-RateLimit-Remaining", 
            String.valueOf(bucket.getAvailableTokens()));
    }
    
    private String extractClientId(HttpServletRequest request) {
        // Extract from JWT or API key
        String token = request.getHeader("Authorization");
        if (token != null) {
            Jwt jwt = jwtDecoder.decode(token.replace("Bearer ", ""));
            return jwt.getClaimAsString("client_id");
        }
        return request.getRemoteAddr(); // Fallback to IP
    }
}
```

---

## Step 3: Register Interceptor

```java
@Configuration
public class WebConfig implements WebMvcConfigurer {
    
    @Autowired
    private RateLimitInterceptor rateLimitInterceptor;
    
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(rateLimitInterceptor)
            .addPathPatterns("/api/**");
    }
}
```

---

## Step 4: Different Tiers

```java
private Bucket createBucket(String clientId) {
    ClientTier tier = getTierForClient(clientId);
    
    return switch (tier) {
        case FREE -> Bucket.builder()
            .addLimit(Bandwidth.classic(10, Refill.intervally(10, Duration.ofMinutes(1))))
            .build();
        case PREMIUM -> Bucket.builder()
            .addLimit(Bandwidth.classic(1000, Refill.intervally(1000, Duration.ofMinutes(1))))
            .build();
        case ENTERPRISE -> Bucket.builder()
            .addLimit(Bandwidth.classic(10000, Refill.intervally(10000, Duration.ofMinutes(1))))
            .build();
    };
}
```

---

## Key Concepts

- **Token Bucket**: Algorithm for rate limiting
- **Distributed**: Redis-backed for multiple servers
- **Headers**: Communicate limits to clients
- **Tiers**: Different limits for different clients

---

## Resources

- **Bucket4j**: https://bucket4j.com/
- **Rate Limiting Patterns**: https://www.baeldung.com/spring-bucket4j
