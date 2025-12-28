# Guide 20: Error Handling and User Feedback

**Phase 4: User Experience** | **Week 7-8** | **Task 20 of 30**

## Overview

Implement comprehensive error handling with user-friendly messages, proper HTTP status codes, and detailed logging for debugging.

---

## What You'll Build

- Global exception handlers
- Custom error pages
- OAuth error responses
- Structured logging
- User-friendly error messages

---

## Step 1: Create Exception Hierarchy

```java
public class OAuthException extends RuntimeException {
    private final String error;
    private final String errorDescription;
    private final int httpStatus;
}

public class InvalidGrantException extends OAuthException {
    public InvalidGrantException(String description) {
        super("invalid_grant", description, 400);
    }
}
```

---

## Step 2: Global Exception Handler

```java
@RestControllerAdvice
public class OAuth2ExceptionHandler {
    
    @ExceptionHandler(OAuthException.class)
    public ResponseEntity<OAuth2ErrorResponse> handleOAuthException(OAuthException ex) {
        
        // Log for debugging (don't expose to user)
        log.error("OAuth error: {}", ex.getError(), ex);
        
        OAuth2ErrorResponse response = OAuth2ErrorResponse.builder()
            .error(ex.getError())
            .errorDescription(ex.getErrorDescription())
            .build();
        
        return ResponseEntity
            .status(ex.getHttpStatus())
            .body(response);
    }
    
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGenericException(Exception ex) {
        log.error("Unexpected error", ex);
        
        return ResponseEntity
            .status(500)
            .body(new ErrorResponse("server_error", "An unexpected error occurred"));
    }
}
```

---

## Step 3: Custom Error Pages

Create templates for common errors:

```html
<!-- error/404.html -->
<!DOCTYPE html>
<html>
<head><title>Page Not Found</title></head>
<body>
    <h1>404 - Page Not Found</h1>
    <p>The page you're looking for doesn't exist.</p>
    <a href="/">Go Home</a>
</body>
</html>
```

Configure error controller:
```java
@Controller
public class CustomErrorController implements ErrorController {
    
    @RequestMapping("/error")
    public String handleError(HttpServletRequest request, Model model) {
        Integer statusCode = (Integer) request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        
        if (statusCode == 404) {
            return "error/404";
        } else if (statusCode == 403) {
            return "error/403";
        }
        
        return "error/generic";
    }
}
```

---

## Step 4: Structured Logging

```java
@Aspect
@Component
public class LoggingAspect {
    
    @Around("@annotation(org.springframework.web.bind.annotation.PostMapping)")
    public Object logAround(ProceedingJoinPoint joinPoint) throws Throwable {
        
        MDC.put("requestId", UUID.randomUUID().toString());
        
        try {
            Object result = joinPoint.proceed();
            log.info("Request completed successfully");
            return result;
        } catch (Exception e) {
            log.error("Request failed", e);
            throw e;
        } finally {
            MDC.clear();
        }
    }
}
```

---

## Step 5: User-Friendly Messages

Map technical errors to user messages:

```java
public class ErrorMessageMapper {
    
    private static final Map<String, String> MESSAGES = Map.of(
        "invalid_grant", "The authorization code is invalid or has expired. Please try again.",
        "invalid_client", "Application authentication failed. Please contact support.",
        "access_denied", "You denied access to this application.",
        "invalid_scope", "The requested permissions are not available."
    );
    
    public static String getUserMessage(String errorCode) {
        return MESSAGES.getOrDefault(errorCode, "An error occurred. Please try again.");
    }
}
```

---

## Key Concepts

- **OAuth Error Codes**: Standard error responses per RFC 6749
- **HTTP Status Codes**: Proper codes for different error types
- **User vs Developer Errors**: Different detail levels
- **Logging**: Structured, searchable, contextual

---

## Resources

- **OAuth Error Responses**: https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
- **Spring Error Handling**: https://www.baeldung.com/exception-handling-for-rest-with-spring
- **Structured Logging**: https://www.baeldung.com/mdc-in-log4j-2-logback
