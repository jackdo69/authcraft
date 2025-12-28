# Guide 01: Set Up Project Structure

**Phase 1: Foundation** | **Week 1-2** | **Task 1 of 5**

## Overview

Create the initial Spring Boot project for the Identity Provider using Spring Initializr and Maven. This establishes the foundation with proper dependencies and project structure.

---

## What You'll Build

A Spring Boot application skeleton with:
- Maven project structure
- Core Spring Boot dependencies
- Spring Security framework
- Database connectivity (JPA/Hibernate)
- Web framework
- Development tools

---

## Why Start Here?

Before writing any authentication code, you need a properly configured Spring Boot application. Spring Boot follows "convention over configuration" - the project structure and dependencies determine how features work together.

---

## Step 1: Generate Project with Spring Initializr

### Use Spring Initializr Web Tool

1. **Visit**: https://start.spring.io/

2. **Project Settings**:
   - **Project**: Maven (not Gradle)
     - *Why*: Maven is more common in enterprise environments and has simpler XML-based configuration
   - **Language**: Java
   - **Spring Boot**: 3.2.x (select latest stable 3.2 version)
     - *Why*: Version 3.x requires Java 17+ and includes Spring Security 6.x which we need
   - **Packaging**: Jar
     - *Why*: Creates an executable JAR file that includes an embedded Tomcat server
   - **Java**: 17

3. **Project Metadata**:
   - **Group**: `com.learning`
     - *Why*: Standard reverse-domain naming convention for Java packages
   - **Artifact**: `identity-provider`
     - *Why*: This becomes your project name and JAR filename
   - **Name**: `identity-provider`
   - **Description**: OAuth 2.0 Identity Provider Learning Project
   - **Package name**: `com.learning.idp`
     - *Why*: The base package for all your Java classes

### Why These Settings Matter
- **Group + Artifact**: Creates unique coordinates for your project (like `@scope/package-name` in npm)
- **Package name**: Determines the folder structure under `src/main/java/`

---

## Step 2: Add Dependencies

Click "Add Dependencies" and search for these:

### Core Web Framework
- **Spring Web**
  - *Why*: Provides REST endpoints, MVC support, and embedded Tomcat server (like Express.js in Node)

### Security
- **Spring Security**
  - *Why*: Core security framework for authentication and authorization
- **OAuth2 Authorization Server** (search for "authorization")
  - *Why*: Official Spring implementation of OAuth 2.0 and OpenID Connect specifications

### Database
- **Spring Data JPA**
  - *Why*: ORM framework for database operations (similar to TypeORM or Prisma)
- **PostgreSQL Driver**
  - *Why*: JDBC driver to connect to PostgreSQL database
- **Flyway Migration** or **Liquibase**
  - *Why*: Manages database schema versions (like Prisma migrations)

### Caching & Session
- **Spring Data Redis**
  - *Why*: Stores user sessions and caching tokens in Redis

### Template Engine
- **Thymeleaf**
  - *Why*: Server-side HTML templates for login/consent pages (like EJS or Handlebars)

### Validation
- **Validation** (Spring Boot Starter Validation)
  - *Why*: Validates request data with annotations (like `class-validator` in TypeScript)

### Development Tools
- **Spring Boot DevTools**
  - *Why*: Enables hot reload during development (like nodemon)
- **Lombok**
  - *Why*: Reduces boilerplate code with annotations (generates getters, setters, constructors)

---

## Step 3: Generate and Download

1. Click **"Generate"** button (Ctrl/Cmd + Enter)
2. A ZIP file downloads: `identity-provider.zip`
3. **Extract** the ZIP into your project's `identity-provider/` folder
4. The extracted content should be INSIDE `identity-provider/`, not in a subfolder

### Expected Structure
```
authcraft/
└── identity-provider/
    ├── src/
    │   ├── main/
    │   │   ├── java/com/learning/idp/
    │   │   │   └── IdentityProviderApplication.java
    │   │   └── resources/
    │   │       ├── application.properties
    │   │       ├── static/
    │   │       └── templates/
    │   └── test/
    ├── pom.xml
    ├── mvnw (Maven wrapper script)
    └── mvnw.cmd
```

---

## Step 4: Understand the Project Structure

### Key Directories

#### `src/main/java/com/learning/idp/`
- **Your Java source code goes here**
- Main application class: `IdentityProviderApplication.java`
- Create subpackages: `config/`, `controller/`, `service/`, `model/`, `repository/`

#### `src/main/resources/`
- **Configuration files and static assets**
- `application.properties` or `application.yml`: App configuration
- `templates/`: Thymeleaf HTML templates
- `static/`: CSS, JavaScript, images

#### `src/test/java/`
- **Unit and integration tests**
- Mirrors the structure of `src/main/java/`

#### `pom.xml`
- **Maven configuration file** (like `package.json`)
- Defines dependencies, plugins, and build settings
- Maven downloads dependencies from Maven Central Repository

#### `mvnw` and `mvnw.cmd`
- **Maven Wrapper** scripts
- Allows running Maven without installing it globally (like `npx` in npm)
- Use `./mvnw` instead of `mvn` for consistency

---

## Step 5: Open Project in IntelliJ IDEA

1. **Open IntelliJ IDEA**
2. **File → Open**
3. **Navigate** to `authcraft/identity-provider/` folder
4. **Select** the folder (not the `pom.xml` file)
5. **Click "Open"**
6. IntelliJ will detect it's a Maven project and import automatically
7. **Wait** for Maven to download dependencies (may take a few minutes)

### What Happens During Import?
- IntelliJ reads `pom.xml`
- Maven downloads all dependencies to `~/.m2/repository/`
- IntelliJ indexes the code for autocomplete and navigation
- Project structure is configured automatically

---

## Step 6: Review the pom.xml

### Open `pom.xml` and understand key sections:

#### Parent Section
```xml
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.2.x</version>
</parent>
```
*Why*: Inherits default configurations and dependency versions from Spring Boot

#### Dependencies Section
- Each `<dependency>` is like a package in `package.json`
- Spring Boot "starters" are curated dependency bundles
- Example: `spring-boot-starter-web` includes Spring MVC, Tomcat, and Jackson

#### Build Plugins
```xml
<build>
    <plugins>
        <plugin>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-maven-plugin</artifactId>
        </plugin>
    </plugins>
</build>
```
*Why*: Enables running the app with `mvn spring-boot:run` and packaging as executable JAR

---

## Step 7: Add Additional Dependencies

Spring Initializr doesn't include everything you need. Open `pom.xml` and add these manually inside the `<dependencies>` section:

### JWT Library (for token generation)
You'll need to add:
- `io.jsonwebtoken:jjwt-api`
- `io.jsonwebtoken:jjwt-impl`
- `io.jsonwebtoken:jjwt-jackson`

### Apache Commons Codec (for PKCE)
- `commons-codec:commons-codec`

### Find Exact Dependencies
Visit https://mvnrepository.com/ and search for each library to get the latest versions and proper XML snippets.

**Example search**: "jjwt" → Select `io.jsonwebtoken:jjwt-api` → Copy Maven XML

---

## Step 8: Configure Application Properties

### Switch to YAML Format
Spring Boot supports both `.properties` and `.yml` formats. YAML is more readable.

1. **Rename** `src/main/resources/application.properties` to `application.yml`
2. **Delete** the contents (we'll configure it in the next guide)

*Why YAML?*: Nested structure is clearer than dot notation, especially for complex configs like database and OAuth settings.

---

## Step 9: Create Package Structure

Inside `src/main/java/com/learning/idp/`, create these packages (folders):

```
com/learning/idp/
├── config/          # Configuration classes (@Configuration)
├── controller/      # REST endpoints (@RestController, @Controller)
├── service/         # Business logic (@Service)
├── repository/      # Database access (@Repository)
├── model/          # Entity classes (@Entity)
├── security/       # Security utilities (JWT, PKCE, etc.)
└── dto/            # Data Transfer Objects
```

### Why This Structure?
This follows the **layered architecture pattern** common in Spring applications:
- **Controller**: Handles HTTP requests/responses (like Express route handlers)
- **Service**: Business logic (like service classes in NestJS)
- **Repository**: Database queries (like TypeORM repositories)
- **Model**: Database entities (like TypeORM entities)
- **Config**: Spring configuration (beans, security rules)

---

## Step 10: Run the Application

### Test the Basic Setup

1. **Open** `IdentityProviderApplication.java`
2. **Right-click** the file → "Run 'IdentityProviderApplication'"
   - *Or* click the green play button in the gutter
3. **Watch** the console output

### Expected Output
You should see:
```
  .   ____          _            __ _ _
 /\\ / ___'_ __ _ _(_)_ __  __ _ \ \ \ \
( ( )\___ | '_ | '_| | '_ \/ _` | \ \ \ \
 \\/  ___)| |_)| | | | | || (_| |  ) ) ) )
  '  |____| .__|_| |_|_| |_\__, | / / / /
 =========|_|==============|___/=/_/_/_/
 :: Spring Boot ::                (v3.2.x)

...
Started IdentityProviderApplication in X seconds
```

### What If It Fails?
- **No database configured error**: Expected! We'll configure PostgreSQL in the next guide
- **Port 8080 already in use**: Stop other services or change the port in `application.yml`

For now, the app won't fully start because the database isn't set up yet. That's normal.

---

## Step 11: Understand the Main Application Class

Open `IdentityProviderApplication.java`:

```java
@SpringBootApplication
public class IdentityProviderApplication {
    public static void main(String[] args) {
        SpringApplication.run(IdentityProviderApplication.class, args);
    }
}
```

### What This Does
- **@SpringBootApplication**: Combines three annotations:
  - `@Configuration`: Marks this as a configuration class
  - `@EnableAutoConfiguration`: Automatically configures beans based on dependencies
  - `@ComponentScan`: Scans for `@Component`, `@Service`, `@Controller`, etc.
- **main method**: Entry point that starts the embedded Tomcat server

*Why auto-configuration?*: Spring Boot detects you have Spring Security on the classpath and automatically sets up basic security. This is "convention over configuration" in action.

---

## Common Issues

### "Cannot resolve symbol" errors in IntelliJ
- **Solution**: File → Invalidate Caches → Invalidate and Restart
- **Or**: Right-click `pom.xml` → Maven → Reload Project

### Dependencies not downloading
- **Check**: Internet connection
- **Try**: `./mvnw clean install` in terminal
- **Check**: Maven settings at `~/.m2/settings.xml` for proxy configuration

### Lombok not working
- **Solution**: File → Settings → Plugins → Search "Lombok" → Install
- **Enable**: Settings → Build, Execution, Deployment → Compiler → Annotation Processors → Enable annotation processing

---

## What You've Accomplished

✅ Generated a Spring Boot project with correct dependencies
✅ Understood Maven project structure
✅ Set up proper package organization
✅ Configured development tools (Lombok, DevTools)
✅ Ran the application (even if it didn't fully start yet)

---

## Next Steps

**Proceed to Guide 02**: Configure PostgreSQL and Redis with Docker

Before moving on, ensure:
- [ ] Project opens without errors in IntelliJ
- [ ] Maven dependencies are downloaded
- [ ] Package structure is created
- [ ] Application attempts to start (database error is OK for now)

---

## Key Concepts Learned

### Spring Boot Auto-Configuration
Spring Boot automatically configures components based on:
- Dependencies in `pom.xml`
- Configuration in `application.yml`
- Annotations on classes

### Maven Dependency Management
- Dependencies are transitively included (if A needs B, and B needs C, you get all three)
- Spring Boot manages version numbers through the parent POM
- Starters bundle related dependencies together

### Package Structure Best Practices
- Organize by layer (controller, service, repository), not by feature
- Main application class should be at the root of the base package
- Subpackages are automatically component-scanned

---

## Additional Resources

- **Spring Boot Reference**: https://docs.spring.io/spring-boot/docs/current/reference/html/
- **Maven in 5 Minutes**: https://maven.apache.org/guides/getting-started/maven-in-five-minutes.html
- **Project Structure Guide**: https://www.baeldung.com/spring-boot-project-structure
- **Understanding @SpringBootApplication**: https://www.baeldung.com/spring-boot-annotations
