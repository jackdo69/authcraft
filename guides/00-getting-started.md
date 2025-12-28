# Guide 00: Getting Started - Environment Setup

## Overview

Before building the OAuth 2.0 Identity Provider, you need to set up your development environment with Java, Maven, Docker, and an IDE. This guide covers installing all necessary tools and creating the initial project structure.

---

## Prerequisites Check

### What You Need
- **MacOS/Linux/Windows** with administrator access
- **8GB RAM minimum** (16GB recommended for running multiple services)
- **10GB free disk space** for tools, dependencies, and databases
- **Stable internet connection** for downloading dependencies

### Time Estimate
- Initial setup: 1-2 hours
- Verification: 30 minutes

---

## Step 1: Install Java Development Kit (JDK)

### What to Install
**Java 17 or higher** (LTS version recommended)

### Why Java 17?
Spring Boot 3.2+ requires Java 17 minimum. This version includes modern features like records, pattern matching, and improved garbage collection that make development more productive.

### Installation Options

#### Option 1: SDKMAN (Recommended for Mac/Linux)
**Why SDKMAN?** Allows you to easily switch between Java versions, similar to `nvm` for Node.js.

- **Install SDKMAN**: https://sdkman.io/install
- **Command**: After installing SDKMAN, run `sdk install java 17.0.9-tem` (Temurin distribution)
- **Verify**: Run `java -version` - should show Java 17.x.x

#### Option 2: Official Distributions
- **Eclipse Temurin** (recommended): https://adoptium.net/
- **Oracle JDK**: https://www.oracle.com/java/technologies/downloads/
- **Amazon Corretto**: https://aws.amazon.com/corretto/

### What to Verify
After installation, run these commands:
```bash
java -version    # Should show 17.x.x or higher
javac -version   # Java compiler should match
```

### TypeScript Background Note
Think of the JDK as similar to installing Node.js - it includes the runtime (`java`) and compiler (`javac`). Unlike JavaScript, Java code must be compiled before running.

**Learn More**:
- [What is JDK vs JRE?](https://www.baeldung.com/jvm-vs-jre-vs-jdk)

---

## Step 2: Install Apache Maven

### What to Install
**Maven 3.9+** - Build automation and dependency management tool

### Why Maven?
Maven manages dependencies (like `npm`/`package.json` in Node.js), builds your project, and runs tests. Java projects use XML (`pom.xml`) instead of JSON for configuration.

### Installation Options

#### Option 1: SDKMAN (Recommended for Mac/Linux)
- **Command**: `sdk install maven`
- **Verify**: `mvn -version`

#### Option 2: Package Manager
- **Mac (Homebrew)**: `brew install maven`
- **Linux (Ubuntu/Debian)**: `sudo apt install maven`
- **Windows (Chocolatey)**: `choco install maven`

#### Option 3: Manual Installation
- **Download**: https://maven.apache.org/download.cgi
- **Extract** and add `bin/` directory to your `PATH`

### What to Verify
```bash
mvn -version    # Should show Maven 3.9.x and Java 17.x
```

### Key Concepts
- **`pom.xml`**: Like `package.json` - defines dependencies and build configuration
- **Maven Central**: Like npm registry - hosts Java libraries
- **Dependencies**: Automatically downloaded and cached in `~/.m2/repository`

**Learn More**:
- [Maven in 5 Minutes](https://maven.apache.org/guides/getting-started/maven-in-five-minutes.html)

---

## Step 3: Install Docker Desktop

### What to Install
**Docker Desktop** - For running PostgreSQL and Redis containers

### Why Docker?
Instead of installing PostgreSQL and Redis directly on your machine, Docker provides isolated containers. This keeps your system clean and makes it easy to reset databases during development.

### Installation
- **Download**: https://www.docker.com/products/docker-desktop/
- **Install** the application for your operating system
- **Start** Docker Desktop application
- **Verify**: Run `docker --version` and `docker compose version`

### What to Verify
```bash
docker --version           # Should show 24.x or higher
docker compose version     # Should show 2.x or higher
docker ps                  # Should run without errors
```

### Key Concepts
- **Container**: Lightweight, isolated environment (like a mini virtual machine)
- **Image**: Blueprint for a container (PostgreSQL image, Redis image)
- **docker-compose**: Runs multiple containers together with a YAML configuration file

**Learn More**:
- [Docker for Beginners](https://docker-curriculum.com/)

---

## Step 4: Install an IDE

### Recommended: IntelliJ IDEA

### Why IntelliJ IDEA?
Industry-standard IDE for Java development with excellent Spring Boot support, intelligent code completion, and built-in tools for Maven, debugging, and testing.

### Installation Options

#### Option 1: IntelliJ IDEA Community Edition (Free)
- **Download**: https://www.jetbrains.com/idea/download/
- **Features**: Sufficient for this project
- **Install**: Download and run the installer

#### Option 2: IntelliJ IDEA Ultimate (Paid/Free for Students)
- **Extra features**: Advanced Spring support, database tools, HTTP client
- **Student License**: Free with .edu email at https://www.jetbrains.com/student/

#### Alternative: Visual Studio Code
- **Download**: https://code.visualstudio.com/
- **Extensions needed**:
  - Extension Pack for Java (Microsoft)
  - Spring Boot Extension Pack (VMware)
- **Note**: Less feature-rich than IntelliJ for Java

### First-Time Setup in IntelliJ
1. **Configure JDK**: File → Project Structure → SDKs → Add JDK → Select your Java 17 installation
2. **Install Plugins**: File → Settings → Plugins → Search and install:
   - Spring Boot (usually pre-installed)
   - Lombok
3. **Enable Annotation Processing**: Settings → Build, Execution, Deployment → Compiler → Annotation Processors → Enable

### TypeScript Background Note
IntelliJ IDEA is like VSCode but specifically optimized for Java. The IDE provides stronger type checking, refactoring tools, and automatic imports compared to JavaScript/TypeScript development.

**Learn More**:
- [IntelliJ IDEA for Eclipse Users](https://www.jetbrains.com/help/idea/migrating-from-eclipse-to-intellij-idea.html)

---

## Step 5: Verify Your Environment

### Run This Checklist

```bash
# Java
java -version
# Output should include: "17.0" or higher

# Maven
mvn -version
# Output should include: "Apache Maven 3.9" and "Java version: 17"

# Docker
docker --version
docker compose version
docker ps
# All commands should run without errors

# Git (should already be installed)
git --version
```

### Test Docker Setup
Run a test container to ensure Docker works:
```bash
docker run hello-world
```

You should see a "Hello from Docker!" message. This confirms Docker can pull images and run containers.

---

## Step 6: Create Project Structure

### Directory Layout
Create the following folder structure in your project root:

```
authcraft/
├── identity-provider/       # Will create Spring Boot project here
├── resource-server/          # Will create Spring Boot project here
├── client-app/               # Will create Spring Boot project here
├── docker-compose.yml        # You'll create this for PostgreSQL + Redis
├── CLAUDE.md                 # Already exists
├── oauth-idp-learning-project.md  # Already exists
└── guides/                   # Already exists
```

### Create Directories
Run these commands from your project root:

```bash
mkdir -p identity-provider
mkdir -p resource-server
mkdir -p client-app
```

### Why Three Separate Projects?
- **identity-provider**: The OAuth2 server (this is what you're building from scratch)
- **resource-server**: A protected API that validates tokens (demonstrates OAuth in action)
- **client-app**: An application that uses OAuth to access protected resources

Each runs independently and communicates via HTTP, simulating a real-world microservices architecture.

---

## Step 7: Understanding the Development Workflow

### Coming from TypeScript
Here are key differences in the Java development workflow:

| Aspect | TypeScript/Node.js | Java/Spring Boot |
|--------|-------------------|------------------|
| **Build** | Not required | Must compile `.java` → `.class` files |
| **Dependencies** | `npm install` | `mvn clean install` |
| **Run** | `npm start` or `node index.js` | `mvn spring-boot:run` or run main class |
| **Hot Reload** | nodemon | Spring Boot DevTools (similar) |
| **Config Files** | `.json`, `.env` | `application.yml`, `application.properties` |
| **Package Manager** | npm/yarn/pnpm | Maven/Gradle |

### Maven Build Lifecycle
Common commands you'll use:
- **`mvn clean`**: Deletes previous build files
- **`mvn compile`**: Compiles source code
- **`mvn test`**: Runs tests
- **`mvn package`**: Creates JAR file
- **`mvn spring-boot:run`**: Runs Spring Boot application

---

## Step 8: Test Your Setup with a Simple Project

### Create a Hello World Spring Boot App
Use Spring Initializr to test your setup:

1. **Visit**: https://start.spring.io/
2. **Configure**:
   - Project: Maven
   - Language: Java
   - Spring Boot: 3.2.x (latest stable)
   - Java: 17
   - Dependencies: Spring Web
3. **Generate** and download the ZIP
4. **Extract** to a test folder (outside your main project)
5. **Open** in IntelliJ IDEA
6. **Run** the application (should start on port 8080)
7. **Test**: Visit `http://localhost:8080` in browser

### Why This Test?
This verifies that Java, Maven, and your IDE are properly configured before starting the actual project. If this works, you're ready to begin Phase 1.

---

## Common Installation Issues

### Java Not Found
- **Issue**: `java: command not found`
- **Solution**: Add Java to your PATH environment variable
- **Verify**: Check `echo $JAVA_HOME` (should point to JDK installation)

### Maven Not Using Correct Java Version
- **Issue**: `mvn -version` shows wrong Java version
- **Solution**: Set `JAVA_HOME` environment variable: `export JAVA_HOME=$(/usr/libexec/java_home -v 17)`

### Docker Permission Denied
- **Issue**: `permission denied while trying to connect to the Docker daemon`
- **Solution**: Ensure Docker Desktop is running, or add your user to docker group (Linux)

### Port Already in Use
- **Issue**: Application won't start due to port conflict
- **Solution**: Find and kill the process using the port: `lsof -ti:8080 | xargs kill`

---

## Next Steps

Once your environment is set up and verified:
1. **Proceed to Guide 01**: Set Up Project Structure
2. **Read**: Browse through the main project document (`oauth-idp-learning-project.md`) to understand the overall architecture
3. **Bookmark**: Keep Spring Boot documentation handy: https://docs.spring.io/spring-boot/docs/current/reference/html/

---

## Additional Resources

### Essential Bookmarks
- **Spring Initializr**: https://start.spring.io/ (generates starter projects)
- **Maven Central Repository**: https://mvnrepository.com/ (search for dependencies)
- **Spring Boot Documentation**: https://docs.spring.io/spring-boot/docs/current/reference/html/
- **Baeldung**: https://www.baeldung.com/ (excellent Java/Spring tutorials)

### Java Learning Resources (for TypeScript Developers)
- **Java for JavaScript Developers**: https://www.baeldung.com/java-for-javascript-developers
- **Spring Boot vs Express.js**: Understanding the mental model shift from Node.js frameworks

---

## Checklist

Before moving to the next guide, ensure you have:
- [ ] Java 17+ installed and verified
- [ ] Maven 3.9+ installed and verified
- [ ] Docker Desktop installed and running
- [ ] IntelliJ IDEA (or VSCode with Java extensions) installed
- [ ] Created project directory structure
- [ ] Successfully run a test Spring Boot application
- [ ] Bookmarked essential documentation

**You're ready to start building!** 🚀
