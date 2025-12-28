# Guide 42: GraphQL API for OAuth IdP

**Advanced Topics** | **Task 42 of 45**

## Overview

Add a GraphQL API to your OAuth IdP for flexible data querying and mutations. Provide developers with a modern alternative to REST for managing users, clients, and authorization data with fine-grained control.

---

## What You'll Build

- GraphQL schema for users, clients, and tokens
- Queries and mutations
- GraphQL authentication/authorization
- Subscription support (real-time updates)
- DataLoader for N+1 query prevention
- GraphQL Playground
- Query complexity analysis
- Rate limiting for GraphQL

---

## Why GraphQL?

### Advantages Over REST

**Flexible Queries**: Clients request exactly the data they need
**Single Endpoint**: `/graphql` instead of many REST endpoints
**Strong Typing**: Schema-first with type safety
**Real-time**: Subscriptions for live updates
**Developer Experience**: GraphQL Playground for testing

### Use Cases

- **Admin Dashboard**: Complex queries with nested data
- **Mobile Apps**: Reduce bandwidth by fetching only needed fields
- **Third-Party Integrations**: Flexible API for partners

**Learn More**: https://graphql.org/learn/

---

## Step 1: Add GraphQL Dependencies

### Maven Dependencies

```xml
<dependencies>
    <!-- GraphQL Spring Boot Starter -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-graphql</artifactId>
    </dependency>

    <!-- GraphQL extended scalars (DateTime, etc.) -->
    <dependency>
        <groupId>com.graphql-java</groupId>
        <artifactId>graphql-java-extended-scalars</artifactId>
        <version>20.2</version>
    </dependency>

    <!-- For subscriptions -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-websocket</artifactId>
    </dependency>
</dependencies>
```

---

## Step 2: Define GraphQL Schema

### Create Schema File

`src/main/resources/graphql/schema.graphqls`:

```graphql
scalar DateTime
scalar JSON

type Query {
    # Users
    user(id: ID!): User
    users(page: Int, size: Int, filter: UserFilter): UserConnection!
    me: User

    # OAuth Clients
    client(id: ID!): OAuthClient
    clients(page: Int, size: Int): OAuthClientConnection!

    # Tokens
    activeTokens(userId: ID!): [AccessToken!]!

    # Audit logs
    auditLogs(userId: ID, page: Int, size: Int): AuditLogConnection!
}

type Mutation {
    # User management
    createUser(input: CreateUserInput!): User!
    updateUser(id: ID!, input: UpdateUserInput!): User!
    deleteUser(id: ID!): Boolean!
    changePassword(oldPassword: String!, newPassword: String!): Boolean!

    # OAuth Client management
    createClient(input: CreateClientInput!): OAuthClient!
    updateClient(id: ID!, input: UpdateClientInput!): OAuthClient!
    deleteClient(id: ID!): Boolean!
    rotateClientSecret(id: ID!): OAuthClient!

    # Token management
    revokeToken(tokenId: ID!): Boolean!
    revokeAllUserTokens(userId: ID!): Int!
}

type Subscription {
    userCreated: User!
    loginEvent(userId: ID!): LoginEvent!
}

# User types
type User {
    id: ID!
    email: String!
    firstName: String
    lastName: String
    enabled: Boolean!
    createdAt: DateTime!
    lastLoginAt: DateTime
    role: String!

    # Nested data
    clients: [OAuthClient!]!
    sessions: [UserSession!]!
    auditLogs(limit: Int): [AuditLog!]!
}

type UserConnection {
    edges: [UserEdge!]!
    pageInfo: PageInfo!
    totalCount: Int!
}

type UserEdge {
    node: User!
    cursor: String!
}

# OAuth Client types
type OAuthClient {
    id: ID!
    clientId: String!
    name: String!
    redirectUris: [String!]!
    scopes: [String!]!
    grantTypes: [String!]!
    createdAt: DateTime!

    # Nested data
    owner: User!
    activeTokens: Int!
}

type OAuthClientConnection {
    edges: [OAuthClientEdge!]!
    pageInfo: PageInfo!
}

type OAuthClientEdge {
    node: OAuthClient!
    cursor: String!
}

# Token types
type AccessToken {
    id: ID!
    tokenValue: String!  # Masked for security
    scopes: [String!]!
    expiresAt: DateTime!
    createdAt: DateTime!
    client: OAuthClient!
}

# Audit types
type AuditLog {
    id: ID!
    eventType: String!
    eventCategory: String!
    result: String!
    ipAddress: String
    createdAt: DateTime!
    eventData: JSON
}

type AuditLogConnection {
    edges: [AuditLogEdge!]!
    pageInfo: PageInfo!
}

type AuditLogEdge {
    node: AuditLog!
}

# Session types
type UserSession {
    id: String!
    ipAddress: String!
    userAgent: String!
    lastAccessedAt: DateTime!
}

# Subscription types
type LoginEvent {
    userId: ID!
    success: Boolean!
    ipAddress: String!
    timestamp: DateTime!
}

# Input types
input UserFilter {
    email: String
    enabled: Boolean
    role: String
}

input CreateUserInput {
    email: String!
    password: String!
    firstName: String
    lastName: String
    role: String
}

input UpdateUserInput {
    firstName: String
    lastName: String
    enabled: Boolean
}

input CreateClientInput {
    name: String!
    redirectUris: [String!]!
    scopes: [String!]!
    grantTypes: [String!]!
}

input UpdateClientInput {
    name: String
    redirectUris: [String!]
    scopes: [String!]
}

# Pagination
type PageInfo {
    hasNextPage: Boolean!
    hasPreviousPage: Boolean!
    startCursor: String
    endCursor: String
}
```

---

## Step 3: Implement GraphQL Resolvers

### User Queries

```java
@Controller
public class UserGraphQLController {

    @Autowired
    private UserService userService;

    @QueryMapping
    public User user(@Argument Long id) {
        return userService.findById(id)
            .orElseThrow(() -> new UserNotFoundException(id));
    }

    @QueryMapping
    public UserConnection users(
        @Argument Integer page,
        @Argument Integer size,
        @Argument UserFilter filter
    ) {
        Pageable pageable = PageRequest.of(
            page != null ? page : 0,
            size != null ? size : 20
        );

        Page<User> userPage = userService.findAll(filter, pageable);

        return UserConnection.from(userPage);
    }

    @QueryMapping
    public User me(@ContextValue Authentication authentication) {
        return (User) authentication.getPrincipal();
    }

    @MutationMapping
    @PreAuthorize("hasRole('ADMIN')")
    public User createUser(@Argument CreateUserInput input) {
        User user = new User();
        user.setEmail(input.getEmail());
        user.setPassword(passwordEncoder.encode(input.getPassword()));
        user.setFirstName(input.getFirstName());
        user.setLastName(input.getLastName());
        user.setRole(input.getRole());
        user.setEnabled(true);

        return userService.save(user);
    }

    @MutationMapping
    @PreAuthorize("hasRole('ADMIN') or #id == authentication.principal.id")
    public User updateUser(@Argument Long id, @Argument UpdateUserInput input) {
        User user = userService.findById(id)
            .orElseThrow(() -> new UserNotFoundException(id));

        if (input.getFirstName() != null) {
            user.setFirstName(input.getFirstName());
        }
        if (input.getLastName() != null) {
            user.setLastName(input.getLastName());
        }
        if (input.getEnabled() != null) {
            user.setEnabled(input.getEnabled());
        }

        return userService.save(user);
    }

    @MutationMapping
    @PreAuthorize("hasRole('ADMIN')")
    public Boolean deleteUser(@Argument Long id) {
        userService.deleteById(id);
        return true;
    }
}
```

### Nested Field Resolvers

```java
@Controller
public class UserFieldResolver {

    @Autowired
    private OAuthClientService clientService;

    @Autowired
    private SessionService sessionService;

    @Autowired
    private AuditService auditService;

    @SchemaMapping(typeName = "User", field = "clients")
    public List<OAuthClient> clients(User user) {
        return clientService.findByOwnerId(user.getId());
    }

    @SchemaMapping(typeName = "User", field = "sessions")
    public List<UserSession> sessions(User user) {
        return sessionService.getActiveSessions(user.getId());
    }

    @SchemaMapping(typeName = "User", field = "auditLogs")
    public List<AuditLog> auditLogs(User user, @Argument Integer limit) {
        return auditService.findByUserId(
            user.getId(),
            PageRequest.of(0, limit != null ? limit : 10)
        );
    }
}
```

---

## Step 4: Implement DataLoader (N+1 Prevention)

### DataLoader Configuration

```java
@Configuration
public class DataLoaderConfiguration {

    @Bean
    public DataLoaderRegistry dataLoaderRegistry(
        UserService userService,
        OAuthClientService clientService
    ) {
        DataLoaderRegistry registry = new DataLoaderRegistry();

        // User DataLoader
        BatchLoader<Long, User> userBatchLoader = userIds ->
            CompletableFuture.supplyAsync(() ->
                userService.findAllById(userIds)
            );

        registry.register("userLoader",
            DataLoaderFactory.newDataLoader(userBatchLoader));

        // OAuth Client DataLoader
        BatchLoader<Long, List<OAuthClient>> clientBatchLoader = userIds ->
            CompletableFuture.supplyAsync(() ->
                clientService.findByOwnerIds(userIds)
            );

        registry.register("clientLoader",
            DataLoaderFactory.newMappedDataLoader(clientBatchLoader));

        return registry;
    }
}
```

### Use DataLoader

```java
@SchemaMapping(typeName = "AccessToken", field = "client")
public CompletableFuture<OAuthClient> client(
    AccessToken token,
    DataLoader<Long, OAuthClient> clientLoader
) {
    return clientLoader.load(token.getClientId());
}
```

**Why DataLoader?**: Batches multiple database queries into one (e.g., loading users for 100 tokens becomes 1 query instead of 100)

---

## Step 5: Add Authentication to GraphQL

### GraphQL Security Config

```java
@Configuration
public class GraphQLSecurityConfig {

    @Bean
    public GraphQlSourceBuilderCustomizer graphQlSourceBuilderCustomizer() {
        return builder -> builder.configureRuntimeWiring(wiringBuilder ->
            wiringBuilder.directiveWiring(new AuthDirectiveWiring())
        );
    }
}
```

### Custom @auth Directive

Schema:
```graphql
directive @auth(requires: Role = USER) on OBJECT | FIELD_DEFINITION

enum Role {
    USER
    ADMIN
}

type Query {
    adminOnlyQuery: String @auth(requires: ADMIN)
}
```

Implementation:
```java
public class AuthDirectiveWiring implements SchemaDirectiveWiring {

    @Override
    public GraphQLFieldDefinition onField(SchemaDirectiveWiringEnvironment<GraphQLFieldDefinition> environment) {
        GraphQLFieldDefinition field = environment.getElement();
        GraphQLFieldsContainer parentType = environment.getFieldsContainer();

        DataFetcher<?> originalFetcher = environment.getCodeRegistry().getDataFetcher(parentType, field);

        DataFetcher<?> authFetcher = (DataFetchingEnvironment dfe) -> {
            Authentication auth = dfe.getGraphQlContext().get("authentication");

            if (auth == null || !auth.isAuthenticated()) {
                throw new UnauthorizedException("Not authenticated");
            }

            String requiredRole = environment.getDirective("auth")
                .getArgument("requires")
                .getValue();

            boolean hasRole = auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_" + requiredRole));

            if (!hasRole) {
                throw new ForbiddenException("Insufficient permissions");
            }

            return originalFetcher.get(dfe);
        };

        environment.getCodeRegistry().dataFetcher(parentType, field, authFetcher);

        return field;
    }
}
```

---

## Step 6: Implement GraphQL Subscriptions

### Subscription Resolver

```java
@Controller
public class SubscriptionController {

    @Autowired
    private ApplicationEventPublisher eventPublisher;

    @SubscriptionMapping
    public Flux<User> userCreated() {
        return Flux.create(sink -> {
            ApplicationListener<UserCreatedEvent> listener = event -> {
                sink.next(event.getUser());
            };

            eventPublisher.addApplicationListener(listener);

            sink.onDispose(() ->
                eventPublisher.removeApplicationListener(listener)
            );
        });
    }

    @SubscriptionMapping
    public Flux<LoginEvent> loginEvent(@Argument Long userId) {
        return Flux.create(sink -> {
            ApplicationListener<LoginEvent> listener = event -> {
                if (event.getUserId().equals(userId)) {
                    sink.next(event);
                }
            };

            eventPublisher.addApplicationListener(listener);
            sink.onDispose(() -> eventPublisher.removeApplicationListener(listener));
        });
    }
}
```

### Publish Events

```java
@Service
public class UserService {

    @Autowired
    private ApplicationEventPublisher eventPublisher;

    public User createUser(User user) {
        User saved = userRepository.save(user);

        // Publish event for subscription
        eventPublisher.publishEvent(new UserCreatedEvent(saved));

        return saved;
    }
}
```

### Client Subscription

```graphql
subscription {
    userCreated {
        id
        email
        createdAt
    }
}
```

---

## Step 7: Query Complexity Analysis

### Prevent Expensive Queries

```java
@Configuration
public class GraphQLComplexityConfig {

    @Bean
    public GraphQlSourceBuilderCustomizer complexityAnalyzer() {
        return builder -> builder.configureGraphQl(graphQlBuilder -> {
            FieldComplexityCalculator complexityCalculator =
                (env, childComplexity) -> {
                    if (env.getFieldDefinition().getName().equals("users")) {
                        Object sizeArg = env.getArgument("size");
                        int size = sizeArg != null ? (int) sizeArg : 20;
                        return size * childComplexity;
                    }
                    return 1 + childComplexity;
                };

            MaxQueryComplexityInstrumentation instrumentation =
                new MaxQueryComplexityInstrumentation(1000, complexityCalculator);

            graphQlBuilder.instrumentation(instrumentation);
        });
    }
}
```

**Max Complexity**: Reject queries exceeding threshold (e.g., fetching 1000 users with 100 nested fields each)

---

## Step 8: GraphQL Rate Limiting

### Per-Field Rate Limiting

```java
@Component
public class GraphQLRateLimitInstrumentation extends SimpleInstrumentation {

    private final RateLimiter rateLimiter;

    @Override
    public InstrumentationContext<ExecutionResult> beginExecutionStrategy(
        InstrumentationExecutionStrategyParameters parameters
    ) {
        String operation = parameters.getExecutionContext()
            .getOperationDefinition()
            .getOperation()
            .name();

        if (!rateLimiter.tryAcquire(operation)) {
            throw new RateLimitExceededException("Rate limit exceeded for " + operation);
        }

        return super.beginExecutionStrategy(parameters);
    }
}
```

---

## Step 9: GraphQL Playground

### Enable Playground

`application.yml`:
```yaml
spring:
  graphql:
    graphiql:
      enabled: true
      path: /graphiql

    # CORS for GraphQL
    cors:
      allowed-origins: "*"
      allowed-methods: GET, POST
      allowed-headers: "*"
```

**Access**: http://localhost:8080/graphiql

### Example Queries

```graphql
# Query with nested data
query GetUserWithClients {
    user(id: 1) {
        id
        email
        firstName
        lastName
        clients {
            id
            name
            redirectUris
        }
        sessions {
            id
            ipAddress
            lastAccessedAt
        }
    }
}

# Filtered pagination
query ListUsers {
    users(page: 0, size: 10, filter: { enabled: true }) {
        edges {
            node {
                id
                email
                lastLoginAt
            }
            cursor
        }
        pageInfo {
            hasNextPage
            endCursor
        }
        totalCount
    }
}

# Mutation
mutation CreateNewUser {
    createUser(input: {
        email: "newuser@example.com"
        password: "password123"
        firstName: "John"
        lastName: "Doe"
        role: "USER"
    }) {
        id
        email
        createdAt
    }
}

# Revoke tokens
mutation RevokeUserTokens {
    revokeAllUserTokens(userId: 1)
}
```

---

## Common Issues

### N+1 Query Problem

**Problem**: Fetching 100 users, each with clients = 101 database queries

**Solution**: Use DataLoader (batches into 2 queries)

### Query Too Complex

**Problem**: Client requests deeply nested data causing timeout

**Solution**: Implement query complexity analysis and set max depth

### Authentication Not Working

**Problem**: GraphQL queries bypass Spring Security

**Solution**: Add GraphQL context with Authentication:
```java
@Bean
public GraphQlContextBuilderCustomizer contextCustomizer() {
    return (builder, request) -> {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        builder.put("authentication", auth);
    };
}
```

---

## What You've Accomplished

✅ Defined comprehensive GraphQL schema
✅ Implemented queries and mutations
✅ Added nested field resolvers
✅ Prevented N+1 queries with DataLoader
✅ Secured GraphQL with authentication
✅ Implemented real-time subscriptions
✅ Added query complexity analysis
✅ Enabled GraphQL Playground

---

## Next Steps

**Proceed to Guide 43**: Mobile App Integration

Before moving on:
- [ ] GraphQL schema defined
- [ ] Queries and mutations working
- [ ] DataLoader preventing N+1 queries
- [ ] Authentication enforced
- [ ] GraphQL Playground accessible
- [ ] Subscriptions working

---

## Key Concepts Learned

### GraphQL vs REST

| Feature | GraphQL | REST |
|---------|---------|------|
| Endpoints | Single `/graphql` | Multiple (`/users`, `/clients`) |
| Data Fetching | Client specifies fields | Server decides response |
| Versioning | Schema evolution | URL versioning (v1, v2) |
| Real-time | Subscriptions | WebSockets/SSE |

### GraphQL Best Practices

- **Schema-First**: Define schema before implementation
- **Pagination**: Use cursor-based pagination
- **DataLoader**: Batch database queries
- **Complexity**: Limit query depth and cost
- **Security**: Authenticate and authorize per field

---

## Additional Resources

- **GraphQL Specification**: https://spec.graphql.org/
- **Spring for GraphQL**: https://spring.io/projects/spring-graphql
- **GraphQL Java**: https://www.graphql-java.com/
- **DataLoader**: https://github.com/graphql-java/java-dataloader
- **GraphQL Best Practices**: https://graphql.org/learn/best-practices/
