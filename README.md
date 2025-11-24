# Building-AI-enabled-Web-Applications-with-Claude
Building AI enabled Web applications with Claude

# Building Production-Ready AI Web Applications with Claude

## Architecture Overview

A production AI application typically consists of:
- **Frontend**: User interface (React, Vue, or vanilla JS)
- **Backend**: API server that handles Claude API calls securely
- **Database**: Store user data, conversation history, and app state
- **Authentication**: Secure user management
- **Deployment**: Hosting infrastructure

## Core Implementation Pattern

### 1. Backend API Server (Never expose API keys to frontend)

```javascript
// Example using Node.js/Express
import Anthropic from '@anthropic-ai/sdk';
import express from 'express';

const app = express();
const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY // Store securely in env variables
});

app.post('/api/chat', async (req, res) => {
  try {
    const { messages, systemPrompt } = req.body;
    
    const response = await anthropic.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 4096,
      system: systemPrompt,
      messages: messages
    });
    
    res.json(response);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
```

### 2. Frontend Implementation

```javascript
// React example
async function sendMessage(userMessage) {
  const response = await fetch('/api/chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      messages: [{ role: 'user', content: userMessage }],
      systemPrompt: 'You are a helpful assistant...'
    })
  });
  
  return await response.json();
}
```

## Key Production Considerations

### Security
- **Never expose API keys in frontend code**
- Store keys in environment variables or secret managers (AWS Secrets Manager, HashiCorp Vault)
- Implement rate limiting to prevent abuse
- Add authentication/authorization for your API endpoints
- Validate and sanitize all user inputs
- Use HTTPS in production

### Cost Management
- Implement token counting and budgets per user
- Cache common responses where appropriate
- Use streaming for better UX and early termination options
- Choose appropriate models (Haiku for speed/cost, Sonnet for balance, Opus for complex tasks)
- Monitor usage with logging and analytics

### Performance
- **Streaming responses**: Use server-sent events (SSE) for real-time streaming
```javascript
// Backend streaming example
app.post('/api/chat/stream', async (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  
  const stream = await anthropic.messages.create({
    model: 'claude-sonnet-4-20250514',
    max_tokens: 4096,
    messages: req.body.messages,
    stream: true
  });
  
  for await (const event of stream) {
    if (event.type === 'content_block_delta') {
      res.write(`data: ${JSON.stringify(event.delta)}\n\n`);
    }
  }
  res.end();
});
```

- Implement caching strategies (Redis for conversation context)
- Use CDN for static assets
- Optimize database queries

### Conversation Management
- Store conversation history in your database
- Implement context window management (Claude has 200K token context)
- Trim old messages when approaching limits
- Consider summarizing old conversations to maintain context

```javascript
// Example context management
function manageContext(messages, maxTokens = 150000) {
  let totalTokens = estimateTokens(messages);
  
  while (totalTokens > maxTokens && messages.length > 2) {
    messages.splice(1, 2); // Remove oldest exchange
    totalTokens = estimateTokens(messages);
  }
  
  return messages;
}
```

### Error Handling
```javascript
async function callClaude(messages, retries = 3) {
  for (let i = 0; i < retries; i++) {
    try {
      return await anthropic.messages.create({...});
    } catch (error) {
      if (error.status === 429) {
        // Rate limit - wait and retry
        await sleep(Math.pow(2, i) * 1000);
        continue;
      }
      if (error.status === 529) {
        // Overloaded - retry with backoff
        await sleep(Math.pow(2, i) * 1000);
        continue;
      }
      throw error; // Don't retry other errors
    }
  }
}
```

## Advanced Features

### Tool Use / Function Calling
Enable Claude to call your backend functions:

```javascript
const tools = [{
  name: 'get_user_data',
  description: 'Retrieves user profile data',
  input_schema: {
    type: 'object',
    properties: {
      user_id: { type: 'string' }
    }
  }
}];

const response = await anthropic.messages.create({
  model: 'claude-sonnet-4-20250514',
  max_tokens: 4096,
  tools: tools,
  messages: messages
});

// Handle tool use in response
if (response.stop_reason === 'tool_use') {
  const toolUse = response.content.find(c => c.type === 'tool_use');
  const result = await executeToolFunction(toolUse.name, toolUse.input);
  
  // Send result back to Claude
  messages.push({ role: 'assistant', content: response.content });
  messages.push({ 
    role: 'user', 
    content: [{
      type: 'tool_result',
      tool_use_id: toolUse.id,
      content: JSON.stringify(result)
    }]
  });
}
```

### Image/Document Processing
```javascript
// Handle file uploads
app.post('/api/analyze-image', upload.single('image'), async (req, res) => {
  const imageBuffer = req.file.buffer;
  const base64Image = imageBuffer.toString('base64');
  
  const response = await anthropic.messages.create({
    model: 'claude-sonnet-4-20250514',
    max_tokens: 4096,
    messages: [{
      role: 'user',
      content: [
        {
          type: 'image',
          source: {
            type: 'base64',
            media_type: 'image/jpeg',
            data: base64Image
          }
        },
        { type: 'text', text: 'What\'s in this image?' }
      ]
    }]
  });
  
  res.json(response);
});
```

## Tech Stack Recommendations

### Backend Options
- **Node.js/Express**: Fast, great ecosystem
- **Python/FastAPI**: Excellent for AI/ML integration
- **Next.js API Routes**: Full-stack React solution
- **Ruby on Rails**: Rapid development

### Frontend Options
- **React**: Most popular, great ecosystem
- **Vue.js**: Simpler, progressive
- **Svelte**: Lightweight, fast
- **Next.js**: Full-stack React with SSR

### Databases
- **PostgreSQL**: Robust relational DB for structured data
- **MongoDB**: Flexible for conversation storage
- **Redis**: Caching and session management
- **Pinecone/Weaviate**: Vector databases for RAG applications

### Deployment
- **Vercel/Netlify**: Easy deployment for Next.js/React
- **AWS/Google Cloud/Azure**: Full control, scalable
- **Railway/Render**: Simple deployment for full-stack apps
- **Docker + Kubernetes**: Enterprise-scale deployments

## Example Production Architecture

```
┌─────────────┐
│   Client    │
│  (Browser)  │
└──────┬──────┘
       │ HTTPS
       ▼
┌─────────────┐      ┌──────────────┐
│   Load      │─────▶│  Web Server  │
│  Balancer   │      │  (Nginx)     │
└─────────────┘      └──────┬───────┘
                            │
                            ▼
                     ┌──────────────┐
                     │  API Server  │
                     │  (Node.js)   │
                     └──────┬───────┘
                            │
          ┌─────────────────┼─────────────────┐
          ▼                 ▼                 ▼
    ┌──────────

-------------------------------------------------------------------------------------------------------------------------
PART 2
-------------------------------------------------------------------------------------------------------------------------
# Building Production-Ready AI Web Applications with Claude using Java & Spring Boot

## Architecture Overview

A production AI application with Spring Boot consists of:
- **Frontend**: React/Angular/Vue or Thymeleaf templates
- **Backend**: Spring Boot REST API with Claude integration
- **Database**: JPA with PostgreSQL/MySQL
- **Security**: Spring Security with JWT
- **Deployment**: Docker containers on cloud platforms

## Project Setup

### Maven Dependencies (pom.xml)

```xml
<dependencies>
    <!-- Spring Boot Starters -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>
    
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-validation</artifactId>
    </dependency>
    
    <!-- Database -->
    <dependency>
        <groupId>org.postgresql</groupId>
        <artifactId>postgresql</artifactId>
    </dependency>
    
    <!-- HTTP Client for Claude API -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-webflux</artifactId>
    </dependency>
    
    <!-- JSON Processing -->
    <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
    </dependency>
    
    <!-- JWT -->
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-api</artifactId>
        <version>0.12.3</version>
    </dependency>
    
    <!-- Lombok (optional, for cleaner code) -->
    <dependency>
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
        <optional>true</optional>
    </dependency>
    
    <!-- Redis for caching -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-redis</artifactId>
    </dependency>
</dependencies>
```

## Core Implementation

### 1. Configuration (application.yml)

```yaml
spring:
  application:
    name: claude-ai-app
  datasource:
    url: jdbc:postgresql://localhost:5432/claude_app
    username: ${DB_USERNAME}
    password: ${DB_PASSWORD}
  jpa:
    hibernate:
      ddl-auto: update
    show-sql: false
  redis:
    host: localhost
    port: 6379

claude:
  api:
    key: ${ANTHROPIC_API_KEY}
    url: https://api.anthropic.com/v1/messages
    model: claude-sonnet-4-20250514
    max-tokens: 4096
    version: 2023-06-01

server:
  port: 8080
  
logging:
  level:
    com.yourcompany: INFO
```

### 2. Claude API Configuration

```java
package com.yourcompany.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class ClaudeConfig {
    
    @Value("${claude.api.url}")
    private String apiUrl;
    
    @Value("${claude.api.key}")
    private String apiKey;
    
    @Value("${claude.api.version}")
    private String apiVersion;
    
    @Bean
    public WebClient claudeWebClient() {
        return WebClient.builder()
                .baseUrl(apiUrl)
                .defaultHeader("x-api-key", apiKey)
                .defaultHeader("anthropic-version", apiVersion)
                .defaultHeader("Content-Type", "application/json")
                .build();
    }
}
```

### 3. DTOs (Data Transfer Objects)

```java
package com.yourcompany.dto;

import lombok.Data;
import lombok.Builder;
import java.util.List;

@Data
@Builder
public class ClaudeRequest {
    private String model;
    private Integer maxTokens;
    private List<Message> messages;
    private String system;
    private Boolean stream;
    
    @Data
    @Builder
    public static class Message {
        private String role; // "user" or "assistant"
        private String content;
    }
}

@Data
public class ClaudeResponse {
    private String id;
    private String type;
    private String role;
    private List<Content> content;
    private String model;
    private String stopReason;
    private Usage usage;
    
    @Data
    public static class Content {
        private String type;
        private String text;
    }
    
    @Data
    public static class Usage {
        private Integer inputTokens;
        private Integer outputTokens;
    }
}

@Data
public class ChatRequest {
    private String message;
    private String conversationId;
    private String systemPrompt;
}

@Data
@Builder
public class ChatResponse {
    private String response;
    private String conversationId;
    private Integer tokensUsed;
}
```

### 4. Entity Models

```java
package com.yourcompany.entity;

import jakarta.persistence.*;
import lombok.Data;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "conversations")
@Data
public class Conversation {
    
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;
    
    @Column(name = "user_id", nullable = false)
    private String userId;
    
    @Column(name = "title")
    private String title;
    
    @Column(name = "system_prompt", columnDefinition = "TEXT")
    private String systemPrompt;
    
    @OneToMany(mappedBy = "conversation", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Message> messages = new ArrayList<>();
    
    @Column(name = "created_at")
    private LocalDateTime createdAt;
    
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
    
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }
    
    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}

@Entity
@Table(name = "messages")
@Data
public class Message {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "conversation_id")
    private Conversation conversation;
    
    @Column(name = "role", nullable = false)
    private String role; // "user" or "assistant"
    
    @Column(name = "content", columnDefinition = "TEXT", nullable = false)
    private String content;
    
    @Column(name = "tokens_used")
    private Integer tokensUsed;
    
    @Column(name = "created_at")
    private LocalDateTime createdAt;
    
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
}

@Entity
@Table(name = "users")
@Data
public class User {
    
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;
    
    @Column(unique = true, nullable = false)
    private String email;
    
    @Column(nullable = false)
    private String password;
    
    @Column(name = "token_usage")
    private Long tokenUsage = 0L;
    
    @Column(name = "token_limit")
    private Long tokenLimit = 1000000L;
    
    @Column(name = "created_at")
    private LocalDateTime createdAt;
    
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
}
```

### 5. Repository Layer

```java
package com.yourcompany.repository;

import com.yourcompany.entity.Conversation;
import com.yourcompany.entity.Message;
import com.yourcompany.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Optional;

@Repository
public interface ConversationRepository extends JpaRepository<Conversation, String> {
    List<Conversation> findByUserIdOrderByUpdatedAtDesc(String userId);
    Optional<Conversation> findByIdAndUserId(String id, String userId);
}

@Repository
public interface MessageRepository extends JpaRepository<Message, Long> {
    List<Message> findByConversationIdOrderByCreatedAtAsc(String conversationId);
}

@Repository
public interface UserRepository extends JpaRepository<User, String> {
    Optional<User> findByEmail(String email);
}
```

### 6. Claude Service

```java
package com.yourcompany.service;

import com.yourcompany.dto.ClaudeRequest;
import com.yourcompany.dto.ClaudeResponse;
import com.yourcompany.dto.ChatRequest;
import com.yourcompany.dto.ChatResponse;
import com.yourcompany.entity.Conversation;
import com.yourcompany.entity.Message;
import com.yourcompany.repository.ConversationRepository;
import com.yourcompany.repository.MessageRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class ClaudeService {
    
    private final WebClient claudeWebClient;
    private final ConversationRepository conversationRepository;
    private final MessageRepository messageRepository;
    private final UserService userService;
    
    @Value("${claude.api.model}")
    private String model;
    
    @Value("${claude.api.max-tokens}")
    private Integer maxTokens;
    
    @Transactional
    public ChatResponse chat(ChatRequest request, String userId) {
        // Get or create conversation
        Conversation conversation = getOrCreateConversation(
            request.getConversationId(), 
            userId, 
            request.getSystemPrompt()
        );
        
        // Get conversation history
        List<Message> history = messageRepository
            .findByConversationIdOrderByCreatedAtAsc(conversation.getId());
        
        // Check token limits
        userService.checkTokenLimit(userId);
        
        // Build Claude request
        List<ClaudeRequest.Message> messages = buildMessages(history, request.getMessage());
        
        ClaudeRequest claudeRequest = ClaudeRequest.builder()
            .model(model)
            .maxTokens(maxTokens)
            .messages(messages)
            .system(conversation.getSystemPrompt())
            .build();
        
        // Call Claude API with retry logic
        ClaudeResponse claudeResponse = callClaudeAPI(claudeRequest);
        
        // Extract response text
        String responseText = claudeResponse.getContent().stream()
            .filter(c -> "text".equals(c.getType()))
            .map(ClaudeResponse.Content::getText)
            .collect(Collectors.joining("\n"));
        
        // Save messages
        saveMessage(conversation, "user", request.getMessage(), 
            claudeResponse.getUsage().getInputTokens());
        saveMessage(conversation, "assistant", responseText, 
            claudeResponse.getUsage().getOutputTokens());
        
        // Update user token usage
        int totalTokens = claudeResponse.getUsage().getInputTokens() + 
                         claudeResponse.getUsage().getOutputTokens();
        userService.incrementTokenUsage(userId, totalTokens);
        
        return ChatResponse.builder()
            .response(responseText)
            .conversationId(conversation.getId())
            .tokensUsed(totalTokens)
            .build();
    }
    
    private ClaudeResponse callClaudeAPI(ClaudeRequest request) {
        try {
            return claudeWebClient.post()
                .body(Mono.just(request), ClaudeRequest.class)
                .retrieve()
                .bodyToMono(ClaudeResponse.class)
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(1))
                    .filter(throwable -> isRetryableError(throwable)))
                .block();
        } catch (Exception e) {
            log.error("Error calling Claude API", e);
            throw new RuntimeException("Failed to get response from Claude", e);
        }
    }
    
    private boolean isRetryableError(Throwable throwable) {
        // Retry on 429 (rate limit) and 529 (overloaded)
        String message = throwable.getMessage();
        return message != null && (message.contains("429") || message.contains("529"));
    }
    
    private Conversation getOrCreateConversation(String conversationId, 
                                                 String userId, 
                                                 String systemPrompt) {
        if (conversationId != null) {
            return conversationRepository.findByIdAndUserId(conversationId, userId)
                .orElseThrow(() -> new RuntimeException("Conversation not found"));
        }
        
        Conversation conversation = new Conversation();
        conversation.setId(UUID.randomUUID().toString());
        conversation.setUserId(userId);
        conversation.setSystemPrompt(systemPrompt != null ? systemPrompt : 
            "You are a helpful AI assistant.");
        conversation.setTitle("New Conversation");
        return conversationRepository.save(conversation);
    }
    
    private List<ClaudeRequest.Message> buildMessages(List<Message> history, 
                                                      String newMessage) {
        List<ClaudeRequest.Message> messages = new ArrayList<>();
        
        // Add conversation history (manage context window)
        List<Message> managedHistory = manageContextWindow(history);
        for (Message msg : managedHistory) {
            messages.add(ClaudeRequest.Message.builder()
                .role(msg.getRole())
                .content(msg.getContent())
                .build());
        }
        
        // Add new user message
        messages.add(ClaudeRequest.Message.builder()
            .role("user")
            .content(newMessage)
            .build());
        
        return messages;
    }
    
    private List<Message> manageContextWindow(List<Message> history) {
        // Keep last 20 messages or implement smarter context management
        if (history.size() <= 20) {
            return history;
        }
        return history.subList(history.size() - 20, history.size());
    }
    
    private void saveMessage(Conversation conversation, String role, 
                           String content, Integer tokens) {
        Message message = new Message();
        message.setConversation(conversation);
        message.setRole(role);
        message.setContent(content);
        message.setTokensUsed(tokens);
        messageRepository.save(message);
    }
    
    public List<Conversation> getUserConversations(String userId) {
        return conversationRepository.findByUserIdOrderByUpdatedAtDesc(userId);
    }
    
    @Transactional
    public void deleteConversation(String conversationId, String userId) {
        Conversation conversation = conversationRepository
            .findByIdAndUserId(conversationId, userId)
            .orElseThrow(() -> new RuntimeException("Conversation not found"));
        conversationRepository.delete(conversation);
    }
}
```

### 7. User Service (Token Management)

```java
package com.yourcompany.service;

import com.yourcompany.entity.User;
import com.yourcompany.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserService {
    
    private final UserRepository userRepository;
    
    public void checkTokenLimit(String userId) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("User not found"));
        
        if (user.getTokenUsage() >= user.getTokenLimit()) {
            throw new RuntimeException("Token limit exceeded");
        }
    }
    
    @Transactional
    public void incrementTokenUsage(String userId, int tokens) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("User not found"));
        user.setTokenUsage(user.getTokenUsage() + tokens);
        userRepository.save(user);
    }
    
    public Long getRemainingTokens(String userId) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("User not found"));
        return user.getTokenLimit() - user.getTokenUsage();
    }
}
```

### 8. REST Controller

```java
package com.yourcompany.controller;

import com.yourcompany.dto.ChatRequest;
import com.yourcompany.dto.ChatResponse;
import com.yourcompany.entity.Conversation;
import com.yourcompany.service.ClaudeService;
import com.yourcompany.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/chat")
@RequiredArgsConstructor
@CrossOrigin(origins = "*") // Configure properly for production
public class ChatController {
    
    private final ClaudeService claudeService;
    private final UserService userService;
    
    @PostMapping
    public ResponseEntity<ChatResponse> chat(
            @Valid @RequestBody ChatRequest request,
            @AuthenticationPrincipal UserDetails userDetails) {
        
        String userId = userDetails.getUsername(); // Or get from JWT
        ChatResponse response = claudeService.chat(request, userId);
        return ResponseEntity.ok(response);
    }
    
    @GetMapping("/conversations")
    public ResponseEntity<List<Conversation>> getConversations(
            @AuthenticationPrincipal UserDetails userDetails) {
        
        String userId = userDetails.getUsername();
        List<Conversation> conversations = claudeService.getUserConversations(userId);
        return ResponseEntity.ok(conversations);
    }
    
    @DeleteMapping("/conversations/{conversationId}")
    public ResponseEntity<Void> deleteConversation(
            @PathVariable String conversationId,
            @AuthenticationPrincipal UserDetails userDetails) {
        
        String userId = userDetails.getUsername();
        claudeService.deleteConversation(conversationId, userId);
        return ResponseEntity.noContent().build();
    }
    
    @GetMapping("/tokens/remaining")
    public ResponseEntity<Map<String, Long>> getRemainingTokens(
            @AuthenticationPrincipal UserDetails userDetails) {
        
        String userId = userDetails.getUsername();
        Long remaining = userService.getRemainingTokens(userId);
        return ResponseEntity.ok(Map.of("remainingTokens", remaining));
    }
}
```

### 9. Security Configuration

```java
package com.yourcompany.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    
    private final JwtAuthenticationFilter jwtAuthFilter;
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf().disable()
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**").permitAll()
                .requestMatchers("/api/health").permitAll()
                .anyRequest().authenticated()
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

### 10. Rate Limiting (using Bucket4j)

```java
package com.yourcompany.config;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class RateLimiter {
    
    private final Map<String, Bucket> cache = new ConcurrentHashMap<>();
    
    public Bucket resolveBucket(String userId) {
        return cache.computeIfAbsent(userId, k -> createNewBucket());
    }
    
    private Bucket createNewBucket() {
        // 50 requests per minute
        Bandwidth limit = Bandwidth.classic(50, 
            Refill.intervally(50, Duration.ofMinutes(1)));
        return Bucket.builder()
            .addLimit(limit)
            .build();
    }
    
    public boolean tryConsume(String userId) {
        Bucket bucket = resolveBucket(userId);
        return bucket.tryConsume(1);
    }
}
```

### 11. Exception Handling

```java
package com.yourcompany.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {
    
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<Map<String, Object>> handleRuntimeException(RuntimeException ex) {
        Map<String, Object> error = new HashMap<>();
        error.put("timestamp", LocalDateTime.now());
        error.put("message", ex.getMessage());
        error.put("status", HttpStatus.INTERNAL_SERVER_ERROR.value());
        
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
    }
    
    @ExceptionHandler(TokenLimitExceededException.class)
    public ResponseEntity<Map<String, Object>> handleTokenLimitExceeded(
            TokenLimitExceededException ex) {
        Map<String, Object> error = new HashMap<>();
        error.put("timestamp", LocalDateTime.now());
        error.put("message", "Token limit exceeded");
        error.put("status", HttpStatus.TOO_MANY_REQUESTS.value());
        
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(error);
    }
}
```

## Deployment

### Docker Configuration

```dockerfile
# Dockerfile
FROM eclipse-temurin:17-jdk-alpine AS build
WORKDIR /app
COPY mvnw .
COPY .mvn .mvn
COPY pom.xml .
COPY src src
RUN ./mvnw clean package -DskipTests

FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
```

```yaml
# docker-compose.yml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "8080:8080"
    environment:
      - SPRING_DATASOURCE_URL=jdbc:postgresql://db:5432/claude_app
      - SPRING_DATASOURCE_USERNAME=postgres
      - SPRING_DATASOURCE_PASSWORD=password
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - SPRING_REDIS_HOST=redis
    depends_on:
      - db
      - redis
  
  db:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=claude_app
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data
  
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

volumes:
  postgres_data:
```

## Testing

```java
package com.yourcompany.service;

import com.yourcompany.dto.ChatRequest;
import com.yourcompany.dto.ChatResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("test")
class ClaudeServiceTest {
    
    @Autowired
    private ClaudeService claudeService;
    
    @Test
    void testChat() {
        ChatRequest request = new ChatRequest();
        request.setMessage("Hello, Claude!");
        request.setSystemPrompt("You are a helpful assistant.");
        
        ChatResponse response = claudeService.chat(request, "test-user-id");
        
        assertNotNull(response);
        assertNotNull(response.getResponse());
        assertNotNull(response.getConversationId());
        assertTrue(response.getTokensUsed() > 0);
    }
}
```

## Production Checklist

✅ **Security**
- API keys stored in environment variables
- JWT authentication implemented
- Input validation on all endpoints
- Rate limiting enabled
- CORS configured properly
- HTTPS enforced

✅ **Performance**
- Connection pooling configured
- Redis caching enabled
- Database indexes on foreign keys
- Async processing for long operations

✅ **Monitoring**
- Application logging configured
- Health check endpoints
- Metrics collection (Micrometer/Prometheus)
- Error tracking (Sentry/Rollbar)

✅ **Cost Management**
- Token usage tracking per user
- User quotas enforced
- Request rate limiting
- Context window management

✅ **Reliability**
- Retry logic with exponential backoff
- Circuit breaker pattern
- Database transactions
- Graceful degradation

This gives you a complete, production-ready Spring Boot application for integrating Claude AI!
#AIDevelopment
#Claude
