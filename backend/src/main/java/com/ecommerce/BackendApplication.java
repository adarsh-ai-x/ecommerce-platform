package com.ecommerce;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.*;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.transaction.annotation.Transactional;
import jakarta.persistence.*;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.security.Keys;
import java.io.IOException;
import java.security.Key;
import java.time.LocalDateTime;
import java.util.*;

@SpringBootApplication
public class BackendApplication {

    public static void main(String[] args) {
        SpringApplication.run(BackendApplication.class, args);
    }

    @Bean
    CommandLineRunner initDatabase(ProductRepository productRepo, UserRepository userRepo, PasswordEncoder encoder) {
        return args -> {
            productRepo.save(new Product("Gaming Laptop", "RTX 4060, 16GB RAM, 512GB SSD", 75000.0, 10));
            productRepo.save(new Product("Mechanical Keyboard", "RGB Custom Switches", 3500.0, 25));
            productRepo.save(new Product("Wireless Mouse", "16000 DPI Optical Sensor", 1800.0, 40));
            productRepo.save(new Product("Noise Cancelling Headphones", "Active ANC with 40h Battery", 6500.0, 15));

            if (userRepo.findByUsername("demo").isEmpty()) {
                userRepo.save(new User("demo", "demo@cloudmart.com", encoder.encode("demo123"), "ROLE_USER"));
            }
        };
    }
}

class JwtUtil {
    public static final Key SECRET_KEY = Keys.hmacShaKeyFor("cloudmart-super-secret-jwt-token-key-256-bits!".getBytes());

    public static String generateToken(String username, String role, Long userId) {
        return Jwts.builder()
            .setSubject(username)
            .claim("role", role)
            .claim("userId", userId)
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + 86400000))
            .signWith(SECRET_KEY)
            .compact();
    }

    public static Claims validateToken(String token) {
        return Jwts.parserBuilder()
            .setSigningKey(SECRET_KEY)
            .build()
            .parseClaimsJws(token)
            .getBody();
    }
}

class JwtAuthFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            try {
                Claims claims = JwtUtil.validateToken(token);
                String username = claims.getSubject();
                String role = claims.get("role", String.class);

                if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        username, null, List.of(new SimpleGrantedAuthority(role != null ? role : "ROLE_USER"))
                    );
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            } catch (Exception ignored) {}
        }
        filterChain.doFilter(request, response);
    }
}

@Configuration
@EnableWebSecurity
class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**").permitAll()
                .requestMatchers(org.springframework.http.HttpMethod.GET, "/api/products/**").permitAll()
                .requestMatchers("/api/orders/**").authenticated()
                .anyRequest().permitAll()
            )
            .addFilterBefore(new JwtAuthFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOriginPatterns(List.of("*"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}

@Entity
@Table(name = "users")
class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(unique = true, nullable = false)
    private String username;
    @Column(unique = true, nullable = false)
    private String email;
    @Column(nullable = false)
    private String password;
    private String role;

    public User() {}
    public User(String username, String email, String password, String role) {
        this.username = username;
        this.email = email;
        this.password = password;
        this.role = role;
    }

    public Long getId() { return id; }
    public String getUsername() { return username; }
    public String getEmail() { return email; }
    public String getPassword() { return password; }
    public String getRole() { return role; }
}

interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);
}

@RestController
@RequestMapping("/api/auth")
class AuthController {
    private final UserRepository userRepo;
    private final PasswordEncoder encoder;

    public AuthController(UserRepository userRepo, PasswordEncoder encoder) {
        this.userRepo = userRepo;
        this.encoder = encoder;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String, String> body) {
        String username = body.get("username");
        String email = body.get("email");
        String password = body.get("password");

        if (username == null || email == null || password == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "All fields required"));
        }
        if (userRepo.findByUsername(username).isPresent()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Username taken"));
        }
        if (userRepo.findByEmail(email).isPresent()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Email already registered"));
        }

        User user = new User(username, email, encoder.encode(password), "ROLE_USER");
        userRepo.save(user);

        return ResponseEntity.ok(Map.of("message", "Registration successful", "username", username));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body) {
        String username = body.get("username");
        String password = body.get("password");

        Optional<User> userOpt = userRepo.findByUsername(username);
        if (userOpt.isEmpty() || !encoder.matches(password, userOpt.get().getPassword())) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid username or password"));
        }

        User user = userOpt.get();
        String token = JwtUtil.generateToken(user.getUsername(), user.getRole(), user.getId());

        return ResponseEntity.ok(Map.of(
            "token", token,
            "username", user.getUsername(),
            "role", user.getRole()
        ));
    }
}

@Entity
@Table(name = "products")
class Product {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String name;
    private String description;
    private Double price;
    private Integer stock;

    public Product() {}
    public Product(String name, String description, Double price, Integer stock) {
        this.name = name;
        this.description = description;
        this.price = price;
        this.stock = stock;
    }

    public Long getId() { return id; }
    public String getName() { return name; }
    public String getDescription() { return description; }
    public Double getPrice() { return price; }
    public Integer getStock() { return stock; }
    public void setStock(Integer stock) { this.stock = stock; }
}

interface ProductRepository extends JpaRepository<Product, Long> {}

@RestController
@RequestMapping("/api/products")
class ProductController {
    private final ProductRepository productRepo;
    public ProductController(ProductRepository productRepo) { this.productRepo = productRepo; }

    @GetMapping
    public List<Product> getAllProducts() { return productRepo.findAll(); }

    @PostMapping
    public Product addProduct(@RequestBody Product product) { return productRepo.save(product); }
}

@Entity
@Table(name = "orders")
class Order {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private Long productId;
    private String productName;
    private Integer quantity;
    private Double totalPrice;
    private String username;
    private LocalDateTime orderDate;

    public Order() {}
    public Order(Long productId, String productName, Integer quantity, Double totalPrice, String username) {
        this.productId = productId;
        this.productName = productName;
        this.quantity = quantity;
        this.totalPrice = totalPrice;
        this.username = username;
        this.orderDate = LocalDateTime.now();
    }

    public Long getId() { return id; }
    public Long getProductId() { return productId; }
    public String getProductName() { return productName; }
    public Integer getQuantity() { return quantity; }
    public Double getTotalPrice() { return totalPrice; }
    public String getUsername() { return username; }
    public LocalDateTime getOrderDate() { return orderDate; }
}

interface OrderRepository extends JpaRepository<Order, Long> {
    List<Order> findByUsernameOrderByOrderDateDesc(String username);
}

@RestController
@RequestMapping("/api/orders")
class OrderController {
    private final OrderRepository orderRepo;
    private final ProductRepository productRepo;

    public OrderController(OrderRepository orderRepo, ProductRepository productRepo) {
        this.orderRepo = orderRepo;
        this.productRepo = productRepo;
    }

    // Checkout: Supports single item OR multi-item Cart batch checkout
    @PostMapping
    @Transactional
    public ResponseEntity<?> placeOrder(@RequestBody Map<String, Object> req) {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || "anonymousUser".equals(auth.getPrincipal())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Authentication required to checkout"));
        }
        String currentUser = auth.getName();

        // Check if multi-item cart batch checkout
        if (req.containsKey("items")) {
            List<Map<String, Object>> items = (List<Map<String, Object>>) req.get("items");
            if (items == null || items.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Cart is empty"));
            }

            List<Order> createdOrders = new ArrayList<>();

            // 1. Validation phase (Atomic check)
            for (Map<String, Object> it : items) {
                Long pId = Long.valueOf(it.get("productId").toString());
                int qty = Integer.parseInt(it.get("quantity").toString());
                Optional<Product> pOpt = productRepo.findById(pId);
                if (pOpt.isEmpty()) {
                    return ResponseEntity.badRequest().body(Map.of("error", "Product SKU #" + pId + " not found"));
                }
                if (pOpt.get().getStock() < qty) {
                    return ResponseEntity.badRequest().body(Map.of("error", "Insufficient stock for " + pOpt.get().getName()));
                }
            }

            // 2. Execution phase (Stock decrement + order generation)
            for (Map<String, Object> it : items) {
                Long pId = Long.valueOf(it.get("productId").toString());
                int qty = Integer.parseInt(it.get("quantity").toString());
                Product product = productRepo.findById(pId).get();
                product.setStock(product.getStock() - qty);
                productRepo.save(product);

                Order order = new Order(product.getId(), product.getName(), qty, product.getPrice() * qty, currentUser);
                createdOrders.add(orderRepo.save(order));
            }

            return ResponseEntity.ok(Map.of(
                "message", "Cart checkout completed successfully",
                "ordersCount", createdOrders.size(),
                "orders", createdOrders
            ));
        }

        // Fallback for single quick order
        Long productId = Long.valueOf(req.get("productId").toString());
        int quantity = Integer.parseInt(req.getOrDefault("quantity", 1).toString());

        Optional<Product> prodOpt = productRepo.findById(productId);
        if (prodOpt.isEmpty()) return ResponseEntity.badRequest().body(Map.of("error", "Product not found"));

        Product product = prodOpt.get();
        if (product.getStock() < quantity) return ResponseEntity.badRequest().body(Map.of("error", "Insufficient stock"));

        product.setStock(product.getStock() - quantity);
        productRepo.save(product);

        Order order = new Order(product.getId(), product.getName(), quantity, product.getPrice() * quantity, currentUser);
        return ResponseEntity.ok(orderRepo.save(order));
    }

    @GetMapping
    public List<Order> getUserOrders() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) return Collections.emptyList();
        return orderRepo.findByUsernameOrderByOrderDateDesc(auth.getName());
    }
}