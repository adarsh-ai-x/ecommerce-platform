package com.ecommerce;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.*;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.http.ResponseEntity;
import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.*;

@SpringBootApplication
@RestController
@CrossOrigin(origins = "*")
public class BackendApplication {

    public static void main(String[] args) {
        SpringApplication.run(BackendApplication.class, args);
    }

    @Bean
    CommandLineRunner initDatabase(ProductRepository productRepo) {
        return args -> {
            productRepo.save(new Product("Gaming Laptop", "RTX 4060, 16GB RAM, 512GB SSD", 75000.0, 10));
            productRepo.save(new Product("Mechanical Keyboard", "RGB Custom Switches", 3500.0, 25));
            productRepo.save(new Product("Wireless Mouse", "16000 DPI Optical Sensor", 1800.0, 40));
        };
    }
}

// ================= PRODUCT MODULE =================
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
@CrossOrigin(origins = "*")
class ProductController {
    private final ProductRepository productRepo;
    public ProductController(ProductRepository productRepo) { this.productRepo = productRepo; }

    @GetMapping
    public List<Product> getAllProducts() { return productRepo.findAll(); }

    @PostMapping
    public Product addProduct(@RequestBody Product product) { return productRepo.save(product); }
}

// ================= ORDER MODULE =================
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
    private LocalDateTime orderDate;

    public Order() {}
    public Order(Long productId, String productName, Integer quantity, Double totalPrice) {
        this.productId = productId;
        this.productName = productName;
        this.quantity = quantity;
        this.totalPrice = totalPrice;
        this.orderDate = LocalDateTime.now();
    }

    public Long getId() { return id; }
    public Long getProductId() { return productId; }
    public String getProductName() { return productName; }
    public Integer getQuantity() { return quantity; }
    public Double getTotalPrice() { return totalPrice; }
    public LocalDateTime getOrderDate() { return orderDate; }
}

interface OrderRepository extends JpaRepository<Order, Long> {}

@RestController
@RequestMapping("/api/orders")
@CrossOrigin(origins = "*")
class OrderController {
    private final OrderRepository orderRepo;
    private final ProductRepository productRepo;

    public OrderController(OrderRepository orderRepo, ProductRepository productRepo) {
        this.orderRepo = orderRepo;
        this.productRepo = productRepo;
    }

    @PostMapping
    public ResponseEntity<?> placeOrder(@RequestBody Map<String, Object> req) {
        Long productId = Long.valueOf(req.get("productId").toString());
        int quantity = Integer.parseInt(req.getOrDefault("quantity", 1).toString());

        Optional<Product> prodOpt = productRepo.findById(productId);
        if (prodOpt.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Product not found"));
        }

        Product product = prodOpt.get();
        if (product.getStock() < quantity) {
            return ResponseEntity.badRequest().body(Map.of("error", "Insufficient stock available"));
        }

        product.setStock(product.getStock() - quantity);
        productRepo.save(product);

        Order order = new Order(product.getId(), product.getName(), quantity, product.getPrice() * quantity);
        Order savedOrder = orderRepo.save(order);

        return ResponseEntity.ok(savedOrder);
    }

    @GetMapping
    public List<Order> getAllOrders() {
        return orderRepo.findAll();
    }
}