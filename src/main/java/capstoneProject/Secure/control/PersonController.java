package capstoneProject.Secure.control;

import capstoneProject.Secure.config.CustomUserDetails;
import capstoneProject.Secure.model.Person;
import capstoneProject.Secure.repo.UserRepository;
import capstoneProject.Secure.service.AuthService;
import capstoneProject.Secure.service.JwtService;
import io.jsonwebtoken.JwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;

import java.awt.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/person")
@CrossOrigin("*")
public class PersonController {

    @Autowired
    private AuthService authService;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private UserRepository userRepository;

    private static final Logger logger = LoggerFactory.getLogger(PersonController.class);

    @PostMapping("/register")
    public ResponseEntity<String> registerPerson(@RequestBody Person user) {
        try {
            logger.debug("Attempting authentication for username: {}", user.getUsername());
            // Check if the user is already registered
            if (authService.isUserRegistered(user.getUsername())) {
                return ResponseEntity.status(HttpStatus.CONFLICT).body("User already registered");
            } else {
                // Set initial status to 0 (Pending approval)
                user.setStatus(0);

                // Handle role-specific validation and saving
                if ("ADMIN".equalsIgnoreCase(user.getRole())) {
                    authService.ValidateAdmin(user); // Admin-specific validation
                    authService.saveUser(user); // Save user to database
                    return ResponseEntity.status(HttpStatus.OK).body("Admin request sent for approval");
                } else if ("SHOP KEEPER".equalsIgnoreCase(user.getRole())) {
                    authService.ValidateAdmin(user); // Shop keeper validation
                    authService.saveUser(user); // Save user to database
                    return ResponseEntity.status(HttpStatus.OK).body("Shop Keeper request sent for approval");
                } else {
                    // If the role is not valid
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid role. Please provide a valid role.");
                }
            }
        } catch (Exception e) {
            // Handle exceptions
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An error occurred during registration");
        }
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> getToken(@RequestBody Person authRequest) {
        Person user = authService.findByUsername(authRequest.getUsername());
        if (user.getStatus() == 0) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", "You are not yet approved. Contact admin"));
        }

        try {
            logger.debug("Attempting authentication for username: {}", authRequest.getUsername());
            Authentication authenticate = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));

                    if (authenticate.isAuthenticated()) {
                        CustomUserDetails userCredential = (CustomUserDetails) authenticate.getPrincipal();
                        String token = authService.generateToken(authRequest.getUsername());
                        Map<String, String> response = new HashMap<>();
                        response.put("token", token); // Include the token in the response
                        return ResponseEntity.ok(response);
                    }

             else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("message", "Invalid credentials"));
            }
        } catch (AuthenticationException e) {
            logger.debug("Attempting authentication for username: {}", authRequest.getUsername());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("message", "Authentication failed"));
        }
    }

    @GetMapping("/app")
    public ResponseEntity<String> WaitingForApproval() {
        return ResponseEntity.ok("ddd");
    }

    @GetMapping("/approvalRequests")
    public ResponseEntity<List<Person>> getUsersWaitingForApproval() {
        List<Person> usersWaitingForApproval = authService.findUsersWaitingForApproval();
        System.out.print(usersWaitingForApproval);

        if (usersWaitingForApproval.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NO_CONTENT).body(usersWaitingForApproval); // No Content if no users found
        }

        return ResponseEntity.ok(usersWaitingForApproval);
    }
    @GetMapping("/validate")
    public ResponseEntity<String> validateToken(@RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader) {
        try {
            // Extract the token from the Authorization header
            String token = authHeader.startsWith("Bearer ") ? authHeader.substring(7) : authHeader;

            // Validate the token
            authService.validateToken(token);

            // Extract username from the token
            String username = jwtService.extractUsername(token);
            // Return username if token is valid
            return ResponseEntity.ok(username);
        } catch (JwtException | IllegalArgumentException e) {
            // Return error message if token is invalid or expired
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid or expired token");
        }
    }

    @PutMapping("/approve/{username}")
    public ResponseEntity<String> approveUser(@PathVariable String username) {
        // Fetch the user from the database by their username
        Person user = authService.findByUsername(username);

        if (user == null) {
            // If the user is not found, return a 404 Not Found response
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found with username: " + username);
        }

        // Update the status to 1 (approved)
        user.setStatus(1);

        // Save the updated user back to the database
        userRepository.save(user);

        // Return a success response
        return ResponseEntity.ok("User with username " + username + " has been approved.");
    }
    @DeleteMapping("/delete/{username}")
    public ResponseEntity<String> deleteUser(@PathVariable String username) {
        // Fetch the user from the database by their username
        Person user = authService.findByUsername(username);

        if (user == null) {
            // If the user is not found, return a 404 Not Found response
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found with username: " + username);
        }

        // Delete the user from the database
        userRepository.delete(user);

        // Return a success response
        return ResponseEntity.ok("User with username " + username + " has been deleted.");
    }
}
