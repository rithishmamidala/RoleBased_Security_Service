package capstoneProject.Secure.service;

import capstoneProject.Secure.Exception.UserExistException;
import capstoneProject.Secure.model.Person;
import capstoneProject.Secure.repo.AdminDumpRepo;
import capstoneProject.Secure.repo.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class AuthService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AdminDumpRepo adminRepo;

    public Person saveUser(Person user){
        user.setPassword((passwordEncoder.encode(user.getPassword())));
        try {
            return userRepository.save(user);
        }
        catch (Exception e){
            throw new UserExistException("User already");
        }
    }
    public String generateToken(String username)
    {
        return jwtService.generateToken(username);
    }

    public void validateToken(String token) {
        jwtService.validateToken(token);
    }
    public boolean isUserRegistered(String username) {
        // Check if a user with the given username already exists in the database
        return userRepository.existsByUsername(username);
    }

    public Person findByUsername(String username) {
        Optional<Person> personOptional = userRepository.findByUsername(username);
        // If the user exists, return the Person object, otherwise return null
        return personOptional.orElse(null); // Return null if user is not found
    }

    public List<Person> findUsersWaitingForApproval() {
        return userRepository.findByStatus(0); // 0 represents waiting for approval
    }

    public void ValidateAdmin( Person user){


    }
}