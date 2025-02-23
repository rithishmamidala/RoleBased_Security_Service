package capstoneProject.Secure.config;

import capstoneProject.Secure.model.Person;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

public class CustomUserDetails implements UserDetails {

    private Long id;
    private String username;
    private String password;
    private String role;

    public CustomUserDetails(Person userCredential) {
        this.id = userCredential.getId();
        this.username = userCredential.getUsername();
        this.password = userCredential.getPassword();
        this.role = userCredential.getRole();  // Get the role of the user
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Convert role to authorities
        return List.of(() -> role);  // This is how we can assign role as authority
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    // Getter for id
    public Long getId() {
        return id;
    }
}
