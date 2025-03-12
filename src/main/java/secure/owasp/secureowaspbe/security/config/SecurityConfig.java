package secure.owasp.secureowaspbe.security.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import secure.owasp.secureowaspbe.security.jwt.JwtAuthFilter;
import secure.owasp.secureowaspbe.security.service.UserDService;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;
    private final UserDService userDetailsService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        jwtAuthFilter.setUserDetailsService(userDetailsService);

        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/feedback/all").permitAll()  // Permite acces public pentru a primi toate feedback-urile
                        .requestMatchers("/api/feedback/submit").permitAll()  // Permite acces public pentru a adauga un feedback
                        .requestMatchers("/api/store-checker/check-stock").permitAll()  // Permite acces public pentru a verifica stock-ul magazinelor
                        .requestMatchers("/api/recipes/list").permitAll()  // Permite acces public pentru a primi lista cu toate retetele
                        .requestMatchers("/api/recipes/read").permitAll()  // Permite acces public pentru a citi o reteta anume
                        .requestMatchers("/api/admin/**").hasRole("ADMIN") // Acces doar pentru userii cu rolul de 'ADMIN' pentru endpoint-ul /admin/ (config, execute)
                        .requestMatchers("/api/auth/**").permitAll() // Permitem autentificarea fara JWT
                        .anyRequest().authenticated()
                )
                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class); // Adaugam filtrul JWT

        return http.build();
    }


    @Bean
    public AuthenticationManager authenticationManager(UserDService userDetailsService, PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder);

        return new ProviderManager(authProvider);
    }


    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDService userDetailsService() {
        return userDetailsService;
    }
}
