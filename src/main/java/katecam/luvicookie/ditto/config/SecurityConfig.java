package katecam.luvicookie.ditto.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // HttpSecurity 설정
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/user/**").authenticated()
                        // user 주소는 인증된 사용자만 접근 가능
                        .requestMatchers("/manager/**").hasAnyRole("MANAGER", "ADMIN")
                        // manager 주소는 ROLE_MANAGER 또는 ROLE_ADMIN 권한 필요
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        // admin 주소는 ROLE_ADMIN 권한 필요
                        .anyRequest().permitAll() // 그 외 모든 요청은 인증 없이 접근 가능
                )
                .formLogin(form -> form
                        .loginPage("/loginForm") // 커스텀 로그인 페이지 설정
                        .permitAll() // 모든 사용자가 로그인 페이지에 접근 가능
                )
                .logout(logout -> logout
                        .permitAll() // 로그아웃은 인증 여부에 상관없이 접근 가능
                );

        return http.build();
    }
}
