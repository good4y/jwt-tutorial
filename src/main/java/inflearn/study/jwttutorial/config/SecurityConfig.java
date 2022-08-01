package inflearn.study.jwttutorial.config;

import inflearn.study.jwttutorial.jwt.JwtAccessDeniedHandler;
import inflearn.study.jwttutorial.jwt.JwtAuthenticationEntryPoint;
import inflearn.study.jwttutorial.jwt.JwtSecurityConfig;
import inflearn.study.jwttutorial.jwt.TokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)  // preauthorize 어노테이션을 메서드 단위로 사용하기 위한 어노테이션
public class SecurityConfig {
  private final TokenProvider tokenProvider;
  private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
  private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

  public SecurityConfig(
      TokenProvider tokenProvider,
      JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
      JwtAccessDeniedHandler jwtAccessDeniedHandler
  ) {
    this.tokenProvider = tokenProvider;
    this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
    this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public WebSecurityCustomizer webSecurityCustomizer(){
    return web -> web.ignoring()
        .antMatchers(
            "/h2-console/**"
        ,"/favicon.ico"
        ,"/error"
        );
  }
  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
    // token을 사용하는 방식이기 때문에 csrf를 disable합니다.
    // exception 핸들링 추가
    http.csrf().disable()
        .exceptionHandling()
        .authenticationEntryPoint(jwtAuthenticationEntryPoint)
        .accessDeniedHandler(jwtAccessDeniedHandler);

    // enable h2-console
    http.headers().frameOptions().sameOrigin();

    // 세션을 사용하지 않기 때문에 STATELESS로 설정
    http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

    // 토큰 요청이 필요없는 페이지에 권한 해제
    http.authorizeRequests()
        .antMatchers("/api/hello").permitAll()
        .antMatchers("/api/authenticate").permitAll()
        .antMatchers("/api/signup").permitAll()
        .anyRequest().authenticated();

    // JWT 필터 적용
    http.apply(new JwtSecurityConfig(tokenProvider));
    return http.build();
  }
}