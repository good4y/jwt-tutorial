package inflearn.study.jwttutorial.service;


import inflearn.study.jwttutorial.dto.UserDto;
import inflearn.study.jwttutorial.entity.Authority;
import inflearn.study.jwttutorial.entity.User;
import inflearn.study.jwttutorial.repository.UserRepository;
import inflearn.study.jwttutorial.util.SecurityUtil;
import java.util.Collections;
import java.util.Optional;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService {
  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;

  public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
    this.userRepository = userRepository;
    this.passwordEncoder = passwordEncoder;
  }

  @Transactional
  public User signup(UserDto userDto) {
    if (userRepository.findOneWithAuthoritiesByUsername(userDto.getUsername()).orElse(null) != null) {
      throw new RuntimeException("이미 가입되어 있는 유저입니다.");
    }

    Authority authority = Authority.builder()
        .authorityName("ROLE_USER")
        .build();

    User user = User.builder()
        .username(userDto.getUsername())
        .password(passwordEncoder.encode(userDto.getPassword()))
        .nickname(userDto.getNickname())
        .authorities(Collections.singleton(authority))
        .activated(true)
        .build();

    return userRepository.save(user);
  }

  // username을 파라메터로 받아 유저네임에 해당하는 권한정보
  @Transactional(readOnly = true)
  public Optional<User> getUserWithAuthorities(String username) {
    return userRepository.findOneWithAuthoritiesByUsername(username);
  }

  // 현재 securitycontext에 저장된 username에 해당하는 유저정보, 권한정보
  @Transactional(readOnly = true)
  public Optional<User> getMyUserWithAuthorities() {
    return SecurityUtil.getCurrentUsername().flatMap(userRepository::findOneWithAuthoritiesByUsername);
  }
}