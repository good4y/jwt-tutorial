package inflearn.study.jwttutorial.repository;

import inflearn.study.jwttutorial.entity.User;
import java.util.Optional;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
  // username을 이용하여 유저 정보와 권한 정보를 같이 가져옴
  // @entityGraph eager 조회로 authorities 정보를 같이 가져옴
  @EntityGraph(attributePaths = "authorities")
  Optional<User> findOneWithAuthoritiesByUsername(String username);
}
