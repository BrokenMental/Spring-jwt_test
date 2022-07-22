package test.jwt.demo.entity;

import lombok.*;

import javax.persistence.*;
import java.util.Set;

@Entity //DB 테이블과 1대1로 매핑되는 객체
@Table(name = "users") //테이블 사용
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Users {

    @Id
    @Column(name = "user_id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long userId;

    @Column(name = "username", length = 50, unique = true)
    private String username;

    @Column(name = "password", length = 100)
    private String password;

    @Column(name = "nickname", length = 50)
    private String nickname;

    @Column(name = "activated")
    private boolean activated;

    @ManyToMany //테이블의 다대다 관계를 일대다 또는 다대일 관계의 조인 테이블로 정의했다는 의미
    @JoinTable(
            name = "user_authority",
            joinColumns = {@JoinColumn(name = "user_id", referencedColumnName = "user_id")},
            inverseJoinColumns = {@JoinColumn(name = "authority_name", referencedColumnName = "authority_name")})
    private Set<Authority> authorities;
}
