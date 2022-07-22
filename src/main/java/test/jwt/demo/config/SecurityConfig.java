package test.jwt.demo.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    //deprecate 관련 정보 : https://velog.io/@pjh612/Deprecated%EB%90%9C-WebSecurityConfigurerAdapter-%EC%96%B4%EB%96%BB%EA%B2%8C-%EB%8C%80%EC%B2%98%ED%95%98%EC%A7%80

    @Override
    public void configure(WebSecurity web) throws Exception {
        //서버 시작 시, h2-console 하위 모든 요청과 favicon 관련 요청은 spring-security 로직을 수행하지 않고 접근할 수 있게 함
        web.ignoring()
           .antMatchers(
               "/h2-console/**"
               ,"/favicon.ico"
           );
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests() //servletRequest 사용하는 요청들에 대한 접근 제한 실행
            .antMatchers("/api/hello").permitAll() //Matchers 에 존재하는 요청(여기서는 /api/hello)에 대해선 인증을 허용
            .anyRequest().authenticated(); //나머지 요청들은 모두 인증이 되어야 한다는 의미
    }
}
