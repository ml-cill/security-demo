package pers.melii.cill.security.demo;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import pers.melii.cill.security.demo.dao.MenuMapper;
import pers.melii.cill.security.demo.dao.UserMapper;
import pers.melii.cill.security.demo.domain.User;

import java.util.Date;
import java.util.List;

@SpringBootTest
class SecurityDemoApplicationTests {


    /**
     * JWT 加解密
     */
    @Test
    void jwtEncryptAndDecodeTest() {
        // 设置 jwt 加密
        String jwt = Jwts.builder()
                .setId("Security-DEMO") // 设置id
                .setSubject("Security") // 设置主题
                .setIssuedAt(new Date()) // 签发日期
                // .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60))  // 设置过期时间
                .claim("userId", "123")
                .signWith(SignatureAlgorithm.HS256, "melii").compact(); // 加密模式一个盐值
        System.out.println(jwt);

        // 设置 jwt 解密
        Claims claims = Jwts.parser()
                .setSigningKey("melii")
                .parseClaimsJws(jwt)
                .getBody();
        System.out.println(claims);
    }

    @Autowired
    UserMapper userMapper;

    @Test
    void getUserList() {
        List<User> users = userMapper.selectList(null);
        System.out.println(users.get(0));
    }

    @Autowired
    PasswordEncoder passwordEncoder;

    @Test
    void testBcript() {
        String password1 = passwordEncoder.encode("melii");
        String password2 = passwordEncoder.encode("power");
        System.out.println(password1);
        System.out.println(password2);

        boolean flag1 = passwordEncoder.matches("melii", password1);
        boolean flag2 = passwordEncoder.matches("power", password2);
        System.out.println(flag1);
        System.out.println(flag2);
    }

    @Autowired
    MenuMapper menuMapper;

    @Test
    void getMenu() {
        List<String> result = menuMapper.selectPermsByUserId(2L);
        System.out.println(result);
    }

}
