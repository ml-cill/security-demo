package pers.melii.cill.security.demo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import pers.melii.cill.security.demo.filter.JwtAuthenticationTokenFilter;
import pers.melii.cill.security.demo.handler.AccessDeniedHandlerImpl;
import pers.melii.cill.security.demo.handler.AuthenticationEntryPointImpl;

/**
 * security 配置
 *
 * @author: melii ma
 * @date: 2022/9/13 21:04
 */
@Configuration
// 基于注解的权限控制方案，配置之后就可以使用 @PreAuthorize 注解修饰相关方法了
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    /**
     * 自定义加密模式
     *
     * security 中默认使用的加密模式为：{id}password 它会根据id判断加密模式
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Autowired
    private JwtAuthenticationTokenFilter jwtAuthenticationTokenFilter;

    @Autowired
    private AuthenticationEntryPointImpl authenticationEntryPoint;

    @Autowired
    private AccessDeniedHandlerImpl accessDeniedHandler;

    @Autowired
    private AuthenticationSuccessHandler successHandler;

    @Autowired
    private AuthenticationFailureHandler failureHandler;

    @Autowired
    private LogoutSuccessHandler logoutSuccessHandler;

    /*
    * 原本继承 WebSecurityConfigurerAdapter 在2.7 的版本已经不推荐使用了
    *
    * 现在的写法是 自定义一个 SecurityFilterChain
    * */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        /*
        * 关闭 csrf(跨站请求伪造)
        * 不通过 session 获取 securityContext
        * 设置 /user/login 匿名接口
        */
        http.csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                .authorizeRequests()
                .antMatchers("/user/login").anonymous()
                .anyRequest().authenticated();

        // 将自定义认证过滤器放到 UsernamePasswordAuthenticationFilter 过滤器之前执行
        http.addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);

        // 设置 security 如何处理异常
        http.exceptionHandling().authenticationEntryPoint(authenticationEntryPoint).accessDeniedHandler(accessDeniedHandler);

        // 配置认证成功及失败处理器
        http.formLogin().successHandler(successHandler).failureHandler(failureHandler);

        // 配置登出（注销）成功处理器
        http.logout().logoutSuccessHandler(logoutSuccessHandler);
        return http.build();
    }

    @Autowired
    private AuthenticationConfiguration authenticationConfiguration;

    @Bean
    public AuthenticationManager authenticationConfiguration() throws Exception {
        AuthenticationManager authenticationManager = authenticationConfiguration.getAuthenticationManager();
        return authenticationManager;
    }
}
