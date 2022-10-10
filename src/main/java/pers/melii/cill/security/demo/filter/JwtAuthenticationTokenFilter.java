package pers.melii.cill.security.demo.filter;


import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import pers.melii.cill.security.demo.domain.LoginUser;
import pers.melii.cill.security.demo.util.JwtUtil;
import pers.melii.cill.security.demo.util.RedisCacheUtil;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;

/**
 * 认证过滤器
 * <p>
 * 继承 OncePerRequestFilter ， 为了请求前此过滤器只走一次
 *
 * @author: melii ma
 * @date: 2022/9/15 22:29
 */
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    @Autowired
    RedisCacheUtil redisCacheUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // 1. 获取 Token
        String token = request.getHeader("token");
        if (!StringUtils.hasText(token)) {
            // 未登录的情况下 放行，让后面的过滤器来执行
            filterChain.doFilter(request, response);
            return;
        }

        // 2. 解析 Token
        Claims claims;
        try {
            claims = JwtUtil.parseJWT(token);
        } catch (Exception e) {
            throw new RuntimeException("token 不合法");
        }

        // 3. 获取 userId，并从redis 中获取用户信息
        String userId = claims.getSubject();
        LoginUser loginUser = redisCacheUtil.getCacheObject("user:" + userId);
        if (Objects.isNull(loginUser)) {
            throw new RuntimeException("当前用户未登录");
        }

        // 4. 封装 Authentication 并存入 SecurityContextHolder
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(
                        loginUser, null, loginUser.getAuthorities()));

        filterChain.doFilter(request, response);
    }
}
