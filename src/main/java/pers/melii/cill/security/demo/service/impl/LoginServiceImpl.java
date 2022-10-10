package pers.melii.cill.security.demo.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import pers.melii.cill.security.demo.domain.LoginUser;
import pers.melii.cill.security.demo.domain.ResponseResult;
import pers.melii.cill.security.demo.domain.User;
import pers.melii.cill.security.demo.service.LoginService;
import pers.melii.cill.security.demo.util.JwtUtil;
import pers.melii.cill.security.demo.util.RedisCacheUtil;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * 登录相关 实现
 *
 * @author: melii ma
 * @date: 2022/9/13 21:02
 */
@Service
public class LoginServiceImpl implements LoginService {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private RedisCacheUtil redisCacheUtil;

    @Override
    public ResponseResult login(User user) {
        // 使用 ProviderManager(AuthenticationManager的实现) auth 方法进行验证
        Authentication authenticate = authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated(user.getUserName(), user.getPassword()));
        // 校验失败的情况下 需要返回错误信息
        if (Objects.isNull(authenticate)) {
            throw new RuntimeException("用户名或密码错误");
        }

        // 自己生成 JWT 给前端
        LoginUser loginUser = (LoginUser) authenticate.getPrincipal();
        String userId = loginUser.getUser().getId().toString();
        String jwt = JwtUtil.createJWT(userId);

        // 系统用户相关信息存放到redis中
        redisCacheUtil.setCacheObject("user:"+userId, loginUser);

        // 确定返回值内容
        Map resultDateMap = new HashMap<String, String>();
        resultDateMap.put("jwt", jwt);
        return new ResponseResult(200, "登录成功", resultDateMap);
    }

    @Override
    public ResponseResult logout() {
        // 获取到 Token, 删除 redis 中的数据
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        LoginUser loginUser = (LoginUser) authentication.getPrincipal();
        redisCacheUtil.deleteObject("user:"+loginUser.getUser().getId());
        return new ResponseResult(200, "退出成功");
    }
}
