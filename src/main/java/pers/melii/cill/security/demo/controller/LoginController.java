package pers.melii.cill.security.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import pers.melii.cill.security.demo.domain.LoginUser;
import pers.melii.cill.security.demo.domain.ResponseResult;
import pers.melii.cill.security.demo.domain.User;
import pers.melii.cill.security.demo.service.LoginService;

/**
 * 登录 Controller
 *
 * @author: melii ma
 * @date: 2022/9/13 20:56
 */
@RestController
@RequestMapping("/user")
public class LoginController {

    @Autowired
    LoginService loginService;

    @PostMapping("/login")
    public ResponseResult login(@RequestBody User user) {
        return loginService.login(user);
    }

    @PostMapping("/logout")
    public ResponseResult logout() {
        return loginService.logout();
    }

    @GetMapping("/msg")
    @PreAuthorize("hasAuthority('user/msg')")
    public ResponseResult test() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        LoginUser loginUser = (LoginUser) authentication.getPrincipal();
        return new ResponseResult(200, "测试", loginUser);
    }

}
