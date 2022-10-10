package pers.melii.cill.security.demo.service;


import pers.melii.cill.security.demo.domain.ResponseResult;
import pers.melii.cill.security.demo.domain.User;

/**
 * 登录相关 service
 *
 * @author: melii ma
 * @date: 2022/9/13 21:02
 */
public interface LoginService {

    ResponseResult login(User user);

    ResponseResult logout();

}
