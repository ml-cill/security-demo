package pers.melii.cill.security.demo.handler;

import com.alibaba.fastjson.JSON;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import pers.melii.cill.security.demo.domain.ResponseResult;
import pers.melii.cill.security.demo.util.WebUtil;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 认证失败自定义异常处理
 *
 * @author: melii ma
 * @date: 2022/9/22 21:57
 */
@Component
public class AuthenticationEntryPointImpl implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        ResponseResult responseResult = new ResponseResult(HttpStatus.UNAUTHORIZED.value(), "登录失败了，请重新登录");
        String json = JSON.toJSONString(responseResult);
        WebUtil.renderString(response, json);

    }
}
