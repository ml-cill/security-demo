package pers.melii.cill.security.demo.handler;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import pers.melii.cill.security.demo.domain.ResponseResult;

/**
 * 全局异常处理
 *
 * @author: melii ma
 * @date: 2022/9/22 22:11
 */
@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ResponseResult failed(Exception e) {
        return new ResponseResult(HttpStatus.INTERNAL_SERVER_ERROR.value(), e);
    }

}
