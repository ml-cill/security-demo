package pers.melii.cill.security.demo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import pers.melii.cill.security.demo.domain.ResponseResult;

/**
 * 权限测试接口
 *
 * @author: melii ma
 * @date: 2022/9/21 22:35
 */
@RestController
@RequestMapping("/perms")
public class PermsTestController {

    @GetMapping("/pull")
    @PreAuthorize("hasAnyAuthority('dev:code:pull')")
    public ResponseResult pullTest() {
        return new ResponseResult(200, "pull success");
    }


    @GetMapping("/push")
    @PreAuthorize("hasAnyAuthority('dev:code:push')")
    public ResponseResult pushTest() {
        return new ResponseResult(200, "push success");
    }

}
