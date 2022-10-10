package pers.melii.cill.security.demo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import pers.melii.cill.security.demo.domain.ResponseResult;

/**
 * Index Controller
 *
 * @author: ml
 * @date: 2022/9/7 22:38
 */
@RestController
@RequestMapping("/index")
public class IndexController {

    @GetMapping("/demo")
    @PreAuthorize("hasAuthority('demo')")
    public ResponseResult demo() {
        return new ResponseResult(200, "msg");
    }

}