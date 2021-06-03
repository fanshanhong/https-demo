package com.fan.https.demo;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @Description:
 * @Author: fan
 * @Date: 2020-10-10 15:30
 * @Modify:
 */
@RestController
public class HttpsTest {

    @GetMapping("hello")
    public String hello() {
        return "hello";
    }

    @GetMapping("strTest")
    public String strTest() {
        return "strTest";
    }
}
