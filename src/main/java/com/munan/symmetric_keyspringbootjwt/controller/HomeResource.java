package com.munan.symmetric_keyspringbootjwt.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class HomeResource {

    @GetMapping("/hello")
    public String hello(){
        String world = "World".toUpperCase();
        return "<h2>Hello " +world+"<h2>";
    }
}
