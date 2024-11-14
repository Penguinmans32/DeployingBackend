package com.example.usersavorspace.controllers;

import com.example.usersavorspace.entities.User;
import com.example.usersavorspace.services.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RequestMapping("/admin")
@RestController
@CrossOrigin
public class AdminController {

    private final UserService userService;

    public AdminController(UserService userService) {
        this.userService = userService;
    }

    @PreAuthorize("hasAuthority('ADMIN')")
    @DeleteMapping("/users/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable Integer id) {
        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }

    @PreAuthorize("hasAuthority('ADMIN')")
    @PutMapping("/users/{id}")
    public ResponseEntity<User> updateUser(@PathVariable Integer id, @RequestBody User user) {
        User updatedUser = userService.adminUpdateUser(id, user);
        return ResponseEntity.ok(updatedUser);
    }

    @PreAuthorize("hasAuthority('ADMIN')")
    @GetMapping("/users")
    public ResponseEntity<List<User>> allUsers() {
        List<User> users = userService.allUsers();
        return ResponseEntity.ok(users);
    }

    @PreAuthorize("hasAuthority('ADMIN')")
    @GetMapping("/me")
    public ResponseEntity<User> authenticatedAdmin() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User currentAdmin = (User) authentication.getPrincipal();
        System.out.println("Authenticated admin: " + currentAdmin.getRole());
        return ResponseEntity.ok(currentAdmin);
    }
}