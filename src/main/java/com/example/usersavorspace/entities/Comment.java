package com.example.usersavorspace.entities;


import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "comments")
public class Comment {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long commentID;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "recipeID", nullable = false)
    @JsonBackReference("recipe-comments")
    private Recipe recipe;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "userID", nullable = false)
    @OnDelete(action = OnDeleteAction.NO_ACTION)
    @JsonBackReference("user-comments")
    private User user;

    @Column(nullable = false)
    private String content;


    //@Column(name = "is_flagged")
    //private boolean isFlagged = false;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "comment_flags",
            joinColumns = @JoinColumn(name = "comment_id"),
            inverseJoinColumns = @JoinColumn(name = "user_id")
    )
    @JsonIgnoreProperties({"comments", "flaggedComments", "password"})
    private Set<User> flaggedByUsers = new HashSet<>();

    @Column(nullable = false)
    private boolean deleted = false;

    @Column(nullable = false)
    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private LocalDateTime createdAt;

    @Transient
    private String username;

    public String getUsername() {
        return user != null ? user.getUsername() : null;
    }

    public boolean isDeleted() {
        return deleted;
    }

    public void setDeleted(boolean deleted) {
        this.deleted = deleted;
    }

    public Long getCommentID() {
        return commentID;
    }

    public void setCommentID(Long commentID) {
        this.commentID = commentID;
    }

    public Recipe getRecipe() {
        return recipe;
    }

    public void setRecipe(Recipe recipe) {
        this.recipe = recipe;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }


    /*public boolean getFlagged() {
        return isFlagged;
    }*/
    /*public void setFlagged(boolean flagged) {
        isFlagged = flagged;
    }*/

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void addFlag(User user) {
        flaggedByUsers.add(user);
    }

    public void removeFlag(User user) {
        flaggedByUsers.remove(user);
    }

    public boolean isFlaggedByUser(User user) {
        return flaggedByUsers.contains(user);
    }

    public int getFlagCount() {
        return flaggedByUsers.size();
    }

    public Set<User> getFlaggedByUsers() {
        return flaggedByUsers;
    }

    public void setFlaggedByUsers(Set<User> flaggedByUsers) {
        this.flaggedByUsers = flaggedByUsers;
    }

    // Remove or modify the old getFlagged/setFlagged methods
    public boolean getFlagged() {
        return !flaggedByUsers.isEmpty();
    }
}