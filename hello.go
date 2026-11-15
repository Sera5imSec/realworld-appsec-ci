package main

import (
	"fmt"
	"log"
	"os"

	"github.com/gin-gonic/gin"

	"github.com/gothinkster/golang-gin-realworld-example-app/articles"
	"github.com/gothinkster/golang-gin-realworld-example-app/common"
	"github.com/gothinkster/golang-gin-realworld-example-app/users"
	"gorm.io/gorm"
)

func Migrate(db *gorm.DB) error {
	if err := users.AutoMigrate(); err != nil {
		return fmt.Errorf("users migration: %w", err)
	}
	if err := db.AutoMigrate(&articles.ArticleModel{}, &articles.TagModel{},
		&articles.FavoriteModel{}, &articles.ArticleUserModel{}, &articles.CommentModel{}); err != nil {
		return fmt.Errorf("articles migration: %w", err)
	}
	return nil
}

func main() {
	if _, err := common.JWTSigningKey(); err != nil {
		log.Fatal(err)
	}

	db := common.Init()
	if err := Migrate(db); err != nil {
		log.Fatal("database migration failed: ", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		log.Println("failed to get sql.DB:", err)
	} else {
		defer sqlDB.Close()
	}

	r := gin.New()
	// Scrub URL tokens before Gin's logger captures the request path.
	r.Use(func(c *gin.Context) {
		query := c.Request.URL.Query()
		if values, ok := query["access_token"]; ok {
			if len(values) > 0 {
				c.Set("legacy_access_token", values[0])
			}
			query.Set("access_token", "[REDACTED]")
			c.Request.URL.RawQuery = query.Encode()
		}
		c.Next()
	})
	r.Use(gin.Logger(), gin.Recovery())

	// Disable automatic redirect for trailing slashes
	// This prevents POST body from being lost during redirects
	r.RedirectTrailingSlash = false

	v1 := r.Group("/api")
	users.UsersRegister(v1.Group("/users"))
	v1.Use(users.AuthMiddleware(false))
	articles.ArticlesAnonymousRegister(v1.Group("/articles"))
	articles.TagsAnonymousRegister(v1.Group("/tags"))
	users.ProfileRetrieveRegister(v1.Group("/profiles"))

	v1.Use(users.AuthMiddleware(true))
	users.UserRegister(v1.Group("/user"))
	users.ProfileRegister(v1.Group("/profiles"))

	articles.ArticlesRegister(v1.Group("/articles"))

	testAuth := r.Group("/api/ping")

	testAuth.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})

	// Get port from environment variable or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	if err := r.Run(":" + port); err != nil {
		log.Fatal("failed to start server:", err)
	}
}
