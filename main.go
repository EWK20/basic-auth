package main

import (
	"github.com/PhenixSolutions/phenix-auth/controllers"
	"github.com/PhenixSolutions/phenix-auth/initializers"
	"github.com/PhenixSolutions/phenix-auth/middleware"
	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnv()
	initializers.DBConnect()
}

func main() {
	r := gin.Default()
	auth := r.Group("/v1/auth")
	api := r.Group("/v1/api")
	api.Use(middleware.RequireAuth)

	//! Routes

	//* Create new client with temp password
	auth.POST("/new-user", controllers.CreateUser)

	//* Login
	auth.POST("/login", controllers.Login)

	//* Set new paasword
	api.POST("/set-pass", controllers.ChangePassword)

	//* Validate auth
	api.GET("/validate", controllers.Validate)

	r.Run()
}
