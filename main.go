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
	cli := auth.Group("/cli")
	adm := auth.Group("/adm")

	//! Routes

	//* Create new user with temp password
	// auth.POST("/new-user", controllers.CreateUser)

	//* Client Login
	cli.POST("/login", controllers.ClientLogin)

	//* Client change password
	cli.POST("/set-pass", middleware.RequireClientAuth, controllers.ClientChangePassword)

	//* Agent Login
	adm.POST("/login", controllers.AgentLogin)

	//* Agent change password
	adm.POST("/set-pass", middleware.RequireAgentAuth, controllers.AgentChangePassword)

	//* Health Check
	r.GET("/health-check")

	r.Run()
}
