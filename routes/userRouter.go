package routes

import (
	"github.com/gin-gonic/gin"
	controller "go_jwt/controllers"
	"go_jwt/middleware"
)

func UserRoutes(incomingRoutes *gin.Engine) {

	// All user routes need authentication using token
	incomingRoutes.Use(middleware.Authenticate())
	incomingRoutes.GET("/users", controller.GetUsers())
	incomingRoutes.GET("/users/:user_id", controller.GetUserbyId())

}
