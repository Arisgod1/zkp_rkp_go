package controller

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type UserController struct{}

func NewUserController() *UserController {
	return &UserController{}
}

func (u *UserController) Me(c *gin.Context) {
	username, _ := c.Get("username")
	c.JSON(http.StatusOK, gin.H{
		"username": username,
		"message":  "authorized",
	})
}
