package controllers

import (
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/PhenixSolutions/phenix-auth/initializers"
	"github.com/PhenixSolutions/phenix-auth/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func CreateUser(ctx *gin.Context) {
	//* Get data from body
	var body struct {
		Firstname string
		Lastname  string
		Phone     string
		Email     string
		Role      string
	}

	if ctx.Bind(&body) != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Failed To Read Body"})
		return
	}

	//* Create temp password
	rand.Seed(time.Now().UnixNano())

	chars := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"abcdefghijklmnopqrstuvwxyz" +
		"0123456789")
	length := 10
	var tempPass_builder strings.Builder
	for i := 0; i < length; i++ {
		tempPass_builder.WriteRune(chars[rand.Intn(len(chars))])
	}
	pass := tempPass_builder.String()

	//* Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(pass), 10)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Failed To Hash Password"})
		return
	}

	//* Create user
	user := models.User{
		FirstName: body.Firstname,
		LastName:  body.Lastname,
		Phone:     body.Phone,
		Email:     body.Email,
		Password:  string(hash),
		Role:      body.Role,
	}

	res := initializers.DB.Create(&user)
	if res.Error != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Failed To Create User"})
		return
	}

	//* Response
	ctx.JSON(http.StatusCreated, gin.H{
		"tempPass": pass,
	})
}

func Login(ctx *gin.Context) {
	//* Get email and pass from body
	var body struct {
		Email    string
		Password string
		Remember bool
	}
	if ctx.Bind(&body) != nil {
		log.Println("Failed To Read Body")
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Failed To Read Body"})
		return
	}

	//* Look up requested user
	var user models.User
	initializers.DB.First(&user, "email = ?", body.Email)
	if user.ID == 0 {
		log.Println("Incorrect Email Or Password")
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect Email Or Password"})
		return
	}

	//* Compare sent in pass with saved user pass hash
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))
	if err != nil {
		log.Println("Incorrect Email Or Password")
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect Email Or Password"})
		return
	}

	//* Generate access token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Minute * 10).Unix(),
	})

	accessToken, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		log.Println("Failed To Create Token")
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Failed To Create Token"})
		return
	}

	//* Generate refresh token
	var oldSessions []models.Session

	initializers.DB.Where(&models.Session{UserID: user.ID, Active: true}).Find(&oldSessions)

	for _, session := range oldSessions {
		session.Active = false
		initializers.DB.Save(&session)
	}

	rand.Seed(time.Now().UnixNano())

	chars := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"abcdefghijklmnopqrstuvwxyz" +
		"0123456789")

	length := 60
	var token_builder strings.Builder
	for i := 0; i < length; i++ {
		token_builder.WriteRune(chars[rand.Intn(len(chars))])
	}
	ref_token := token_builder.String()

	//* Create new session
	if err := initializers.DB.Create(&models.Session{
		UserID:       user.ID,
		RefreshToken: ref_token,
		ExpDate:      time.Now().AddDate(0, 0, 30),
		UserAgent:    ctx.Request.UserAgent(),
		ClientIP:     ctx.ClientIP(),
		Active:       true,
	}).Error; err != nil {
		log.Println("Could Not Create Session")
		ctx.JSON(http.StatusConflict, gin.H{"error": "Could Not Create Session"})
		return
	}

	//* Save it to cookies
	//! Change secure to true in prod
	//! Make duration longer in prod
	ctx.SetSameSite(http.SameSiteLaxMode)
	ctx.SetCookie("Authorization", accessToken, 600, "", "", false, true)
	ctx.SetCookie("RefToken", ref_token, 3600*24*7, "", "", false, true)

	//* Response

	//*First Login
	if !user.Active {
		log.Println("Logged In For The First Time")
		ctx.JSON(http.StatusOK, gin.H{
			"firstLogin": true,
		})
		//* Toggle user.Active to true
		user.Active = true
		if err := initializers.DB.Save(&user).Error; err != nil {
			log.Println("Failed To Update User")
			ctx.JSON(http.StatusConflict, gin.H{"error": "Failed To Update User"})
			return
		}
		return
	}

	log.Println("Logged In")
	ctx.JSON(http.StatusOK, gin.H{})

}

func ChangePassword(ctx *gin.Context) {
	var reqBody struct {
		OldPassword string
		NewPassword string
	}
	if ctx.Bind(&reqBody) != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Failed To Read Body"})
		return
	}

	//* Get current user
	user, _ := ctx.Get("user")
	currUser := user.(models.User)

	//* Compare sent in pass with saved user pass hash
	err := bcrypt.CompareHashAndPassword([]byte(currUser.Password), []byte(reqBody.OldPassword))
	if err != nil {
		log.Println("Incorrect Email Or Password")
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect Email Or Password"})
		return
	}

	//* Hash new password
	hash, err := bcrypt.GenerateFromPassword([]byte(reqBody.NewPassword), 10)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Failed To Hash Password"})
		return
	}

	//* Save new password
	currUser.Password = string(hash)
	if err := initializers.DB.Save(&currUser).Error; err != nil {
		log.Println("Could Not Save New Password")
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Could Not Save New Password"})
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "Password Changed"})

}

func Validate(ctx *gin.Context) {

	//* Get user
	user, _ := ctx.Get("user")
	currUser := user.(models.User)

	//* Build response body
	var res struct {
		Firstname string
		Lastname  string
		Phone     string
		Email     string
		Role      string
	}

	res.Firstname = currUser.FirstName
	res.Lastname = currUser.LastName
	res.Phone = currUser.Phone
	res.Email = currUser.Email
	res.Role = currUser.Role

	ctx.JSON(http.StatusOK, gin.H{"user": res})
}
