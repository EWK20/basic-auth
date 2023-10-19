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

func ClientLogin(ctx *gin.Context) {
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

	//* Look up requested client
	var client models.Client
	initializers.DB.First(&client, "email = ?", body.Email)
	if client.ID == 0 {
		log.Println("Incorrect Email Or Password")
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect Email Or Password"})
		return
	}

	//* Compare sent in pass with saved client pass hash
	err := bcrypt.CompareHashAndPassword([]byte(client.Password), []byte(body.Password))
	if err != nil {
		log.Println("Incorrect Email Or Password")
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect Email Or Password"})
		return
	}

	//* Generate access token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": client.ID,
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

	if err := initializers.DB.Where(&models.Session{ClientID: client.ID, Active: true}).Find(&oldSessions).Error; err != nil {
		log.Println("Could Not Retrieve Old Sessions")
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Could Not Retrieve Old Sessions"})
		return
	}

	for _, session := range oldSessions {
		if err := initializers.DB.Model(&session).Update("active", false).Error; err != nil {
			log.Println("Could Not Invalidate Old Sessions")
			ctx.AbortWithStatus(http.StatusInternalServerError)
		}
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
		ClientID:     client.ID,
		RefreshToken: ref_token,
		ExpDate:      time.Now().AddDate(0, 0, 30),
		UserAgent:    ctx.Request.UserAgent(),
		ClientIP:     ctx.ClientIP(),
		Active:       true,
	}).Error; err != nil {
		log.Println("Could Not Create Session")
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Could Not Create Session"})
		return
	}

	//* Save it to cookies
	//! Change secure to true in prod
	//! Make duration longer in prod
	ctx.SetSameSite(http.SameSiteLaxMode)
	ctx.SetCookie("Authorization", accessToken, 600, "", "", false, true)
	if body.Remember {
		ctx.SetCookie("RefToken", ref_token, 3600*24*7, "", "", false, true)
	} else {
		ctx.SetCookie("RefToken", ref_token, 10, "", "", false, true)
	}

	//* Response

	//*First Login?
	if !client.FirstLogin {
		log.Println("Logged In For The First Time")
		ctx.JSON(http.StatusOK, gin.H{
			"firstLogin": true,
		})
		//* Toggle client.FirstLogin to true
		client.FirstLogin = true
		if err := initializers.DB.Save(&client).Error; err != nil {
			log.Println("Failed To Update Client")
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed To Update Client"})
			return
		}
		return
	}

	log.Println("Logged In")
	ctx.JSON(http.StatusOK, gin.H{})

}

func ClientChangePassword(ctx *gin.Context) {
	var reqBody struct {
		OldPassword string
		NewPassword string
	}
	if ctx.Bind(&reqBody) != nil {
		log.Println("Failed To Read Body")
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Failed To Read Body"})
		return
	}

	//* Get current user
	user, _ := ctx.Get("client")
	currUser := user.(models.Client)

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
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Could Not Save New Password"})
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "Password Changed"})

}

func AgentLogin(ctx *gin.Context) {
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

	//* Look up requested agent
	var agent models.PhenixAgent
	if err := initializers.DB.Where(&models.PhenixAgent{Email: body.Email}).First(&agent).Error; err != nil {
		log.Println("Incorrect Email Or Password - Email Error")
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect Email Or Password"})
		return
	}

	//* Compare sent in pass with saved agent pass hash
	err := bcrypt.CompareHashAndPassword([]byte(agent.Password), []byte(body.Password))
	if err != nil {
		log.Println("Incorrect Email Or Password")
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect Email Or Password"})
		return
	}

	//* Generate access token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": agent.ID,
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

	if err := initializers.DB.Where(&models.Session{AgentID: agent.ID, Active: true}).Find(&oldSessions).Error; err != nil {
		log.Println("Could Not Retrieve Old Sessions")
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Could Not Retrieve Old Sessions"})
		return
	}

	for _, session := range oldSessions {
		if err := initializers.DB.Model(&session).Update("active", false).Error; err != nil {
			log.Println("Could Not Invalidate Old Sessions")
			ctx.AbortWithStatus(http.StatusInternalServerError)
		}
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
		AgentID:      agent.ID,
		RefreshToken: ref_token,
		ExpDate:      time.Now().AddDate(0, 0, 30),
		UserAgent:    ctx.Request.UserAgent(),
		ClientIP:     ctx.ClientIP(),
		Active:       true,
	}).Error; err != nil {
		log.Println("Could Not Create Session")
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Could Not Create Session"})
		return
	}

	//* Save it to cookies
	//! Change secure to true in prod
	//! Make duration longer in prod
	ctx.SetSameSite(http.SameSiteLaxMode)
	ctx.SetCookie("Authorization", accessToken, 600, "", "", false, true)
	if body.Remember {
		ctx.SetCookie("RefToken", ref_token, 3600*24*7, "", "", false, true)
	} else {
		ctx.SetCookie("RefToken", ref_token, 10, "", "", false, true)
	}

	//* Response

	//*First Login?
	if !agent.FirstLogin {
		log.Println("Logged In For The First Time")
		ctx.JSON(http.StatusOK, gin.H{
			"firstLogin": true,
		})
		//* Toggle client.FirstLogin to true
		agent.FirstLogin = true
		if err := initializers.DB.Save(&agent).Error; err != nil {
			log.Println("Failed To Update Agent")
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed To Update Agent"})
			return
		}
		return
	}

	log.Println("Logged In")
	ctx.JSON(http.StatusOK, gin.H{})

}

func AgentChangePassword(ctx *gin.Context) {
	var reqBody struct {
		OldPassword string
		NewPassword string
	}
	if ctx.Bind(&reqBody) != nil {
		log.Println("Failed To Read Body")
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Failed To Read Body"})
		return
	}

	//* Get current user
	user, _ := ctx.Get("agent")
	currUser := user.(models.PhenixAgent)

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
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Could Not Save New Password"})
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "Password Changed"})

}
