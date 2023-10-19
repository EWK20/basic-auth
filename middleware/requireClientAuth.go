package middleware

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/EWK20/basic-auth/initializers"
	"github.com/EWK20/basic-auth/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func RequireClientAuth(ctx *gin.Context) {
	//* Get refresh token cookie off request
	ref_token, err := ctx.Cookie("RefToken")
	if err != nil {
		log.Println("No Refresh Token")
		ctx.AbortWithStatus(http.StatusUnauthorized)
	}

	var session models.Session
	//* Get current session
	if err := initializers.DB.Where(&models.Session{RefreshToken: ref_token}).First(&session).Error; err != nil {
		log.Println("Could Not Retrieve Refresh Token")
		ctx.AbortWithStatus(http.StatusUnauthorized)
	}

	//* Get inactive refresh tokens
	var inactiveSessions []models.Session
	if err := initializers.DB.Where("client_id = ? AND active = false", session.ClientID).Find(&inactiveSessions).Error; err != nil {
		log.Println("Could Not Retrieve Refresh Token")
		ctx.AbortWithStatus(http.StatusUnauthorized)
	}

	//* If current refresh token is equal to an old one then delete all refreh tokens for user
	for _, oldSession := range inactiveSessions {
		if oldSession.RefreshToken == ref_token {
			log.Println("User ID: ", session.ClientID)
			//* Delete All Sessions
			err := initializers.DB.Where(&models.Session{ClientID: session.ClientID}).Unscoped().Delete(&models.Session{})
			if err != nil {
				log.Println("Failed To Delete Sessions")
				ctx.AbortWithStatus(http.StatusUnauthorized)
			}
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}
	}

	//* Get access token cookie off request
	access_token, err := ctx.Cookie("Authorization")
	if err != nil {
		log.Println("No Access Token")

		//* Get user based on refresh token
		var client models.Client

		//* Find the client of the current session
		if err := initializers.DB.First(&client, session.ClientID).Error; err != nil {
			log.Println("Could Not Retrieve User")
			ctx.AbortWithStatus(http.StatusUnauthorized)
		}

		//* Generate new access token
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": client.ID,
			"exp": time.Now().Add(time.Minute * 10).Unix(),
		})

		accessToken, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
		if err != nil {
			log.Println("Failed To Create Token")
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Failed To Create Token"})
			return
		}

		//* Set Cookies
		ctx.SetSameSite(http.SameSiteLaxMode)
		ctx.SetCookie("Authorization", accessToken, 600, "", "", false, true)

		//* Attach to req
		ctx.Set("client", client)

		//* Continue
		ctx.Next()

	}

	//* Decode & Validate token
	token, _ := jwt.Parse(access_token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	//* Check claims
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		//* Check expiration
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			ctx.AbortWithStatus(http.StatusUnauthorized)
		}

		//* Find client with token sub
		var client models.Client
		initializers.DB.First(&client, claims["sub"])
		if client.ID == 0 {
			ctx.AbortWithStatus(http.StatusUnauthorized)
		}

		//* Attach phenix object to req
		ctx.Set("client", client)

		//* Continue
		ctx.Next()
		return
	} else {
		ctx.AbortWithStatus(http.StatusUnauthorized)
	}

}
