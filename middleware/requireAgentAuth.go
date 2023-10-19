package middleware

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/PhenixSolutions/phenix-auth/initializers"
	"github.com/PhenixSolutions/phenix-auth/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func RequireAgentAuth(ctx *gin.Context) {
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
	if err := initializers.DB.Where("agent_id = ? AND active = false", session.AgentID).Find(&inactiveSessions).Error; err != nil {
		log.Println("No Inactive Sessions")
	}

	//* If current refresh token is equal to an old one then delete all refreh tokens for user
	for _, oldSession := range inactiveSessions {
		if oldSession.RefreshToken == ref_token {
			//* Delete All Sessions
			err := initializers.DB.Where(&models.Session{AgentID: session.AgentID}).Unscoped().Delete(&models.Session{})
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
		var agent models.PhenixAgent

		//* Find the agent of the current session
		if err := initializers.DB.First(&agent, session.AgentID).Error; err != nil {
			log.Println("Could Not Retrieve Agent")
			ctx.AbortWithStatus(http.StatusUnauthorized)
		}

		//* Generate new access token
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": agent.ID,
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
		ctx.Set("agent", agent)

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

		//* Find agent with token sub
		var agent models.PhenixAgent
		initializers.DB.First(&agent, claims["sub"])
		if agent.ID == 0 {
			ctx.AbortWithStatus(http.StatusUnauthorized)
		}

		if strings.ToUpper(agent.Role) == "PHENIX" {
			//* Attach phenix object to req
			ctx.Set("agent", agent)

			//* Continue
			ctx.Next()
			return
		}
		ctx.AbortWithStatus(http.StatusUnauthorized)
	} else {
		ctx.AbortWithStatus(http.StatusUnauthorized)
	}

}
