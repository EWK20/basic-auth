package initializers

import (
	"os"

	"github.com/EWK20/basic-auth/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func DBConnect() {
	dsn := os.Getenv("DB_CONN_STRING")
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("Failed to connect to db")
	}

	db.AutoMigrate(&models.Client{}, &models.Session{}, &models.Stage{}, &models.Project{}, &models.PhenixAgent{}, &models.Checklist{})

	DB = db
}
