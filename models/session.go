package models

import (
	"time"

	"gorm.io/gorm"
)

type Session struct {
	gorm.Model
	UserID       uint
	RefreshToken string `gorm:"type:char(60);unique"`
	ExpDate      time.Time
	UserAgent    string `gorm:"type:varchar(60)"`
	ClientIP     string `gorm:"type:varchar(20)"`
	IsBlocked    bool   `gorm:"default:false"`
	Active       bool   `gorm:"default:true"`
}
