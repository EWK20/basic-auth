package models

import "gorm.io/gorm"

type Client struct {
	gorm.Model
	FirstName  string     `gorm:"type:varchar(100)"`
	LastName   string     `gorm:"type:varchar(150)"`
	Phone      string     `gorm:"type:varchar(20)"`
	Email      string     `gorm:"type:varchar(320);unique"`
	Password   string     `gorm:"type:char(60)"`
	Verified   bool       `gorm:"default:false"`
	FirstLogin bool       `gorm:"default:false"`
	Sessions   []Session  `gorm:"foreignKey:ClientID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	Projects   []*Project `gorm:"many2many:client_projects;"`
}
