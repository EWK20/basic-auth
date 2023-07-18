package models

import "gorm.io/gorm"

type PhenixTeam struct {
	gorm.Model
	Headshot  string `gorm:"type:varchar(1024)"`
	FirstName string `gorm:"type:varchar(100)"`
	LastName  string `gorm:"type:varchar(150)"`
	Email     string `gorm:"type:varchar(320);unique"`
	Position  string `gorm:"type:varchar(100)"`
	Active    bool
}
