package models

import "gorm.io/gorm"

type Stage struct {
	gorm.Model
	ProjectID uint
	Stage     string `gorm:"type:varchar(250)"`
	Status    string `gorm:"type:varchar(20)"`
}
