package models

import "gorm.io/gorm"

type Checklist struct {
	gorm.Model
	ProjectID uint
	Task      string `gorm:"type:varchar(250)"`
	Status    string `gorm:"type:varchar(20)"`
}
