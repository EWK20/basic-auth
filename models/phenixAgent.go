package models

import "gorm.io/gorm"

type PhenixAgent struct {
	gorm.Model
	FirstName  string     `gorm:"type:varchar(100)"`
	LastName   string     `gorm:"type:varchar(150)"`
	Phone      string     `gorm:"type:varchar(20)"`
	Email      string     `gorm:"type:varchar(320);unique"`
	Password   string     `gorm:"type:char(60)"`
	Role       string     `gorm:"type:varchar(20);default:'PHENIX'"`
	Headshot   string     `gorm:"type:varchar(1024)"`
	Position   string     `gorm:"type:varchar(100)"`
	Admin      bool       `gorm:"default:false"`
	FirstLogin bool       `gorm:"default:false"`
	Sessions   []Session  `gorm:"foreignKey:AgentID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	Projects   []*Project `gorm:"many2many:project_team;"`
}
