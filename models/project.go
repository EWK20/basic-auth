package models

import (
	"time"

	"gorm.io/gorm"
)

type Project struct {
	gorm.Model
	Ref                 string  `gorm:"type:varchar(16);unique"`
	CompanyName         string  `gorm:"type:varchar(250)"`
	CompanyLogo         string  `gorm:"type:varchar(1024)"`
	Description         string  `gorm:"type:varchar(250)"`
	Cost                float64 `gorm:"type:numeric(13,2)"`
	OutstandingCost     float64 `gorm:"type:numeric(13,2)"`
	Duration            int
	PaymentLink         string `gorm:"type:varchar(250)"`
	Proposal            string `gorm:"type:varchar(1024)"`
	Invoice             string `gorm:"type:varchar(1024)"`
	Contract            string `gorm:"type:varchar(1024)"`
	ContentArchitecture string `gorm:"type:varchar(1024)"`
	Assets              string `gorm:"type:varchar(1024)"`
	Handover            string `gorm:"type:varchar(1024)"`
	Status              string `gorm:"type:varchar(20)"`
	DateCompleted       time.Time
	PhenixTeam          []PhenixTeam `gorm:"many2many:project_team;"`
	Stages              []Stage
	Checklist           []Checklist
}
