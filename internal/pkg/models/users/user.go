package users

import (
	"time"

	"vulnerability-management/internal/pkg/models"
)

type User struct {
	models.Model
	UserName string `gorm:"column:username;" json:"username" form:"username"`
	Password string `gorm:"column:password;" json:"password" form:"password"`
	FullName string `gorm:"column:full_name;" json:"full_name" form:"full_name"`
	Email    string `gorm:"column:email;" json:"email" form:"email"`
}

func (m *User) BeforeCreate() error {
	m.CreatedAt = time.Now()
	m.UpdatedAt = time.Now()

	return nil
}

func (m *User) BeforeUpdate() error {
	m.UpdatedAt = time.Now()

	return nil
}
