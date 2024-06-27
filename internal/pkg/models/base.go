package models

import "time"

type Model struct {
	ID        uint64    `gorm:"column:id;primary_key;auto_increment;" json:"id,omitempty"`
	CreatedAt time.Time `gorm:"column:created_at;type:datetime;" json:"created_at,omitempty"`
	UpdatedAt time.Time `gorm:"column:updated_at;type:datetime;" json:"updated_at,omitempty"`
}
