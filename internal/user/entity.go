package user

import (
	"time"

	"github.com/sing3demons/oauth/kp/pkg/validate"
)

type UserModel struct {
	ID       string `json:"id" bson:"_id,omitempty"`
	Username string `json:"username" bson:"username"`
	Email    string `json:"email" bson:"email"`
	Password string `json:"password" bson:"password"`
	Pin      string `json:"pin,omitempty" bson:"pin,omitempty"`
	Phone    string `json:"phone" bson:"phone"`

	Avatar string `json:"avatar,omitempty" bson:"avatar,omitempty"`

	CreatedAt time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time `json:"updated_at" bson:"updated_at"`
}

type ProfileModel struct {
	ID           string    `json:"id" bson:"_id,omitempty"`
	LanguageCode string    `json:"language_code,omitempty" bson:"language_code,omitempty"`
	UserID       string    `json:"user_id" bson:"user_id"`
	FirstName    string    `json:"first_name" bson:"first_name"`
	LastName     string    `json:"last_name" bson:"last_name"`
	Bio          string    `json:"bio,omitempty" bson:"bio,omitempty"`
	Location     string    `json:"location,omitempty" bson:"location,omitempty"`
	BirthDate    time.Time `json:"birth_date,omitempty" bson:"birth_date,omitempty"`

	CreatedAt time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time `json:"updated_at" bson:"updated_at"`
}

type UserCredentials struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required_without=Pin"`
	Pin      string `json:"pin" validate:"required_without=Password"`
}

func (c *UserCredentials) IsEmail(val string) bool {
	return validate.IsEmail(val)
}
func (c *UserCredentials) IsPinLogin() bool {
	return c.Pin != ""
}

func (c *UserCredentials) IsPasswordLogin() bool {
	return c.Password != ""
}
