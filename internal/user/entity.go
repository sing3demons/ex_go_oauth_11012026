package user

import (
	"time"

	"github.com/sing3demons/oauth/kp/pkg/validate"
)

type ProfileModel struct {
	ID              string                 `json:"id" bson:"_id,omitempty"`
	Href            string                 `json:"href,omitempty" bson:"-"`
	Username        string                 `json:"username" bson:"username"`
	Email           string                 `json:"email" bson:"email"`
	Password        string                 `json:"password" bson:"password"`
	Pin             string                 `json:"pin,omitempty" bson:"pin,omitempty"`
	Phone           string                 `json:"phone,omitempty" bson:"phone,omitempty"`
	ProfileLanguage []ProfileModelLanguage `json:"profile_language,omitempty" bson:"profile_language,omitempty"`

	Avatar string `json:"avatar,omitempty" bson:"avatar,omitempty"`

	CreatedAt time.Time `json:"-" bson:"created_at"`
	UpdatedAt time.Time `json:"-" bson:"updated_at"`
}

type ProfileModelLanguage struct {
	ID           string    `json:"id" bson:"_id,omitempty"`
	LanguageCode string    `json:"language_code" bson:"language_code" validate:"required"`
	Href         string    `json:"href,omitempty" bson:"-"`
	UserID       string    `json:"user_id" bson:"user_id" validate:"required"`
	FirstName    string    `json:"first_name,omitempty" bson:"first_name,omitempty"`
	LastName     string    `json:"last_name,omitempty" bson:"last_name,omitempty"`
	Bio          string    `json:"bio,omitempty" bson:"bio,omitempty"`
	Location     string    `json:"location,omitempty" bson:"location,omitempty"`
	BirthDate    time.Time `json:"birth_date,omitempty" bson:"birth_date,omitempty"`

	CreatedAt time.Time `json:"-" bson:"created_at"`
	UpdatedAt time.Time `json:"-" bson:"updated_at"`
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
