package stores

import "kong/models"

type UserStore interface {
	GetUser(id string) models.User
	GetUserByName(username string) (string, models.User)
}