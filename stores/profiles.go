package stores

import "kong/models"

type ProfileStore interface {
	GetProfile(id string) (models.Profile, error)
}
