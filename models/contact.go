package models

import "github.com/louisevanderlith/husk"

//Contact holds information like email, facebook, cellphone
type Contact struct {
	Icon string `hsk:"size(15)"`
	Name string `hsk:"size(20)"`
	Value string `hsk:"size(256)"`
}

func (c Contact) Valid() (bool, error){
	return husk.ValidateStruct(&c)
}