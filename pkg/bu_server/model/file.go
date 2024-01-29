package model

type File struct {
	Name        string   `json:"name"`    // File name
	Content     []byte   `json:"content"` // File content.
	CreatedDate DateTime `json:"created_date"`
}
