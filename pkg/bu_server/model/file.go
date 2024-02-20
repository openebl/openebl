package model

type File struct {
	Name        string   `json:"name"`      // File name
	FileType    string   `json:"file_type"` // MIME type of the file.
	Content     []byte   `json:"content"`   // File content.
	CreatedDate DateTime `json:"created_date"`
}
