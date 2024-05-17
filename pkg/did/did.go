package did

import (
	"encoding/json"
	"errors"
	"regexp"
)

var ErrInvalidDID = errors.New("invalid DID")

type DID struct {
	method string
	id     string
}

var didRegexp *regexp.Regexp

func init() {
	didPattern := `^did:([a-z0-9]+):((?:[A-Za-z0-9._%-]*:)*[A-Za-z0-9._%-]+)$`
	didRegexp = regexp.MustCompile(didPattern)
}

func (d DID) String() string {
	if d.IsEmpty() {
		return ""
	}
	return "did:" + d.method + ":" + d.id
}

func (d DID) IsEmpty() bool {
	return d.method == "" && d.id == ""
}

func NewDID(method, id string) DID {
	return DID{
		method: method,
		id:     id,
	}
}

func Parse(str string) (DID, error) {
	matches := didRegexp.FindStringSubmatch(str)
	if len(matches) != 3 {
		return DID{}, ErrInvalidDID
	}

	return DID{
		method: matches[1],
		id:     matches[2],
	}, nil
}

func MustParse(did string) DID {
	r, err := Parse(did)
	if err != nil {
		panic(err)
	}
	return r
}

func (d DID) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

func (d *DID) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	parsedDID, err := Parse(str)
	if err != nil {
		return err
	}
	*d = parsedDID
	return nil
}
