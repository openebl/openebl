package model

import "github.com/shopspring/decimal"

type Decimal struct {
	value decimal.Decimal
}

func NewDecimalFromString(s string) (Decimal, error) {
	d, err := decimal.NewFromString(s)
	if err != nil {
		return Decimal{}, err
	}
	return Decimal{
		value: d,
	}, nil
}

func (d Decimal) MarshalJSON() ([]byte, error) {
	return []byte(d.value.String()), nil
}

func (d *Decimal) UnmarshalJSON(b []byte) error {
	return d.value.UnmarshalJSON(b)
}

func (d Decimal) String() string {
	return d.value.String()
}
