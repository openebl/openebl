package model

import (
	"encoding/json"
	"time"
)

// DateTime uses RFC3339 format. It's the same as ISO8601 in eBL use.
// The time zone offset is kept in time.Time.
type DateTime struct {
	timeVal time.Time
}

func (dt DateTime) Unix() int64 {
	return dt.timeVal.Unix()
}

func (dt *DateTime) UnmarshalJSON(b []byte) error {
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}

	newDt, err := NewDateTimeFromString(s)
	if err != nil {
		return err
	}
	*dt = newDt
	return nil
}

func (dt DateTime) MarshalJSON() ([]byte, error) {
	strVal := dt.timeVal.Format(time.RFC3339)
	return json.Marshal(strVal)
}

func NewDateTime(t time.Time) DateTime {
	return DateTime{
		timeVal: t,
	}
}

func NewDateTimeFromUnix(t int64) DateTime {
	return DateTime{
		timeVal: time.Unix(t, 0).UTC(),
	}
}

func NewDateTimeFromString(t string) (DateTime, error) {
	ts, err := time.Parse(time.RFC3339, t)
	if err != nil {
		return DateTime{}, err
	}
	return DateTime{
		timeVal: ts,
	}, nil
}

// Date always use UTC timezone.
type Date struct {
	timeVal time.Time
}

func (dt Date) Unix() int64 {
	return dt.timeVal.Unix()
}

func (dt Date) GetTime() time.Time {
	return dt.timeVal
}

func (dt Date) MarshalJSON() ([]byte, error) {
	strVal := dt.timeVal.Format(time.DateOnly)
	return json.Marshal(strVal)
}

func (dt *Date) UnmarshalJSON(b []byte) error {
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}

	newDt, err := NewDateFromString(s)
	if err != nil {
		return err
	}
	*dt = newDt
	return err
}

func NewDateFromString(t string) (Date, error) {
	ts, err := time.ParseInLocation(time.DateOnly, t, time.UTC)
	if err != nil {
		return Date{}, err
	}
	return Date{
		timeVal: ts,
	}, nil
}

func NewDateFromStringNoError(t string) Date {
	ts, err := time.ParseInLocation(time.DateOnly, t, time.UTC)
	if err != nil {
		panic(err)
	}
	return Date{
		timeVal: ts,
	}
}
