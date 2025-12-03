package shared

import (
	"encoding/json"
)

// String represents a nullable string
type NullString struct {
	String string
	Valid  bool
}

// UnmarshalJSON implements json.Unmarshaler.
func (ns *NullString) UnmarshalJSON(data []byte) error {
	// Handle null case
	if string(data) == "null" {
		ns.Valid = false
		return nil
	}

	// Try to unmarshal as a string
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	ns.String = s
	ns.Valid = true
	return nil
}

// Int represents a nullable int64
type NullInt struct {
	Int64 int64
	Valid bool
}

// UnmarshalJSON implements json.Unmarshaler.
func (ni *NullInt) UnmarshalJSON(data []byte) error {
	// Handle null case
	if string(data) == "null" {
		ni.Valid = false
		return nil
	}

	// Try to unmarshal as an int64
	var i int64
	if err := json.Unmarshal(data, &i); err != nil {
		return err
	}

	ni.Int64 = i
	ni.Valid = true
	return nil
}
