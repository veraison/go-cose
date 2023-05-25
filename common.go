package cose

import (
	"errors"
	"fmt"
)

// intOrStr is a value that can be either an int or a tstr when serialized to
// CBOR.
type intOrStr struct {
	intVal int64
	strVal *string
}

func newIntOrStr(v interface{}) *intOrStr {
	var ios intOrStr
	if err := ios.Set(v); err != nil {
		return nil
	}
	return &ios
}

func (ios intOrStr) Int() int64 {
	return ios.intVal
}

func (ios intOrStr) String() string {
	if ios.IsString() {
		return *ios.strVal
	} else if ios.IsInt() {
		return fmt.Sprint(ios.intVal)
	}
	return ""
}

func (ios intOrStr) IsInt() bool {
	return ios.strVal == nil
}

func (ios intOrStr) IsString() bool {
	return ios.strVal != nil
}

func (ios intOrStr) Value() interface{} {
	if ios.IsInt() {
		return ios.intVal
	} else if ios.IsString() {
		return *ios.strVal
	}

	return nil
}

func (ios *intOrStr) Set(v interface{}) error {
	switch t := v.(type) {
	case int64:
		ios.intVal = t
		ios.strVal = nil
	case int:
		ios.intVal = int64(t)
		ios.strVal = nil
	case string:
		ios.strVal = &t
		ios.intVal = 0
	default:
		return fmt.Errorf("must be int or string, found %T", t)
	}

	return nil
}

// MarshalCBOR returns the encoded CBOR representation of the intOrString, as
// either int or tstr, depending on the value. If no value has been set,
// intOrStr is encoded as a zero-length tstr.
func (ios intOrStr) MarshalCBOR() ([]byte, error) {
	if ios.IsInt() {
		return encMode.Marshal(ios.intVal)
	} else if ios.IsString() {
		return encMode.Marshal(*ios.strVal)
	}

	return encMode.Marshal("")
}

// UnmarshalCBOR unmarshals the provided CBOR encoded data (must be an int,
// uint, or tstr).
func (ios *intOrStr) UnmarshalCBOR(data []byte) error {
	if len(data) == 0 {
		return errors.New("zero length buffer")
	}

	var val interface{}
	if err := decMode.Unmarshal(data, &val); err != nil {
		return err
	}

	return ios.Set(val)
}
