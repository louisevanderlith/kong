package dict

import (
	"encoding/json"
	"testing"
)

func TestKeyValueUnmarshalJSON(t *testing.T) {
	in := "{\"K\":\"Number\",\"V\":\"99\"}"
	act := KeyValue{}
	err := json.Unmarshal([]byte(in), &act)

	if err != nil {
		t.Error(err)
		return
	}

	exp := KeyValue{
		Key:   "Number",
		Value: "99",
	}

	if exp.Key != act.Key {
		t.Error("Key: Expected", exp.Key, "Got", act.Key)
		return
	}

	if exp.Value != act.Value {
		t.Error("Value: Expected", exp.Value, "Got", act.Value)
		return
	}
}

func TestKeyValue_MarshalJSON(t *testing.T) {
	in := KeyValue{
		Key:   "Number",
		Value: "99",
	}

	act, err := json.Marshal(in)

	if err != nil {
		t.Error(err)
		return
	}

	exp := "{\"K\":\"Number\",\"V\":\"99\"}"

	if string(act) != exp {
		t.Error("Expected", exp, "Got", string(act))
	}
}

func TestMap_UnmarshalJSON(t *testing.T) {
	in := "[{\"K\":\"Number\",\"V\":\"99\"}, {\"K\":\"Letter\",\"V\":\"I\"}]"
	act := Map{}
	err := json.Unmarshal([]byte(in), &act)

	if err != nil {
		t.Error(err)
		return
	}

	exp := Map{KeyValue{
		Key:   "Number",
		Value: "99",
	}, {
		Key:   "Letter",
		Value: "I",
	},
	}

	if len(exp) != len(act) {
		t.Error("Expected", exp, "Got", act)
	}
}

func TestMap_MarshalJSON(t *testing.T) {
	in := Map{KeyValue{
		Key:   "Number",
		Value: "99",
	}, {
		Key:   "Letter",
		Value: "I",
	},
	}

	act, err := json.Marshal(in)

	if err != nil {
		t.Error(err)
		return
	}

	exp := "[{\"K\":\"Number\",\"V\":\"99\"},{\"K\":\"Letter\",\"V\":\"I\"}]"

	if string(act) != exp {
		t.Error("Expected", exp, "Got", string(act))
	}
}
