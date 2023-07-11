package iaqualink

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStringOrNumber(t *testing.T) {
	t.Run("Encode and Decode", func(t *testing.T) {
		t.Run("String", func(t *testing.T) {
			var value StringOrNumber
			input := []byte(`"676446"`)
			err := json.Unmarshal(input, &value)
			require.Nil(t, err)
			assert.Equal(t, StringOrNumber{stringValue: "676446", isString: true}, value)
			assert.Equal(t, "676446", value.String())

			output, err := json.Marshal(value)
			require.Nil(t, err)
			assert.Equal(t, input, output)
		})
		t.Run("Number", func(t *testing.T) {
			var value StringOrNumber
			input := []byte(`676446`)
			err := json.Unmarshal(input, &value)
			require.Nil(t, err)
			assert.Equal(t, StringOrNumber{stringValue: "676446", isString: false}, value)
			assert.Equal(t, "676446", value.String())

			output, err := json.Marshal(value)
			require.Nil(t, err)
			assert.Equal(t, input, output)
		})
		t.Run("Bad String", func(t *testing.T) {
			var value StringOrNumber
			input := []byte(`"676446`)
			err := json.Unmarshal(input, &value)
			require.NotNil(t, err)
		})
		t.Run("Bad Number", func(t *testing.T) {
			var value StringOrNumber
			input := []byte(`676 446`)
			err := json.Unmarshal(input, &value)
			require.NotNil(t, err)
		})
	})
}
