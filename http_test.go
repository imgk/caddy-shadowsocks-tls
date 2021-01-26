package shadowsocks

import "testing"

func TestStringToByteSlice(t *testing.T) {
	for _, s := range []string{
		"",
		"Test1",
		"Test2",
	} {
		if string(StringToByteSlice(s)) == s {
			continue
		}
		t.Errorf("error for: %s", s)
	}
}
