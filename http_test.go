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

func TestGenKey(t *testing.T) {
	if len(GenKey("Test1234")) == AuthLen {
		return
	}
	t.Errorf("auth length")
}
