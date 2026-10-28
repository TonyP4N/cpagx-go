package capacity

import (
	"testing"
	"time"
)

func TestOperatorHTTPTimeoutsPreserveDefaultsAndRejectUnknown(t *testing.T) {
	for _, test := range []struct {
		version                                              string
		readPublic, writePublic, readInternal, writeInternal int
	}{
		{"", 30, 60, 15, 30}, {DevelopmentS100, 30, 180, 15, 180}, {Engineering, 60, 600, 60, 600},
	} {
		b, err := HTTPTimeouts(test.version)
		if err != nil {
			t.Fatal(err)
		}
		if b.PublicRead != time.Duration(test.readPublic)*time.Second || b.PublicWrite != time.Duration(test.writePublic)*time.Second || b.InternalRead != time.Duration(test.readInternal)*time.Second || b.InternalWrite != time.Duration(test.writeInternal)*time.Second {
			t.Fatalf("%s: %+v", test.version, b)
		}
	}
	if _, err := HTTPTimeouts("unsupported-future-resource"); err == nil {
		t.Fatal("unknown operator HTTP budget accepted")
	}
}
