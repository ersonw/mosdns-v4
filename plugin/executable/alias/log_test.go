package alias

import (
	"testing"

	"github.com/ersonw/mosdns-v4/coremain"
	"go.uber.org/zap"
)

func TestLogHelperDoesNotRecurse(t *testing.T) {
	p := &plugin{}
	if p.log() == nil {
		t.Fatal("nil BP returned a nil logger")
	}
	p.BP = coremain.NewBP("test", PluginType, zap.NewNop(), nil)
	if p.log() == nil {
		t.Fatal("BP logger is nil")
	}
}
