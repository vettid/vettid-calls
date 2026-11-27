package turnagent

import (
	"syscall"
	"testing"
)

func TestReloadSignalIsSIGUSR2(t *testing.T) {
	if reloadSignal != syscall.SIGUSR2 {
		t.Fatalf("reloadSignal %d, SIGUSR2 %d", reloadSignal, syscall.SIGUSR2)
	}
}
