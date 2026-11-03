package mock

import (
	"fmt"
	"testing"
	"time"
)

func TestLLMSourcesTrackDistinctDockerIDs(t *testing.T) {
	store := newLLMStateStore(t.TempDir())
	store.setRegister(llmRegisterState{Received: true, DockerID: "taa-teellm", ReceivedAt: time.Now().Format(time.RFC3339)})
	store.recordHeartbeat(llmHeartbeatState{DockerID: "taa-teellm", Count: 1})
	store.touchLog("taa-teellm")

	sources := store.get().Sources
	if len(sources) != 1 {
		t.Fatalf("len(sources) = %d, want 1: %+v", len(sources), sources)
	}
	src := sources[0]
	if src.DockerID != "taa-teellm" {
		t.Errorf("dockerId = %q", src.DockerID)
	}
	if src.Registers != 1 || src.Heartbeats != 1 || src.Logs != 1 {
		t.Errorf("counters = %+v", src)
	}
	if src.LastEvent != llmEventLog {
		t.Errorf("lastEvent = %q, want %q", src.LastEvent, llmEventLog)
	}
}

func TestLLMSourcesCapAtFiveAndDropOldest(t *testing.T) {
	store := newLLMStateStore(t.TempDir())
	base := time.Unix(1700000000, 0)
	for i := 0; i < 7; i++ {
		at := base.Add(time.Duration(i) * time.Second)
		store.now = func() time.Time { return at }
		store.recordHeartbeat(llmHeartbeatState{DockerID: fmt.Sprintf("llm-%d", i), Count: 1})
	}

	sources := store.get().Sources
	if len(sources) != maxLLMSources {
		t.Fatalf("len(sources) = %d, want %d", len(sources), maxLLMSources)
	}
	if sources[0].DockerID != "llm-6" {
		t.Errorf("newest = %q, want llm-6", sources[0].DockerID)
	}
	for _, src := range sources {
		if src.DockerID == "llm-0" || src.DockerID == "llm-1" {
			t.Errorf("evicted source %q is still present", src.DockerID)
		}
	}
}

func TestLLMResetClearsSources(t *testing.T) {
	store := newLLMStateStore(t.TempDir())
	store.recordHeartbeat(llmHeartbeatState{DockerID: "taa-teellm", Count: 1})
	store.reset()
	got := store.get().Sources
	if got == nil {
		t.Fatal("sources after reset is nil, want an empty slice so the API renders []")
	}
	if len(got) != 0 {
		t.Fatalf("sources after reset = %+v, want empty", got)
	}
}
