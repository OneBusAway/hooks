package pubsub

import (
	"testing"
	"time"
)

func TestPublishReachesSubscriber(t *testing.T) {
	n := New()
	ch := n.Subscribe("render")
	defer n.Unsubscribe("render", ch)

	n.Publish("render", 7)
	select {
	case got := <-ch:
		if got != 7 {
			t.Fatalf("got %d", got)
		}
	case <-time.After(time.Second):
		t.Fatal("never received")
	}
}

func TestPublishDoesNotBlockOnFullChannel(t *testing.T) {
	n := New()
	ch := n.Subscribe("render")
	defer n.Unsubscribe("render", ch)

	n.Publish("render", 1)
	// Second publish should drop, not block.
	done := make(chan struct{})
	go func() {
		n.Publish("render", 2)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Publish blocked")
	}
}

func TestPublishToOtherSourceIgnored(t *testing.T) {
	n := New()
	ch := n.Subscribe("render")
	defer n.Unsubscribe("render", ch)

	n.Publish("stripe", 1)
	select {
	case got := <-ch:
		t.Fatalf("got cross-source signal %d", got)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestUnsubscribeReleases(t *testing.T) {
	n := New()
	ch := n.Subscribe("render")
	if n.SubscriberCount("render") != 1 {
		t.Fatal("subscribe didn't register")
	}
	n.Unsubscribe("render", ch)
	if n.SubscriberCount("render") != 0 {
		t.Fatal("unsubscribe didn't release")
	}
}
