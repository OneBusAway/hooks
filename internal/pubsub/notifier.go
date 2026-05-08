// Package pubsub provides an in-process per-source publish/subscribe channel
// used to wake SSE handlers and push dispatchers when a new event is ingested.
//
// Semantics: publishers never block. If a subscriber's channel buffer is
// full, the SIGNAL is dropped — not the event. Every subscriber is expected
// to backfill from the durable store after waking, so a missed signal turns
// into a slightly delayed read, never lost data.
package pubsub

import "sync"

// Notifier broadcasts the latest sequence per source to subscribed channels.
type Notifier struct {
	mu   sync.Mutex
	subs map[string]map[chan int64]struct{}
}

// New returns an empty Notifier.
func New() *Notifier {
	return &Notifier{subs: map[string]map[chan int64]struct{}{}}
}

// Subscribe returns a buffered channel that receives the latest sequence
// number whenever Publish(source, ...) is called. Buffer size 1 is correct:
// a missed signal due to a slow consumer is fine; the event itself is in the
// store and the consumer will pick it up on its next read.
//
// Callers MUST eventually call Unsubscribe to release the registration.
func (n *Notifier) Subscribe(source string) chan int64 {
	ch := make(chan int64, 1)
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.subs[source] == nil {
		n.subs[source] = map[chan int64]struct{}{}
	}
	n.subs[source][ch] = struct{}{}
	return ch
}

// Unsubscribe removes ch from source's subscriber set and closes it.
func (n *Notifier) Unsubscribe(source string, ch chan int64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	subs, ok := n.subs[source]
	if !ok {
		return
	}
	if _, present := subs[ch]; !present {
		return
	}
	delete(subs, ch)
	close(ch)
	if len(subs) == 0 {
		delete(n.subs, source)
	}
}

// Publish notifies every subscriber of source about the latest sequence.
// Send is non-blocking: if a subscriber channel is full, the signal is
// dropped (the subscriber will catch up via the store on its next read).
func (n *Notifier) Publish(source string, sequence int64) {
	n.mu.Lock()
	subs := n.subs[source]
	chans := make([]chan int64, 0, len(subs))
	for ch := range subs {
		chans = append(chans, ch)
	}
	n.mu.Unlock()

	for _, ch := range chans {
		select {
		case ch <- sequence:
		default:
			// Buffer full; drop signal, not event.
		}
	}
}

// SubscriberCount returns the count of currently-subscribed channels for source.
// Exposed for tests.
func (n *Notifier) SubscriberCount(source string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.subs[source])
}
