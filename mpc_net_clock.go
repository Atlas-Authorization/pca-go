package pca

// The injectable mesh clock: the connect and receive deadlines read time and schedule their wake-ups through this interface, so
// a test can move time exactly (MpcManualClock) instead of depending on how loaded the machine is. Default: real time.

import (
	"sort"
	"sync"
	"time"
)

// MpcMeshClock is the mesh's time source.
type MpcMeshClock interface {
	Now() time.Time
	// AfterFunc runs fn once after d of clock time; the returned func cancels it.
	AfterFunc(d time.Duration, fn func()) (stop func())
}

// MpcWallClock is real time.
type MpcWallClock struct{}

func (MpcWallClock) Now() time.Time { return time.Now() }

func (MpcWallClock) AfterFunc(d time.Duration, fn func()) func() {
	t := time.AfterFunc(d, fn)
	return func() { t.Stop() }
}

type mpcManualTimer struct {
	due time.Time
	seq int
	fn  func()
}

// MpcManualClock is a virtual clock: time moves only on Advance, which fires every timer that falls due (earliest first).
type MpcManualClock struct {
	mu     sync.Mutex
	t      time.Time
	seq    int
	timers map[int]*mpcManualTimer
}

func NewMpcManualClock() *MpcManualClock {
	return &MpcManualClock{t: time.Unix(0, 0), timers: map[int]*mpcManualTimer{}}
}

func (c *MpcManualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *MpcManualClock) AfterFunc(d time.Duration, fn func()) func() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	id := c.seq
	c.timers[id] = &mpcManualTimer{due: c.t.Add(d), seq: id, fn: fn}
	return func() {
		c.mu.Lock()
		delete(c.timers, id)
		c.mu.Unlock()
	}
}

// Advance moves virtual time forward by d, firing due timers in order of due time (then creation).
func (c *MpcManualClock) Advance(d time.Duration) {
	c.mu.Lock()
	target := c.t.Add(d)
	for {
		var due []*mpcManualTimer
		for _, x := range c.timers {
			if !x.due.After(target) {
				due = append(due, x)
			}
		}
		if len(due) == 0 {
			break
		}
		sort.Slice(due, func(i, j int) bool {
			if !due[i].due.Equal(due[j].due) {
				return due[i].due.Before(due[j].due)
			}
			return due[i].seq < due[j].seq
		})
		x := due[0]
		delete(c.timers, x.seq)
		if x.due.After(c.t) {
			c.t = x.due
		}
		c.mu.Unlock()
		x.fn()
		c.mu.Lock()
	}
	c.t = target
	c.mu.Unlock()
}

// Pending is the number of armed timers.
func (c *MpcManualClock) Pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.timers)
}
