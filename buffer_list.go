package memguard

import (
	"sync"
)

// BufferList stores a list of buffers in a thread-safe manner.
type bufferList struct {
	sync.RWMutex
	list []*LockedBuffer
}

// Add appends a given Buffer to the list.
func (l *bufferList) add(b ...*LockedBuffer) {
	l.Lock()
	defer l.Unlock()

	l.list = append(l.list, b...)
}

// Copy returns an instantaneous snapshot of the list.
func (l *bufferList) copy() []*LockedBuffer {
	l.Lock()
	defer l.Unlock()

	list := make([]*LockedBuffer, len(l.list))
	copy(list, l.list)

	return list
}

// Remove removes a given Buffer from the list.
func (l *bufferList) remove(b *LockedBuffer) {
	l.Lock()
	defer l.Unlock()

	for i, v := range l.list {
		if v == b {
			l.list = append(l.list[:i], l.list[i+1:]...)
			break
		}
	}
}

// Exists checks if a given buffer is in the list.
func (l *bufferList) exists(b *LockedBuffer) bool {
	l.RLock()
	defer l.RUnlock()

	for _, v := range l.list {
		if b == v {
			return true
		}
	}

	return false
}

// Flush clears the list and returns its previous contents.
func (l *bufferList) flush() []*LockedBuffer {
	l.Lock()
	defer l.Unlock()

	list := make([]*LockedBuffer, len(l.list))
	copy(list, l.list)

	l.list = nil

	return list
}
