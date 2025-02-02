package memguard

import (
	"errors"
	"sync"
	"time"
)

// Interval of time between each verify & re-key cycle.
const interval = 500 * time.Millisecond

// ErrCofferExpired is returned when a function attempts to perform an operation using a secure key container that has been wiped and destroyed.
var ErrCofferExpired = errors.New("<memguard::core::ErrCofferExpired> attempted usage of destroyed key object")

/*
Coffer is a specialized container for securing highly-sensitive, 32 byte values.
*/
type Coffer struct {
	sync.Mutex

	left  *LockedBuffer
	right *LockedBuffer

	rand *LockedBuffer
}

// NewCoffer is a raw constructor for the *Coffer object.
func NewCoffer() *Coffer {
	s := new(Coffer)
	s.left = NewBuffer(32)
	s.right = NewBuffer(32)
	s.rand = NewBuffer(32)

	s.Init()

	go func(s *Coffer) {
		ticker := time.NewTicker(interval)

		for range ticker.C {
			if err := s.Rekey(); err != nil {
				break
			}
		}
	}(s)

	return s
}

// Init is used to reset the value stored inside a Coffer to a new random 32 byte value, overwriting the old.
func (s *Coffer) Init() error {
	if s.Destroyed() {
		return ErrCofferExpired
	}

	s.Lock()
	defer s.Unlock()

	if err := Scramble(s.left.data); err != nil {
		return err
	}
	if err := Scramble(s.right.data); err != nil {
		return err
	}

	// left = left XOR hash(right)
	hr := Hash(s.right.data)
	for i := range hr {
		s.left.data[i] ^= hr[i]
	}
	Wipe(hr)

	return nil
}

/*
View returns a snapshot of the contents of a Coffer inside a Buffer. As usual the Buffer should be destroyed as soon as possible after use by calling the Destroy method.
*/
func (s *Coffer) View() (*LockedBuffer, error) {
	if s.Destroyed() {
		return nil, ErrCofferExpired
	}

	b := NewBuffer(32)

	s.Lock()
	defer s.Unlock()

	// data = hash(right) XOR left
	h := Hash(s.right.data)

	for i := range b.data {
		b.data[i] = h[i] ^ s.left.data[i]
	}
	Wipe(h)

	return b, nil
}

/*
Rekey is used to re-key a Coffer. Ideally this should be done at short, regular intervals.
*/
func (s *Coffer) Rekey() error {
	if s.Destroyed() {
		return ErrCofferExpired
	}

	s.Lock()
	defer s.Unlock()

	if err := Scramble(s.rand.data); err != nil {
		return err
	}

	// Hash the current right partition for later.
	hashRightCurrent := Hash(s.right.data)

	// new_right = current_right XOR buf32
	for i := range s.right.data {
		s.right.data[i] ^= s.rand.data[i]
	}

	// new_left = current_left XOR hash(current_right) XOR hash(new_right)
	hashRightNew := Hash(s.right.data)
	for i := range s.left.data {
		s.left.data[i] ^= hashRightCurrent[i] ^ hashRightNew[i]
	}
	Wipe(hashRightNew)

	return nil
}

/*
Destroy wipes and cleans up all memory related to a Coffer object. Once this method has been called, the Coffer can no longer be used and a new one should be created instead.
*/
func (s *Coffer) Destroy() {
	s.Lock()
	defer s.Unlock()

	s.left.Destroy()
	s.right.Destroy()
	s.rand.Destroy()
}

// Destroyed returns a boolean value indicating if a Coffer has been destroyed.
func (s *Coffer) Destroyed() bool {
	if s == nil {
		return true
	}

	s.Lock()
	defer s.Unlock()

	if s.left == nil || s.right == nil {
		return true
	}

	return s.left.data == nil || s.right.data == nil
}
