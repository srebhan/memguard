package memguard

import (
	"errors"
	"sync"

	"github.com/awnumar/memguard/core"
)

var (
	key    = &Coffer{}
	keyMtx = sync.Mutex{}
)

func getOrCreateKey() *Coffer {
	keyMtx.Lock()
	defer keyMtx.Unlock()

	if key.Destroyed() {
		key = NewCoffer()
	}

	return key
}

func getKey() *Coffer {
	keyMtx.Lock()
	defer keyMtx.Unlock()

	return key
}

// ErrNullEnclave is returned when attempting to construct an enclave of size less than one.
var ErrNullEnclave = errors.New("<memguard::ErrNullEnclave> enclave size must be greater than zero")

/*
Enclave is a sealed and encrypted container for sensitive data.
*/
type Enclave struct {
	ciphertext []byte
}

/*
NewEnclave seals up some data into an encrypted enclave object. The buffer is wiped after the data is copied. If the length of the buffer is zero, the function will return nil.

A LockedBuffer may alternatively be converted into an Enclave object using its Seal method. This will also have the effect of destroying the LockedBuffer.
*/
func NewEnclave(src []byte) *Enclave {
	// Return an error if length < 1.
	if len(src) < 1 {
		return nil
	}

	// Create a new Enclave.
	var e Enclave

	// Get a view of the key.
	k, err := getOrCreateKey().View()
	if err != nil {
		core.Panic(err)
	}

	// Encrypt the plaintext.
	e.ciphertext, err = Encrypt(src, k.data)
	if err != nil {
		core.Panic(err) // key is not 32 bytes long
	}

	// Destroy our copy of the key.
	k.Destroy()

	// Wipe the given buffer.
	Wipe(src)

	return &e
}

/*
NewEnclaveRandom generates and seals arbitrary amounts of cryptographically-secure random bytes into an encrypted enclave object. If size is not strictly positive the function will return nil.
*/
func NewEnclaveRandom(size int) *Enclave {
	// todo: stream data into enclave
	b := NewBufferRandom(size)
	return b.Seal()
}

/*
Open decrypts an Enclave object and places its contents into an immutable LockedBuffer. An error will be returned if decryption failed.
*/
func (e *Enclave) Open() (*LockedBuffer, error) {
	bufsize := e.Size()

	if bufsize < 1 {
		core.Panic("<memguard> ciphertext has invalid length") // ciphertext has invalid length
	}

	// Allocate a secure Buffer to hold the decrypted data.
	b := NewBuffer(bufsize)

	// Grab a view of the key.
	k, err := getOrCreateKey().View()
	if err != nil {
		return nil, err
	}

	// Decrypt the enclave into the buffer we created.
	b.RLock()
	if _, err := Decrypt(e.ciphertext, k.data, b.data); err != nil {
		b.RUnlock()
		return nil, err
	}
	b.RUnlock()

	// Destroy our copy of the key.
	k.Destroy()

	b.Freeze()

	return b, nil
}

/*
Size returns the number of bytes of data stored within an Enclave.
*/
func (e *Enclave) Size() int {
	return len(e.ciphertext) - Overhead
}
