package memguard

import (
	"github.com/awnumar/memcall"
)

/* Enhancement: check for low memory locking limit and print warning?*/

/*
ScrambleBytes overwrites an arbitrary buffer with cryptographically-secure random bytes.
*/
func ScrambleBytes(buf []byte) {
	if err := Scramble(buf); err != nil {
		Panic(err)
	}
}

/*
WipeBytes overwrites an arbitrary buffer with zeroes.
*/
func WipeBytes(buf []byte) {
	Wipe(buf)
}

/*
Purge resets the session key to a fresh value and destroys all existing LockedBuffers. Existing Enclave objects will no longer be decryptable.
*/
func Purge() {
	// Halt the re-key cycle and prevent new enclaves or keys being created.
	keyMtx.Lock()
	defer keyMtx.Unlock()
	if !key.Destroyed() {
		key.Lock()
		defer key.Unlock()
	}

	// Get a snapshot of existing Buffers.
	snapshot := buffers.flush()

	// Destroy them, performing the usual sanity checks.
	for _, b := range snapshot {
		b.Destroy()
	}
}

/*
SafePanic wipes all it can before calling panic(v).
*/
func SafePanic(err error) {
	Panic(err)
}

/*
SafeExit destroys everything sensitive before exiting with a specified status code.
*/
func SafeExit(c int) {
	Exit(c)
}

func init() {
	memcall.DisableCoreDumps()
}
