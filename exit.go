package memguard

import (
	"os"
)

/*
Exit terminates the process with a specified exit code but securely wipes and cleans up sensitive data before doing so.
*/
func Exit(c int) {
	// Wipe the encryption key used to encrypt data inside Enclaves.
	getKey().Destroy()

	// Get a snapshot of existing Buffers.
	snapshot := buffers.copy() // copy ensures the buffers stay in the list until they are destroyed.

	// Destroy them, performing the usual sanity checks.
	for _, b := range snapshot {
		b.Destroy()
	}

	// Exit with the specified exit code.
	os.Exit(c)
}

/*
Panic is identical to the builtin panic except it purges the session before calling panic.
*/
func Panic(err error) {
	Purge() // creates a new key so it is safe to recover from this panic
	panic(err)
}
