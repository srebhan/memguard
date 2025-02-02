package memguard

import (
	"bytes"
	"errors"
	"io"
	"os"
	"sync"
	"unsafe"

	"github.com/awnumar/memcall"
)

var buffers = new(bufferList)

// ErrNullBuffer is returned when attempting to construct a buffer of size less than one.
var ErrNullBuffer = errors.New("<memguard::ErrNullBuffer> buffer size must be greater than zero")

// ErrBufferExpired is returned when attempting to perform an operation on or with a buffer that has been destroyed.
var ErrBufferExpired = errors.New("<memguard::ErrBufferExpired> buffer has been purged from memory and can no longer be used")

// ErrBufferInvalidCanary is returned when the canary after the buffer doesn't match the expectation
var ErrBufferInvalidCanary = errors.New("<memguard:ErrBufferInvalidCanary> canary verification failed; buffer overflow detected")

/*
LockedBuffer is a structure that holds raw sensitive data.

The number of LockedBuffers that you are able to create is limited by how much memory your system's kernel allows each process to mlock/VirtualLock. Therefore you should call Destroy on LockedBuffers that you no longer need or defer a Destroy call after creating a new LockedBuffer.
*/
type LockedBuffer struct {
	sync.RWMutex // Local mutex lock // TODO: this does not protect 'data' field

	alive   bool // Signals that destruction has not come
	mutable bool // Mutability state of underlying memory

	data   []byte // Portion of memory holding the data
	memory []byte // Entire allocated memory region

	preguard  []byte // Guard page addressed before the data
	inner     []byte // Inner region between the guard pages
	postguard []byte // Guard page addressed after the data

	canary []byte // Value written behind data to detect spillage
}

// Constructs a LockedBuffer object from a Buffer while also setting up the finalizer for it.
func (buf *LockedBuffer) copy() *LockedBuffer {
	return &LockedBuffer{
		alive:     buf.alive,
		mutable:   buf.mutable,
		data:      buf.data,
		memory:    buf.memory,
		preguard:  buf.preguard,
		inner:     buf.inner,
		postguard: buf.postguard,
		canary:    buf.canary,
	}
}

// Constructs a quasi-destroyed LockedBuffer with size zero.
func newNullBuffer() *LockedBuffer {
	return &LockedBuffer{}
}

/*
NewBuffer creates a mutable data container of the specified size.
*/
func NewBuffer(size int) *LockedBuffer {
	// Construct a Buffer of the specified size.
	if size < 1 {
		Panic(ErrNullBuffer)
	}

	var b LockedBuffer
	var err error

	// Allocate the total needed memory
	innerLen := roundToPageSize(size)
	b.memory, err = memcall.Alloc((2 * pageSize) + innerLen)
	if err != nil {
		Panic(err)
	}

	// Construct slice reference for data buffer.
	b.data = getBytes(&b.memory[pageSize+innerLen-size], size)

	// Construct slice references for page sectors.
	b.preguard = getBytes(&b.memory[0], pageSize)
	b.inner = getBytes(&b.memory[pageSize], innerLen)
	b.postguard = getBytes(&b.memory[pageSize+innerLen], pageSize)

	// Construct slice reference for canary portion of inner page.
	b.canary = getBytes(&b.memory[pageSize], len(b.inner)-len(b.data))

	// Lock the pages that will hold sensitive data.
	if err := memcall.Lock(b.inner); err != nil {
		Panic(err)
	}

	// Initialise the canary value and reference regions.
	if err := Scramble(b.canary); err != nil {
		Panic(err)
	}
	Copy(b.preguard, b.canary)
	Copy(b.postguard, b.canary)

	// Make the guard pages inaccessible.
	if err := memcall.Protect(b.preguard, memcall.NoAccess()); err != nil {
		Panic(err)
	}
	if err := memcall.Protect(b.postguard, memcall.NoAccess()); err != nil {
		Panic(err)
	}

	// Set remaining properties
	b.alive = true
	b.mutable = true

	// Append the container to list of active buffers.
	buffers.add(&b)

	// Return the created Buffer to the caller.
	return &b
}

/*
NewBufferFromBytes constructs an immutable buffer from a byte slice. The source buffer is wiped after the value has been copied over to the created container.
*/
func NewBufferFromBytes(src []byte) *LockedBuffer {
	// Construct a buffer of the correct size.
	b := NewBuffer(len(src))
	if b.Size() == 0 {
		return b
	}

	// Move the data over.
	b.Move(src)

	// Make the buffer immutable.
	b.Freeze()

	// Return the created Buffer object.
	return b
}

/*
NewBufferFromReader reads some number of bytes from an io.Reader into an immutable LockedBuffer.

An error is returned precisely when the number of bytes read is less than the requested amount. Any data read is returned in either case.
*/
func NewBufferFromReader(r io.Reader, size int) (*LockedBuffer, error) {
	// Construct a buffer of the provided size.
	b := NewBuffer(size)
	if b.Size() == 0 {
		return b, nil
	}

	// Attempt to fill it with data from the Reader.
	if n, err := io.ReadFull(r, b.Bytes()); err != nil {
		if n == 0 {
			// nothing was read
			b.Destroy()
			return newNullBuffer(), err
		}

		// partial read
		d := NewBuffer(n)
		d.Copy(b.Bytes()[:n])
		d.Freeze()
		b.Destroy()
		return d, err
	}

	// success
	b.Freeze()
	return b, nil
}

/*
NewBufferFromReaderUntil constructs an immutable buffer containing data sourced from an io.Reader object.

If an error is encountered before the delimiter value, the error will be returned along with the data read up until that point.
*/
func NewBufferFromReaderUntil(r io.Reader, delim byte) (*LockedBuffer, error) {
	// Construct a buffer with a data page that fills an entire memory page.
	b := NewBuffer(os.Getpagesize())

	// Loop over the buffer a byte at a time.
	for i := 0; ; i++ {
		// If we have filled this buffer...
		if i == b.Size() {
			// Construct a new buffer that is a page size larger.
			c := NewBuffer(b.Size() + os.Getpagesize())

			// Copy the data over.
			c.Copy(b.Bytes())

			// Destroy the old one and reassign its variable.
			b.Destroy()
			b = c
		}

		// Attempt to read a single byte.
		n, err := r.Read(b.Bytes()[i : i+1])
		if n != 1 { // if we did not read a byte
			if err == nil { // and there was no error
				i-- // try again
				continue
			}
			// if instead there was an error, we're done early
			if i == 0 { // no data read
				b.Destroy()
				return newNullBuffer(), err
			}
			d := NewBuffer(i)
			d.Copy(b.Bytes()[:i])
			d.Freeze()
			b.Destroy()
			return d, err
		}
		// we managed to read a byte, check if it was the delimiter
		// note that errors are ignored in this case where we got data
		if b.Bytes()[i] == delim {
			if i == 0 {
				// if first byte was delimiter, there's no data to return
				b.Destroy()
				return newNullBuffer(), nil
			}
			d := NewBuffer(i)
			d.Copy(b.Bytes()[:i])
			d.Freeze()
			b.Destroy()
			return d, nil
		}
	}
}

/*
NewBufferFromEntireReader reads from an io.Reader into an immutable buffer. It will continue reading until EOF.

A nil error is returned precisely when we managed to read all the way until EOF. Any data read is returned in either case.
*/
func NewBufferFromEntireReader(r io.Reader) (*LockedBuffer, error) {
	// Create a buffer with a data region of one page size.
	b := NewBuffer(os.Getpagesize())

	for read := 0; ; {
		// Attempt to read some data from the reader.
		n, err := r.Read(b.Bytes()[read:])

		// Nothing read but no error, try again.
		if n == 0 && err == nil {
			continue
		}

		// 1) so either have data and no error
		// 2) or have error and no data
		// 3) or both have data and have error

		// Increment the read count by the number of bytes that we just read.
		read += n

		if err != nil {
			// Suppress EOF error
			if err == io.EOF {
				err = nil
			}
			// We're done, return the data.
			if read == 0 {
				// No data read.
				b.Destroy()
				return newNullBuffer(), err
			}
			d := NewBuffer(read)
			d.Copy(b.Bytes()[:read])
			d.Freeze()
			b.Destroy()
			return d, err
		}

		// If we've filled this buffer, grow it by another page size.
		if len(b.Bytes()[read:]) == 0 {
			d := NewBuffer(b.Size() + os.Getpagesize())
			d.Copy(b.Bytes())
			b.Destroy()
			b = d
		}
	}
}

/*
NewBufferRandom constructs an immutable buffer filled with cryptographically-secure random bytes.
*/
func NewBufferRandom(size int) *LockedBuffer {
	// Construct a buffer of the specified size.
	b := NewBuffer(size)
	if b.Size() == 0 {
		return b
	}

	// Fill the buffer with random bytes.
	b.Scramble()

	// Make the buffer immutable.
	b.Freeze()

	// Return the created Buffer object.
	return b
}

// Freeze makes a LockedBuffer's memory immutable. The call can be reversed with Melt.
func (b *LockedBuffer) Freeze() {
	b.Lock()
	defer b.Unlock()

	if !b.alive || !b.mutable {
		return
	}

	if err := memcall.Protect(b.inner, memcall.ReadOnly()); err != nil {
		Panic(err)
	}
	b.mutable = false
}

// Melt makes a LockedBuffer's memory mutable. The call can be reversed with Freeze.
func (b *LockedBuffer) Melt() {
	b.Lock()
	defer b.Unlock()

	if !b.alive || b.mutable {
		return
	}

	if err := memcall.Protect(b.inner, memcall.ReadWrite()); err != nil {
		Panic(err)
	}
	b.mutable = true
}

/*
Seal takes a LockedBuffer object and returns its contents encrypted inside a sealed Enclave object. The LockedBuffer is subsequently destroyed and its contents wiped.

If Seal is called on a destroyed buffer, a nil enclave is returned.
*/
func (b *LockedBuffer) Seal() *Enclave {
	// Check if the Buffer has been destroyed.
	if !b.alive {
		return nil
	}

	b.Melt() // Make the buffer mutable so that we can wipe it.

	// Construct the Enclave from the Buffer's data.
	b.RLock() // Attain a read lock.
	e := NewEnclave(b.data)
	b.RUnlock()

	// Destroy the Buffer object.
	b.Destroy()

	// Return the newly created Enclave.
	return e
}

/*
Copy performs a time-constant copy into a LockedBuffer. Move is preferred if the source is not also a LockedBuffer or if the source is no longer needed.
*/
func (b *LockedBuffer) Copy(src []byte) {
	b.CopyAt(0, src)
}

/*
CopyAt performs a time-constant copy into a LockedBuffer at an offset. Move is preferred if the source is not also a LockedBuffer or if the source is no longer needed.
*/
func (b *LockedBuffer) CopyAt(offset int, src []byte) {
	if !b.IsAlive() {
		return
	}

	b.Lock()
	defer b.Unlock()

	Copy(b.Bytes()[offset:], src)
}

/*
Move performs a time-constant move into a LockedBuffer. The source is wiped after the bytes are copied.
*/
func (b *LockedBuffer) Move(src []byte) {
	b.MoveAt(0, src)
}

/*
MoveAt performs a time-constant move into a LockedBuffer at an offset. The source is wiped after the bytes are copied.
*/
func (b *LockedBuffer) MoveAt(offset int, src []byte) {
	if !b.IsAlive() {
		return
	}

	b.Lock()
	defer b.Unlock()

	Move(b.Bytes()[offset:], src)
}

/*
Scramble attempts to overwrite the data with cryptographically-secure random bytes.
*/
func (b *LockedBuffer) Scramble() {
	if !b.IsAlive() {
		return
	}

	b.Lock()
	defer b.Unlock()
	if err := Scramble(b.data); err != nil {
		Panic(err)
	}
}

/*
Wipe attempts to overwrite the data with zeros.
*/
func (b *LockedBuffer) Wipe() {
	if !b.IsAlive() {
		return
	}

	b.Lock()
	defer b.Unlock()

	Wipe(b.Bytes())
}

/*
Size gives you the length of a given LockedBuffer's data segment. A destroyed LockedBuffer will have a size of zero.
*/
func (b *LockedBuffer) Size() int {
	return len(b.Bytes())
}

func (b *LockedBuffer) Alive() bool {
	b.RLock()
	defer b.RUnlock()
	return b.alive
}

func (b *LockedBuffer) Data() []byte {
	return b.data
}

/*
Destroy wipes and frees the underlying memory of a LockedBuffer. The LockedBuffer will not be accessible or usable after this calls is made.
*/
func (b *LockedBuffer) Destroy() {
	// Attain a mutex lock on this Buffer.
	b.Lock()
	defer b.Unlock()

	// Return if it's already destroyed.
	if !b.alive {
		return
	}

	// Make all of the memory readable and writable.
	if err := memcall.Protect(b.memory, memcall.ReadWrite()); err != nil {
		Panic(err)
	}
	b.mutable = true

	// Wipe data field.
	Wipe(b.data)

	// Verify the canary
	if !Equal(b.preguard, b.postguard) || !Equal(b.preguard[:len(b.canary)], b.canary) {
		Panic(ErrBufferInvalidCanary)
	}

	// Wipe the memory.
	Wipe(b.memory)

	// Unlock pages locked into memory.
	if err := memcall.Unlock(b.inner); err != nil {
		Panic(err)
	}

	// Free all related memory.
	if err := memcall.Free(b.memory); err != nil {
		Panic(err)
	}

	// Reset the fields.
	b.alive = false
	b.mutable = false
	b.data = nil
	b.memory = nil
	b.preguard = nil
	b.inner = nil
	b.postguard = nil
	b.canary = nil

	buffers.remove(b)
}

/*
IsAlive returns a boolean value indicating if a LockedBuffer is alive, i.e. that it has not been destroyed.
*/
func (b *LockedBuffer) IsAlive() bool {
	b.RLock()
	defer b.RUnlock()
	return b.alive
}

/*
IsMutable returns a boolean value indicating if a LockedBuffer is mutable.
*/
func (b *LockedBuffer) IsMutable() bool {
	b.RLock()
	defer b.RUnlock()
	return b.mutable
}

/*
EqualTo performs a time-constant comparison on the contents of a LockedBuffer with a given buffer. A destroyed LockedBuffer will always return false.
*/
func (b *LockedBuffer) EqualTo(buf []byte) bool {
	b.RLock()
	defer b.RUnlock()

	return Equal(b.Bytes(), buf)
}

/*
	Functions for representing the memory region as various data types.
*/

/*
Bytes returns a byte slice referencing the protected region of memory.
*/
func (b *LockedBuffer) Bytes() []byte {
	return b.data
}

/*
Reader returns a Reader object referencing the protected region of memory.
*/
func (b *LockedBuffer) Reader() *bytes.Reader {
	return bytes.NewReader(b.Bytes())
}

/*
String returns a string representation of the protected region of memory.
*/
func (b *LockedBuffer) String() string {
	slice := b.Bytes()
	return *(*string)(unsafe.Pointer(&slice))
}

/*
Uint16 returns a slice pointing to the protected region of memory with the data represented as a sequence of unsigned 16 bit integers. Its length will be half that of the byte slice, excluding any remaining part that doesn't form a complete uint16 value.

If called on a destroyed LockedBuffer, a nil slice will be returned.
*/
func (b *LockedBuffer) Uint16() []uint16 {
	b.RLock()
	defer b.RUnlock()

	// Check if still alive.
	if !b.alive {
		return nil
	}

	// Compute size of new slice representation.
	size := b.Size() / 2
	if size < 1 {
		return nil
	}

	// Construct the new slice representation.
	var sl = struct {
		addr uintptr
		len  int
		cap  int
	}{uintptr(unsafe.Pointer(&b.Bytes()[0])), size, size}

	// Cast the representation to the correct type and return it.
	return *(*[]uint16)(unsafe.Pointer(&sl))
}

/*
Uint32 returns a slice pointing to the protected region of memory with the data represented as a sequence of unsigned 32 bit integers. Its length will be one quarter that of the byte slice, excluding any remaining part that doesn't form a complete uint32 value.

If called on a destroyed LockedBuffer, a nil slice will be returned.
*/
func (b *LockedBuffer) Uint32() []uint32 {
	b.RLock()
	defer b.RUnlock()

	// Check if still alive.
	if !b.alive {
		return nil
	}

	// Compute size of new slice representation.
	size := b.Size() / 4
	if size < 1 {
		return nil
	}

	// Construct the new slice representation.
	var sl = struct {
		addr uintptr
		len  int
		cap  int
	}{uintptr(unsafe.Pointer(&b.Bytes()[0])), size, size}

	// Cast the representation to the correct type and return it.
	return *(*[]uint32)(unsafe.Pointer(&sl))
}

/*
Uint64 returns a slice pointing to the protected region of memory with the data represented as a sequence of unsigned 64 bit integers. Its length will be one eighth that of the byte slice, excluding any remaining part that doesn't form a complete uint64 value.

If called on a destroyed LockedBuffer, a nil slice will be returned.
*/
func (b *LockedBuffer) Uint64() []uint64 {
	b.RLock()
	defer b.RUnlock()

	// Check if still alive.
	if !b.alive {
		return nil
	}

	// Compute size of new slice representation.
	size := b.Size() / 8
	if size < 1 {
		return nil
	}

	// Construct the new slice representation.
	var sl = struct {
		addr uintptr
		len  int
		cap  int
	}{uintptr(unsafe.Pointer(&b.Bytes()[0])), size, size}

	// Cast the representation to the correct type and return it.
	return *(*[]uint64)(unsafe.Pointer(&sl))
}

/*
Int8 returns a slice pointing to the protected region of memory with the data represented as a sequence of signed 8 bit integers. If called on a destroyed LockedBuffer, a nil slice will be returned.
*/
func (b *LockedBuffer) Int8() []int8 {
	b.RLock()
	defer b.RUnlock()

	// Check if still alive.
	if !b.alive {
		return nil
	}

	// Construct the new slice representation.
	var sl = struct {
		addr uintptr
		len  int
		cap  int
	}{uintptr(unsafe.Pointer(&b.Bytes()[0])), b.Size(), b.Size()}

	// Cast the representation to the correct type and return it.
	return *(*[]int8)(unsafe.Pointer(&sl))
}

/*
Int16 returns a slice pointing to the protected region of memory with the data represented as a sequence of signed 16 bit integers. Its length will be half that of the byte slice, excluding any remaining part that doesn't form a complete int16 value.

If called on a destroyed LockedBuffer, a nil slice will be returned.
*/
func (b *LockedBuffer) Int16() []int16 {
	b.RLock()
	defer b.RUnlock()

	// Check if still alive.
	if !b.alive {
		return nil
	}

	// Compute size of new slice representation.
	size := b.Size() / 2
	if size < 1 {
		return nil
	}

	// Construct the new slice representation.
	var sl = struct {
		addr uintptr
		len  int
		cap  int
	}{uintptr(unsafe.Pointer(&b.Bytes()[0])), size, size}

	// Cast the representation to the correct type and return it.
	return *(*[]int16)(unsafe.Pointer(&sl))
}

/*
Int32 returns a slice pointing to the protected region of memory with the data represented as a sequence of signed 32 bit integers. Its length will be one quarter that of the byte slice, excluding any remaining part that doesn't form a complete int32 value.

If called on a destroyed LockedBuffer, a nil slice will be returned.
*/
func (b *LockedBuffer) Int32() []int32 {
	b.RLock()
	defer b.RUnlock()

	// Check if still alive.
	if !b.alive {
		return nil
	}

	// Compute size of new slice representation.
	size := b.Size() / 4
	if size < 1 {
		return nil
	}

	// Construct the new slice representation.
	var sl = struct {
		addr uintptr
		len  int
		cap  int
	}{uintptr(unsafe.Pointer(&b.Bytes()[0])), size, size}

	// Cast the representation to the correct type and return it.
	return *(*[]int32)(unsafe.Pointer(&sl))
}

/*
Int64 returns a slice pointing to the protected region of memory with the data represented as a sequence of signed 64 bit integers. Its length will be one eighth that of the byte slice, excluding any remaining part that doesn't form a complete int64 value.

If called on a destroyed LockedBuffer, a nil slice will be returned.
*/
func (b *LockedBuffer) Int64() []int64 {
	b.RLock()
	defer b.RUnlock()

	// Check if still alive.
	if !b.alive {
		return nil
	}

	// Compute size of new slice representation.
	size := b.Size() / 8
	if size < 1 {
		return nil
	}

	// Construct the new slice representation.
	var sl = struct {
		addr uintptr
		len  int
		cap  int
	}{uintptr(unsafe.Pointer(&b.Bytes()[0])), size, size}

	// Cast the representation to the correct type and return it.
	return *(*[]int64)(unsafe.Pointer(&sl))
}

/*
ByteArray8 returns a pointer to some 8 byte array. Care must be taken not to dereference the pointer and instead pass it around as-is.

The length of the buffer must be at least 8 bytes in size and the LockedBuffer should not be destroyed. In either of these cases a nil value is returned.
*/
func (b *LockedBuffer) ByteArray8() *[8]byte {
	b.RLock()
	defer b.RUnlock()

	// Check if still alive.
	if !b.alive {
		return nil
	}

	// Check if the length is large enough.
	if len(b.Bytes()) < 8 {
		return nil
	}

	// Cast the representation to the correct type.
	return (*[8]byte)(unsafe.Pointer(&b.Bytes()[0]))
}

/*
ByteArray16 returns a pointer to some 16 byte array. Care must be taken not to dereference the pointer and instead pass it around as-is.

The length of the buffer must be at least 16 bytes in size and the LockedBuffer should not be destroyed. In either of these cases a nil value is returned.
*/
func (b *LockedBuffer) ByteArray16() *[16]byte {
	b.RLock()
	defer b.RUnlock()

	// Check if still alive.
	if !b.alive {
		return nil
	}

	// Check if the length is large enough.
	if len(b.Bytes()) < 16 {
		return nil
	}

	// Cast the representation to the correct type.
	return (*[16]byte)(unsafe.Pointer(&b.Bytes()[0]))
}

/*
ByteArray32 returns a pointer to some 32 byte array. Care must be taken not to dereference the pointer and instead pass it around as-is.

The length of the buffer must be at least 32 bytes in size and the LockedBuffer should not be destroyed. In either of these cases a nil value is returned.
*/
func (b *LockedBuffer) ByteArray32() *[32]byte {
	b.RLock()
	defer b.RUnlock()

	// Check if still alive.
	if !b.alive {
		return nil
	}

	// Check if the length is large enough.
	if len(b.Bytes()) < 32 {
		return nil
	}

	// Cast the representation to the correct type.
	return (*[32]byte)(unsafe.Pointer(&b.Bytes()[0]))
}

/*
ByteArray64 returns a pointer to some 64 byte array. Care must be taken not to dereference the pointer and instead pass it around as-is.

The length of the buffer must be at least 64 bytes in size and the LockedBuffer should not be destroyed. In either of these cases a nil value is returned.
*/
func (b *LockedBuffer) ByteArray64() *[64]byte {
	b.RLock()
	defer b.RUnlock()

	// Check if still alive.
	if !b.alive {
		return nil
	}

	// Check if the length is large enough.
	if len(b.Bytes()) < 64 {
		return nil
	}

	// Cast the representation to the correct type.
	return (*[64]byte)(unsafe.Pointer(&b.Bytes()[0]))
}
