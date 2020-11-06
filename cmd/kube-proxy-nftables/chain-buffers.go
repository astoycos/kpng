package main

import (
	"bytes"
	"io"

	"github.com/OneOfOne/xxhash"
	"github.com/google/btree"
)

var (
	chainBuffers4 = &chainBufferSet{btree.New(4)}
	chainBuffers6 = &chainBufferSet{btree.New(4)}
)

type chainBufferSet struct {
	data *btree.BTree
}

type chainBuffer struct {
	name         string
	previousHash uint64
	currentHash  *xxhash.XXHash64
	buffer       *bytes.Buffer
	lenMA        int
	deferred     []func(*chainBuffer)
}

var (
	_ btree.Item    = &chainBuffer{}
	_ io.ReadWriter = &chainBuffer{}
)

func (c *chainBuffer) Less(i btree.Item) bool {
	return c.name < i.(*chainBuffer).name
}

func (c *chainBuffer) Read(b []byte) (int, error) {
	return c.buffer.Read(b)
}

func (c *chainBuffer) Write(b []byte) (int, error) {
	if c.currentHash == nil {
		c.currentHash = xxhash.New64()
	}
	c.currentHash.Write(b)
	return c.buffer.Write(b)
}

func (c *chainBuffer) Len() int {
	return c.buffer.Len()
}

func (c *chainBuffer) Changed() bool {
	if c.currentHash == nil {
		return c.previousHash != 0
	}
	return c.currentHash.Sum64() != c.previousHash
}

func (c *chainBuffer) Defer(deferred func(*chainBuffer)) {
	c.deferred = append(c.deferred, deferred)
}

func (c *chainBuffer) RunDeferred() {
	for _, deferred := range c.deferred {
		deferred(c)
	}
}

func (c *chainBuffer) Created() bool {
	return c.previousHash == 0 && c.currentHash != nil
}

func (set *chainBufferSet) Reset() {
	set.data.Ascend(func(i btree.Item) bool {
		cb := i.(*chainBuffer)

		cb.deferred = cb.deferred[:0]

		// compute buffer len moving average
		if cb.lenMA == 0 {
			cb.lenMA = cb.buffer.Len()
		} else {
			cb.lenMA = (4*cb.lenMA + cb.buffer.Len()) / 5
		}
		// expect len+20%
		expCap := cb.lenMA * 120 / 100

		if cb.buffer.Cap() <= expCap {
			cb.buffer.Reset()
		} else {
			cb.buffer = bytes.NewBuffer(make([]byte, 0, expCap))
		}

		if cb.currentHash == nil {
			// no writes -> empty
			cb.previousHash = 0
		} else {
			cb.previousHash = cb.currentHash.Sum64()
			cb.currentHash = nil
		}
		return true
	})
}

func (set *chainBufferSet) Get(chainName string) *chainBuffer {
	i := set.data.Get(&chainBuffer{name: chainName})

	if i == nil {
		i = &chainBuffer{
			name:     chainName,
			buffer:   new(bytes.Buffer),
			deferred: make([]func(*chainBuffer), 0, 1),
		}
		set.data.ReplaceOrInsert(i)
	}

	return i.(*chainBuffer)
}

func (set *chainBufferSet) List() (chains []string) {
	chains = make([]string, 0, set.data.Len())

	set.data.Ascend(func(i btree.Item) bool {
		cb := i.(*chainBuffer)
		if cb.currentHash != nil {
			chains = append(chains, cb.name)
		}
		return true
	})

	return
}

func (set *chainBufferSet) Deleted() (chains []string) {
	chains = make([]string, 0, set.data.Len())

	set.data.Ascend(func(i btree.Item) bool {
		cb := i.(*chainBuffer)
		if cb.previousHash != 0 && cb.currentHash == nil {
			chains = append(chains, cb.name)
		}
		return true
	})

	return
}

func (set *chainBufferSet) Changed() (changed bool) {
	changed = false

	set.data.Ascend(func(i btree.Item) bool {
		cb := i.(*chainBuffer)
		if cb.Changed() {
			changed = true
		}
		return !changed
	})

	return
}

func (set *chainBufferSet) RunDeferred() {
	set.data.Ascend(func(i btree.Item) bool {
		i.(*chainBuffer).RunDeferred()
		return true
	})
}