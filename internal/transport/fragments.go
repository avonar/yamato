package transport

import (
	"encoding/binary"
	"errors"
	"time"
)

const chunkSize = 900
const fragmentHeader = 12

func splitPacket(id uint32, b []byte) [][]byte {
	count := (len(b) + chunkSize - 1) / chunkSize
	out := make([][]byte, 0, count)
	for i := 0; i < count; i++ {
		end := min((i+1)*chunkSize, len(b))
		f := make([]byte, fragmentHeader+end-i*chunkSize)
		copy(f, "TL01")
		binary.BigEndian.PutUint32(f[4:], id)
		binary.BigEndian.PutUint16(f[8:], uint16(i))
		binary.BigEndian.PutUint16(f[10:], uint16(count))
		copy(f[12:], b[i*chunkSize:end])
		out = append(out, f)
	}
	return out
}

type partial struct {
	at    time.Time
	parts [2][]byte
	count int
}
type assembler struct {
	pending   map[uint32]*partial
	completed map[uint32]time.Time
}

func (a *assembler) push(f []byte, now time.Time) ([]byte, error) {
	if len(f) < fragmentHeader || string(f[:4]) != "TL01" {
		return nil, errors.New("invalid tunnel fragment")
	}
	id := binary.BigEndian.Uint32(f[4:])
	idx := int(binary.BigEndian.Uint16(f[8:]))
	count := int(binary.BigEndian.Uint16(f[10:]))
	data := f[12:]
	if count < 1 || count > 2 || idx >= count || len(data) < 1 || len(data) > chunkSize || (idx < count-1 && len(data) != chunkSize) || (idx == 1 && len(data) > MTU-chunkSize) {
		return nil, errors.New("invalid fragment dimensions")
	}
	if a.pending == nil {
		a.pending = map[uint32]*partial{}
		a.completed = map[uint32]time.Time{}
	}
	for k, v := range a.pending {
		if now.Sub(v.at) > 2*time.Second {
			delete(a.pending, k)
		}
	}
	for k, v := range a.completed {
		if now.Sub(v) > 2*time.Second {
			delete(a.completed, k)
		}
	}
	if _, ok := a.completed[id]; ok {
		return nil, nil
	}
	p := a.pending[id]
	if p == nil {
		if len(a.pending) >= 64 {
			return nil, nil
		}
		p = &partial{at: now, count: count}
		a.pending[id] = p
	}
	if p.count != count {
		return nil, errors.New("fragment count changed")
	}
	if p.parts[idx] != nil {
		return nil, nil
	}
	p.parts[idx] = append([]byte(nil), data...)
	for i := 0; i < count; i++ {
		if p.parts[i] == nil {
			return nil, nil
		}
	}
	b := append(p.parts[0], p.parts[1]...)
	delete(a.pending, id)
	// Bound duplicate suppression independently of packet rate.
	if len(a.completed) >= 4096 {
		for k := range a.completed {
			delete(a.completed, k)
			break
		}
	}
	a.completed[id] = now
	return b, nil
}
