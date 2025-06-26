package peers

import (
	"time"

	"github.com/hossein1376/kamune/enigma"
	"github.com/hossein1376/kamune/internal/cmap"
)

type Peer struct {
	enigma    enigma.Enigma
	createdAt time.Time
}

func NewPeer(enigma enigma.Enigma) Peer {
	return Peer{
		enigma:    enigma,
		createdAt: time.Now(),
	}
}

type Peers struct {
	Map *cmap.ConcurrentMap[string, Peer]
}

func NewPeers() *Peers {
	return &Peers{cmap.New[string, Peer]()}
}

func (p *Peers) Add(id string, peer Peer) {
	p.Map.Add(id, peer)
}

func (p *Peers) Set(id string, f func(pr Peer) (Peer, error)) error {
	return p.Map.Put(id, f)
}

func (p *Peers) Exists(id string) bool {
	return p.Map.Exists(id)
}

func (p *Peers) Get(id string) (Peer, bool) {
	return p.Map.Get(id)
}
