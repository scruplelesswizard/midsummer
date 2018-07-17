package key

import "golang.org/x/crypto/openpgp/packet"

type UserId struct {
	Name    string
	Email   string
	Comment string
	Primary bool
}

// ToPacket creates a openpgp packet format UserId
func (u *UserId) ToPacket() *packet.UserId {
	return packet.NewUserId(u.Name, u.Comment, u.Email)
}
