package key

import "golang.org/x/crypto/openpgp/packet"

type UID struct {
	Name    string
	Email   string
	Comment string
	Primary bool
}

// ToPacket creates a openpgp packet format UserId
func (u *UID) ToPacket() *packet.UserId {
	return packet.NewUserId(u.Name, u.Comment, u.Email)
}
