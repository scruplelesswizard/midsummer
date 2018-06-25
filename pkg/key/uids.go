package key

import "golang.org/x/crypto/openpgp/packet"

type UIDs []*UID

func (u *UIDs) ToPacket() (uids []*packet.UserId) {
	for _, uid := range *u {
		uids = append(uids, uid.ToPacket())
	}
	return uids
}
