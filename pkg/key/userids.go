package key

import "golang.org/x/crypto/openpgp/packet"

type UserIds []*UserId

func (u *UserIds) ToPacket() (uids []*packet.UserId) {
	for _, uid := range *u {
		uids = append(uids, uid.ToPacket())
	}
	return uids
}

func (u *UserIds) Primary() *UserId {
	for _, uid := range *u {
		if uid.Primary {
			return uid
		}
	}
	return nil
}
