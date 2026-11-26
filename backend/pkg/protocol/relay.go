package protocol

import (
	"crypto/mlkem"
	"crypto/sha256"

	v1 "github.com/dean-2/urGuard/backend/gen/urguard/v1"
	"github.com/dean-2/urGuard/backend/pkg/pqc"
)

// These checks require only enrolled public keys. AEAD opening stays at the recipient.
func VerifyRelayHandshake(h *v1.SessionHandshake, sender, recipient Peer) error {
	if !sender.valid() || !validID(h.GetSessionId()) || sender.ID != h.GetSenderId() || sender.DeviceID != h.GetSenderDeviceId() || h.GetKeyEpoch() == 0 || VerifySessionOffer(h.GetOffer(), recipient) != nil || !pqc.VerifySignature(sender.SigningPublic, []byte(handshakeDomain), handshakeBody(h), h.SenderSignature) {
		return errHandshake
	}
	if len(h.EphemeralX25519PublicKey) != 32 || len(h.Offer.EphemeralX25519PublicKey) != 32 || len(h.Mlkem768Ciphertext) != mlkem.CiphertextSize768 {
		return errHandshake
	}
	if _, err := mlkem.NewEncapsulationKey768(h.Offer.EphemeralMlkem768PublicKey); err != nil {
		return errHandshake
	}
	return nil
}
func VerifyRelayEnvelope(e *v1.EncryptedEnvelope, c *v1.EncryptedChunk, h *v1.SessionHandshake, sender Peer) error {
	x := e.GetHeader()
	if x == nil || h == nil || h.Offer == nil || x.SenderId != sender.ID || x.SenderDeviceId != sender.DeviceID || x.RecipientId != h.Offer.RecipientId || x.RecipientDeviceId != h.Offer.RecipientDeviceId || x.SessionId != h.SessionId || x.KeyEpoch != h.KeyEpoch || x.Timestamp.CheckValid() != nil || len(x.Nonce) != 12 || len(x.ProtoReflect().GetUnknown()) != 0 || len(x.Timestamp.ProtoReflect().GetUnknown()) != 0 {
		return ErrRecipientMismatch
	}
	domain := envelopeDomain
	if len(e.Ciphertext) < 16 {
		return ErrRecipientMismatch
	}
	var meta []byte
	if c != nil {
		if !validID(c.TransferId) || c.ChunkIndex >= c.TotalChunks || c.TotalChunks > MaxChunks || len(c.ChunkHash) != sha256.Size || len(c.RootManifestHash) != sha256.Size || len(e.Ciphertext) > MaxChunkBytes+16 {
			return ErrDeliveryFailed
		}
		domain = chunkDomain
		meta = chunkMeta(c)
	}
	if !pqc.VerifySignature(sender.SigningPublic, []byte(domain), frame(aad(x, meta), x.Nonce, e.Ciphertext), e.SenderSignature) {
		return ErrRecipientMismatch
	}
	return nil
}
func VerifyRelayFinalize(r *v1.FinalizeTransferRequest, p Peer) bool {
	return validID(r.GetTransferId()) && r.TotalChunks > 0 && r.TotalChunks <= MaxChunks && pqc.VerifySignature(p.SigningPublic, []byte(finalizeDomain), finalizeBody(r), r.SenderSignature)
}
