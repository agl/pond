package bbssig

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func TestMarshal(t *testing.T) {
	priv, err := GenerateGroup(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate group: %s", err)
	}

	groupBytes := priv.Group.Marshal()
	_, ok := new(Group).Unmarshal(groupBytes)
	if !ok {
		t.Error("failed to unmarshal group")
	}

	group2, ok := new(Group).Unmarshal(groupBytes)
	if !ok {
		t.Error("failed to unmarshal group")
	}

	if group2Bytes := group2.Marshal(); !bytes.Equal(groupBytes, group2Bytes) {
		t.Error("reserialising group produces different result")
	}

	_, ok = new(PrivateKey).Unmarshal(group2, priv.Marshal())
	if !ok {
		t.Error("failed to unmarshal private key")
	}
}

func TestSign(t *testing.T) {
	priv, err := GenerateGroup(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate group: %s", err)
	}

	group := priv.Group
	member, err := priv.NewMember(rand.Reader)
	if err != nil {
		t.Fatalf("failed to add member to group: %s", err)
	}

	msg := []byte("hello world")
	h := sha256.New()
	h.Write(msg)
	digest := h.Sum(nil)

	ok := false
	groupBytes := group.Marshal()
	group, ok = new(Group).Unmarshal(groupBytes)
	if !ok {
		t.Fatalf("failed to unmarshal group")
	}

	sig, err := member.Sign(rand.Reader, digest, h)
	if err != nil {
		t.Fatalf("failed to sign message: %s", err)
	}

	if !group.Verify(digest, h, sig) {
		t.Errorf("signature failed to verify")
	}

	digest[1] ^= 0x80
	if group.Verify(digest, h, sig) {
		t.Errorf("signature always verifies")
	}
	digest[1] ^= 0x80

	tag, ok := priv.Open(sig)
	if !ok {
		t.Fatalf("failed to open signature")
	}

	if !bytes.Equal(tag, member.Tag()) {
		t.Errorf("Open returned wrong tag value")
	}

	member2, err := priv.NewMember(rand.Reader)
	if err != nil {
		t.Fatalf("failed to add second member: %s", err)
	}
	rev := priv.GenerateRevocation(member)
	revBytes := rev.Marshal()
	rev2, ok := new(Revocation).Unmarshal(revBytes)
	if !ok {
		t.Fatalf("failed to unmarshal revocation")
	}

	group.Update(rev2)
	if group.Verify(digest, h, sig) {
		t.Errorf("signature still verifies after revocation")
	}

	if member.Update(rev2) {
		t.Errorf("revoked key successfully updated")
	}

	sig2, err := member2.Sign(rand.Reader, digest, h)
	if err != nil {
		t.Fatalf("failed to sign second message: %s", err)
	}

	if group.Verify(digest, h, sig2) {
		t.Errorf("signature verified before member key updated")
	}

	member2.Group.Update(rev2)

	if !member2.Update(rev2) {
		t.Errorf("unrevoked member failed to update")
	}

	sig3, err := member2.Sign(rand.Reader, digest, h)
	if err != nil {
		t.Fatalf("failed to sign second message: %s", err)
	}

	if !group.Verify(digest, h, sig3) {
		t.Errorf("updated signature failed to verify")
	}
}

func BenchmarkVerify(b *testing.B) {
	priv, err := GenerateGroup(rand.Reader)
	if err != nil {
		b.Fatalf("failed to generate group: %s", err)
	}

	group := priv.Group
	member, err := priv.NewMember(rand.Reader)
	if err != nil {
		b.Fatalf("failed to add member to group: %s", err)
	}

	msg := []byte("hello world")
	h := sha256.New()
	h.Write(msg)
	digest := h.Sum(nil)

	sig, err := member.Sign(rand.Reader, digest, h)
	if err != nil {
		b.Fatalf("failed to sign message: %s", err)
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if !group.Verify(digest, h, sig) {
			b.Errorf("signature failed to verify")
		}
	}
}
