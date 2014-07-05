// +build !notpm

package disk

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"code.google.com/p/goprotobuf/proto"
	"github.com/agl/pond/client/tpm"
)

func init() {
	erasureRegistry = append(erasureRegistry, func(header *Header) ErasureStorage {
		if header.TpmNvram != nil {
			return &TPM{
				index: header.TpmNvram.GetIndex(),
			}
		}
		return nil
	})
}

type TPM struct {
	Log   func(format string, args ...interface{})
	Rand  io.Reader
	index uint32
}

func (t *TPM) getContext() (*tpm.Context, error) {
	ctx, err := tpm.NewContext()
	if err != nil {
		if tpmErr, ok := err.(tpm.Error); ok {
			if tpmErr.Code() == tpm.ErrCodeCommunicationFailure {
				return nil, errors.New("failed to connect to tcsd; is it running?")
			}
		}
		return nil, fmt.Errorf("failed to create context: %s", err)
	}

	return ctx, nil
}

func (t *TPM) getNVRAM(ctx *tpm.Context, key *[kdfKeyLen]byte) (*tpm.NVRAM, error) {
	h := sha256.New()
	h.Write([]byte("TPM NVRAM key\x00"))
	h.Write(key[:])
	digest := h.Sum(nil)[:20]
	var nvramKey [20]byte
	copy(nvramKey[:], digest[:])

	nvram, err := ctx.NewNVRAM()
	if err != nil {
		return nil, fmt.Errorf("failed to create NVRAM handle: %s", err)
	}

	policy, err := ctx.NewPolicy()
	if err != nil {
		return nil, fmt.Errorf("failed to create new policy object: %s", err)
	}
	if err := policy.SetKey(nvramKey); err != nil {
		return nil, fmt.Errorf("failed to set policy key: %s", err)
	}
	policy.AssignTo(&nvram.Object)

	return nvram, nil

}

func (t *TPM) createIndex(key *[kdfKeyLen]byte) (uint32, error) {
	t.Log("Connecting to local tcsd")
	ctx, err := t.getContext()
	if err != nil {
		return 0, err
	}
	defer ctx.Close()

	tpmPolicy, err := ctx.GetPolicy()
	if err != nil {
		return 0, fmt.Errorf("failed to get TPM policy: %s", err)
	}

	if err := tpmPolicy.SetPassword(""); err != nil {
		return 0, fmt.Errorf("failed to set password on TPM policy: %s", err)
	}

	nvram, err := t.getNVRAM(ctx, key)
	if err != nil {
		return 0, err
	}

	nvram.Size = 32
	nvram.Permissions = tpm.PermWriteAllAtOnce | tpm.PermAuthWrite | tpm.PermAuthRead

NextAttempt:
	for attempt := 0; attempt < 3; attempt++ {
		for nvram.Index == 0 {
			var buf [2]byte
			if _, err := io.ReadFull(t.Rand, buf[:]); err != nil {
				return 0, err
			}
			nvram.Index = uint32(buf[0]) | uint32(buf[1])<<8
		}
		t.Log("Attempting to create NVRAM index %d", nvram.Index)
		if err := nvram.Create(); err != nil {
			if tpmErr, ok := err.(tpm.Error); ok {
				switch tpmErr.Code() {
				case tpm.ErrCodeNVRAMAlreadyExists:
					t.Log("NVRAM index already exists. Trying another.")
					continue NextAttempt
				case tpm.ErrCodeTPMDisabled:
					return 0, errors.New("TPM is disabled. Please enable in the BIOS and try again.")
				case tpm.ErrCodeNoStorageRootKey:
					t.Log("TPM has no owner. Attempting to set default keys.")
					srk, err := ctx.NewRSA()
					if err != nil {
						return 0, fmt.Errorf("failed to create SRK handle: %s", err)
					}
					srkPolicy, err := srk.GetPolicy()
					if err != nil {
						return 0, fmt.Errorf("failed to create SRK policy handle: %s", err)
					}
					if err := srkPolicy.SetPassword(""); err != nil {
						return 0, fmt.Errorf("failed to set SRK policy password: %s", err)
					}
					if err := ctx.TakeOwnership(srk); err != nil {
						return 0, fmt.Errorf("failed to take ownership of TPM: %s", err)
					}
					t.Log("TPM setup with default owner password. Trying again.")
					continue NextAttempt
				}
			}
			return 0, fmt.Errorf("error creating NVRAM: %s", err)
		}

		return nvram.Index, nil
	}

	return 0, errors.New("too many attempts to create NVRAM")
}

func (t *TPM) Create(header *Header, key *[kdfKeyLen]byte) error {
	index, err := t.createIndex(key)
	if err != nil {
		return err
	}

	header.TpmNvram = &Header_TPM{
		Index: proto.Uint32(index),
	}
	t.index = index

	return nil
}

func (t *TPM) Read(key *[kdfKeyLen]byte) (*[erasureKeyLen]byte, error) {
	ctx, err := t.getContext()
	if err != nil {
		return nil, err
	}
	defer ctx.Close()

	nvram, err := t.getNVRAM(ctx, key)
	if err != nil {
		return nil, err
	}

	nvram.Index = t.index
	var buf [erasureKeyLen]byte
	n, err := nvram.Read(buf[:])
	if err != nil {
		if tpmErr, ok := err.(tpm.Error); ok && tpmErr.Code() == tpm.ErrCodeAuthentication {
			return nil, BadPasswordError
		}
		return nil, err
	}
	if n != erasureKeyLen {
		return nil, fmt.Errorf("NVRAM read returned only %d bytes", n)
	}

	return &buf, nil
}

func (t *TPM) Write(key *[kdfKeyLen]byte, value *[erasureKeyLen]byte) error {
	ctx, err := t.getContext()
	if err != nil {
		return err
	}
	defer ctx.Close()

	nvram, err := t.getNVRAM(ctx, key)
	if err != nil {
		return err
	}

	nvram.Index = t.index
	return nvram.Write(value[:])
}

func (t *TPM) Destroy(key *[kdfKeyLen]byte) error {
	ctx, err := t.getContext()
	if err != nil {
		return err
	}
	defer ctx.Close()

	tpmPolicy, err := ctx.GetPolicy()
	if err != nil {
		return fmt.Errorf("failed to get TPM policy: %s", err)
	}

	if err := tpmPolicy.SetPassword(""); err != nil {
		return fmt.Errorf("failed to set password on TPM policy: %s", err)
	}

	nvram, err := t.getNVRAM(ctx, key)
	if err != nil {
		return err
	}

	nvram.Index = t.index
	return nvram.Destroy();
}
