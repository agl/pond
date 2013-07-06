package tpm

import (
	"testing"
)

func TestConnect(t *testing.T) {
	ctx, err := NewContext()
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Close()

	tpmPolicy, err := ctx.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if err := tpmPolicy.SetPassword(""); err != nil {
		t.Fatal(err)
	}

	nvram, err := ctx.NewNVRAM()
	if err != nil {
		t.Fatal(err)
	}

	policy, err := ctx.NewPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.SetPassword(""); err != nil {
		t.Fatal(err)
	}
	policy.AssignTo(&nvram.Object)

	/*
		nvram.Index = 43
		nvram.Size = 32
		nvram.Permissions = PermWriteAllAtOnce | PermAuthWrite | PermAuthRead
		if err := nvram.Create(); err != nil {
			t.Fatalf("error creating NVRAM: %s", err)
		}
	*/
}
