// Package tpm wraps the Trousers library for accessing the TPM from
// user-space. It currently provides very limited functionality: just NVRAM
// access.
package tpm

// #cgo LDFLAGS: -ltspi
// #include <trousers/tss.h>
// #include <trousers/trousers.h>
// #include <string.h>
import "C"

import (
	"fmt"
	"unsafe"
)

func isError(result C.TSS_RESULT) bool {
	return result != C.TSS_SUCCESS
}

type Error struct {
	result C.TSS_RESULT
}

func (e Error) Error() string {
	return fmt.Sprintf("tpm: layer: %s, code: 0x%x: %s", C.GoString(C.Trspi_Error_Layer(e.result)), C.Trspi_Error_Code(e.result), C.GoString(C.Trspi_Error_String(e.result)))
}

type ErrorCode int

func (e Error) Code() ErrorCode {
	return ErrorCode(C.Trspi_Error_Code(e.result))
}

// Error code values
const (
	// Failed to connect to daemon process.
	ErrCodeCommunicationFailure ErrorCode = C.TSS_E_COMM_FAILURE
	// The TPM is disabled in the BIOS.
	ErrCodeTPMDisabled = 7
	// The TPM doesn't have an owner and thus no storage root key has been
	// defined.
	ErrCodeNoStorageRootKey = 0x12
	// The NVRAM index already exists.
	ErrCodeNVRAMAlreadyExists = 0x13b
	// The password is incorrect.
	ErrCodeAuthorisation = 0x3b
)

type Object struct {
	handle C.TSS_HOBJECT
}

type Policy struct {
	policy C.TSS_HPOLICY
}

func (p *Policy) SetKey(key [20]byte) error {
	if result := C.Tspi_Policy_SetSecret(p.policy, C.TSS_SECRET_MODE_SHA1, 20, (*C.BYTE)(&key[0])); isError(result) {
		return Error{result}
	}
	return nil
}

func (p *Policy) SetPassword(pw string) error {
	var result C.TSS_RESULT
	if len(pw) == 0 {
		var zeros [20]byte
		result = C.Tspi_Policy_SetSecret(p.policy, C.TSS_SECRET_MODE_SHA1, 20, (*C.BYTE)(&zeros[0]))
	} else {
		panic("unimplemented")
	}

	if isError(result) {
		return Error{result}
	}
	return nil
}

func (p *Policy) AssignTo(o *Object) error {
	if result := C.Tspi_Policy_AssignToObject(p.policy, o.handle); isError(result) {
		return Error{result}
	}
	return nil
}

type NVRAM struct {
	Object
	Index       uint32
	Size        int
	Permissions uint32
}

const (
	PermAuthRead       = C.TPM_NV_PER_AUTHREAD
	PermAuthWrite      = C.TPM_NV_PER_AUTHWRITE
	PermWriteAllAtOnce = C.TPM_NV_PER_WRITEALL
)

func (nv *NVRAM) setAttributes() error {
	if result := C.Tspi_SetAttribUint32(nv.handle, C.TSS_TSPATTRIB_NV_INDEX, 0, C.UINT32(nv.Index)); isError(result) {
		return Error{result}
	}
	if result := C.Tspi_SetAttribUint32(nv.handle, C.TSS_TSPATTRIB_NV_PERMISSIONS, 0, C.UINT32(nv.Permissions)); isError(result) {
		return Error{result}
	}
	if result := C.Tspi_SetAttribUint32(nv.handle, C.TSS_TSPATTRIB_NV_DATASIZE, 0, C.UINT32(nv.Size)); isError(result) {
		return Error{result}
	}

	return nil
}

func (nv *NVRAM) Create() error {
	if err := nv.setAttributes(); err != nil {
		return err
	}
	if result := C.Tspi_NV_DefineSpace(C.TSS_HNVSTORE(nv.handle), 0, 0); isError(result) {
		return Error{result}
	}
	return nil
}

func (nv *NVRAM) Destroy() error {
	if err := nv.setAttributes(); err != nil {
		return err
	}
	if result := C.Tspi_NV_ReleaseSpace(C.TSS_HNVSTORE(nv.handle)); isError(result) {
		return Error{result}
	}
	return nil
}

func (nv *NVRAM) Read(out []byte) (int, error) {
	if result := C.Tspi_SetAttribUint32(nv.handle, C.TSS_TSPATTRIB_NV_INDEX, 0, C.UINT32(nv.Index)); isError(result) {
		return 0, Error{result}
	}
	l32 := C.UINT32(len(out))
	var buf *C.BYTE
	if result := C.Tspi_NV_ReadValue(C.TSS_HNVSTORE(nv.handle), 0 /* offset */, &l32, &buf); isError(result) {
		return 0, Error{result}
	}
	l := int(l32)
	if l > len(out) {
		l = len(out)
	}
	if l < 0 {
		l = 0
	}
	C.memcpy(unsafe.Pointer(&out[0]), unsafe.Pointer(buf), C.size_t(l))
	return l, nil
}

func (nv *NVRAM) Write(contents []byte) error {
	if result := C.Tspi_SetAttribUint32(nv.handle, C.TSS_TSPATTRIB_NV_INDEX, 0, C.UINT32(nv.Index)); isError(result) {
		return Error{result}
	}
	if result := C.Tspi_NV_WriteValue(C.TSS_HNVSTORE(nv.handle), 0 /* offset */, C.UINT32(len(contents)), (*C.BYTE)(&contents[0])); isError(result) {
		return Error{result}
	}
	return nil
}

type RSA struct {
	Object
}

func (rsa *RSA) GetPolicy() (*Policy, error) {
	p := new(Policy)
	if result := C.Tspi_GetPolicyObject(C.TSS_HOBJECT(rsa.handle), C.TSS_POLICY_USAGE, &p.policy); isError(result) {
		return nil, Error{result}
	}

	return p, nil
}

type Context struct {
	ctx C.TSS_HCONTEXT
	tpm C.TSS_HTPM
}

func NewContext() (*Context, error) {
	c := new(Context)
	if result := C.Tspi_Context_Create(&c.ctx); isError(result) {
		return nil, Error{result}
	}
	if result := C.Tspi_Context_Connect(c.ctx, nil /* local TPM */); isError(result) {
		return nil, Error{result}
	}
	if result := C.Tspi_Context_GetTpmObject(c.ctx, &c.tpm); isError(result) {
		return nil, Error{result}
	}

	return c, nil
}

func (c *Context) Close() error {
	C.Tspi_Context_FreeMemory(c.ctx, nil)
	if result := C.Tspi_Context_Close(c.ctx); isError(result) {
		return Error{result}
	}
	return nil
}

func (c *Context) GetPolicy() (*Policy, error) {
	p := new(Policy)
	if result := C.Tspi_GetPolicyObject(C.TSS_HOBJECT(c.tpm), C.TSS_POLICY_USAGE, &p.policy); isError(result) {
		return nil, Error{result}
	}

	return p, nil
}

func (c *Context) NewPolicy() (*Policy, error) {
	p := new(Policy)
	if result := C.Tspi_Context_CreateObject(c.ctx, C.TSS_OBJECT_TYPE_POLICY, C.TSS_POLICY_USAGE, (*C.TSS_HOBJECT)(&p.policy)); isError(result) {
		return nil, Error{result}
	}

	return p, nil
}

func (c *Context) NewNVRAM() (*NVRAM, error) {
	nv := new(NVRAM)
	if result := C.Tspi_Context_CreateObject(c.ctx, C.TSS_OBJECT_TYPE_NV, 0, &nv.handle); isError(result) {
		return nil, Error{result}
	}

	return nv, nil
}

func (c *Context) NewRSA() (*RSA, error) {
	rsa := new(RSA)
	if result := C.Tspi_Context_CreateObject(c.ctx, C.TSS_OBJECT_TYPE_RSAKEY, C.TSS_KEY_TSP_SRK|C.TSS_KEY_AUTHORIZATION, &rsa.handle); isError(result) {
		return nil, Error{result}
	}

	return rsa, nil
}

func (c *Context) TakeOwnership(srk *RSA) error {
	if result := C.Tspi_TPM_TakeOwnership(c.tpm, C.TSS_HKEY(srk.handle), 0); isError(result) {
		return Error{result}
	}
	return nil
}
