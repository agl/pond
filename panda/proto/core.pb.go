// Code generated by protoc-gen-go.
// source: github.com/agl/pond/panda/proto/core.proto
// DO NOT EDIT!

package panda

import proto "code.google.com/p/goprotobuf/proto"
import json "encoding/json"
import math "math"

// Reference proto, json, and math imports to suppress error if they are not otherwise used.
var _ = proto.Marshal
var _ = &json.SyntaxError{}
var _ = math.Inf

type KeyExchange_Status int32

const (
	KeyExchange_INIT      KeyExchange_Status = 0
	KeyExchange_EXCHANGE1 KeyExchange_Status = 1
	KeyExchange_EXCHANGE2 KeyExchange_Status = 2
)

var KeyExchange_Status_name = map[int32]string{
	0: "INIT",
	1: "EXCHANGE1",
	2: "EXCHANGE2",
}
var KeyExchange_Status_value = map[string]int32{
	"INIT":      0,
	"EXCHANGE1": 1,
	"EXCHANGE2": 2,
}

func (x KeyExchange_Status) Enum() *KeyExchange_Status {
	p := new(KeyExchange_Status)
	*p = x
	return p
}
func (x KeyExchange_Status) String() string {
	return proto.EnumName(KeyExchange_Status_name, int32(x))
}
func (x KeyExchange_Status) MarshalJSON() ([]byte, error) {
	return json.Marshal(x.String())
}
func (x *KeyExchange_Status) UnmarshalJSON(data []byte) error {
	value, err := proto.UnmarshalJSONEnum(KeyExchange_Status_value, data, "KeyExchange_Status")
	if err != nil {
		return err
	}
	*x = KeyExchange_Status(value)
	return nil
}

type KeyExchange struct {
	Status           *KeyExchange_Status       `protobuf:"varint,1,req,name=status,enum=panda.KeyExchange_Status" json:"status,omitempty"`
	KeyExchangeBytes []byte                    `protobuf:"bytes,2,req,name=key_exchange_bytes" json:"key_exchange_bytes,omitempty"`
	SharedSecret     *KeyExchange_SharedSecret `protobuf:"bytes,3,opt,name=shared_secret" json:"shared_secret,omitempty"`
	DhPrivate        []byte                    `protobuf:"bytes,4,opt,name=dh_private" json:"dh_private,omitempty"`
	Key              []byte                    `protobuf:"bytes,5,opt,name=key" json:"key,omitempty"`
	Meeting1         []byte                    `protobuf:"bytes,6,opt,name=meeting1" json:"meeting1,omitempty"`
	Meeting2         []byte                    `protobuf:"bytes,7,opt,name=meeting2" json:"meeting2,omitempty"`
	Message1         []byte                    `protobuf:"bytes,8,opt,name=message1" json:"message1,omitempty"`
	Message2         []byte                    `protobuf:"bytes,9,opt,name=message2" json:"message2,omitempty"`
	SharedKey        []byte                    `protobuf:"bytes,10,opt,name=shared_key" json:"shared_key,omitempty"`
	XXX_unrecognized []byte                    `json:"-"`
}

func (this *KeyExchange) Reset()         { *this = KeyExchange{} }
func (this *KeyExchange) String() string { return proto.CompactTextString(this) }
func (*KeyExchange) ProtoMessage()       {}

func (this *KeyExchange) GetStatus() KeyExchange_Status {
	if this != nil && this.Status != nil {
		return *this.Status
	}
	return 0
}

func (this *KeyExchange) GetKeyExchangeBytes() []byte {
	if this != nil {
		return this.KeyExchangeBytes
	}
	return nil
}

func (this *KeyExchange) GetSharedSecret() *KeyExchange_SharedSecret {
	if this != nil {
		return this.SharedSecret
	}
	return nil
}

func (this *KeyExchange) GetDhPrivate() []byte {
	if this != nil {
		return this.DhPrivate
	}
	return nil
}

func (this *KeyExchange) GetKey() []byte {
	if this != nil {
		return this.Key
	}
	return nil
}

func (this *KeyExchange) GetMeeting1() []byte {
	if this != nil {
		return this.Meeting1
	}
	return nil
}

func (this *KeyExchange) GetMeeting2() []byte {
	if this != nil {
		return this.Meeting2
	}
	return nil
}

func (this *KeyExchange) GetMessage1() []byte {
	if this != nil {
		return this.Message1
	}
	return nil
}

func (this *KeyExchange) GetMessage2() []byte {
	if this != nil {
		return this.Message2
	}
	return nil
}

func (this *KeyExchange) GetSharedKey() []byte {
	if this != nil {
		return this.SharedKey
	}
	return nil
}

type KeyExchange_SharedSecret struct {
	Secret           *string                        `protobuf:"bytes,1,opt,name=secret" json:"secret,omitempty"`
	NumDecks         *int32                         `protobuf:"varint,2,opt,name=num_decks" json:"num_decks,omitempty"`
	CardCount        []int32                        `protobuf:"varint,3,rep,name=card_count" json:"card_count,omitempty"`
	Time             *KeyExchange_SharedSecret_Time `protobuf:"bytes,4,opt,name=time" json:"time,omitempty"`
	XXX_unrecognized []byte                         `json:"-"`
}

func (this *KeyExchange_SharedSecret) Reset()         { *this = KeyExchange_SharedSecret{} }
func (this *KeyExchange_SharedSecret) String() string { return proto.CompactTextString(this) }
func (*KeyExchange_SharedSecret) ProtoMessage()       {}

func (this *KeyExchange_SharedSecret) GetSecret() string {
	if this != nil && this.Secret != nil {
		return *this.Secret
	}
	return ""
}

func (this *KeyExchange_SharedSecret) GetNumDecks() int32 {
	if this != nil && this.NumDecks != nil {
		return *this.NumDecks
	}
	return 0
}

func (this *KeyExchange_SharedSecret) GetCardCount() []int32 {
	if this != nil {
		return this.CardCount
	}
	return nil
}

func (this *KeyExchange_SharedSecret) GetTime() *KeyExchange_SharedSecret_Time {
	if this != nil {
		return this.Time
	}
	return nil
}

type KeyExchange_SharedSecret_Time struct {
	Day              *int32 `protobuf:"varint,1,req,name=day" json:"day,omitempty"`
	Month            *int32 `protobuf:"varint,2,req,name=month" json:"month,omitempty"`
	Year             *int32 `protobuf:"varint,3,req,name=year" json:"year,omitempty"`
	Hours            *int32 `protobuf:"varint,4,req,name=hours" json:"hours,omitempty"`
	Minutes          *int32 `protobuf:"varint,5,req,name=minutes" json:"minutes,omitempty"`
	XXX_unrecognized []byte `json:"-"`
}

func (this *KeyExchange_SharedSecret_Time) Reset()         { *this = KeyExchange_SharedSecret_Time{} }
func (this *KeyExchange_SharedSecret_Time) String() string { return proto.CompactTextString(this) }
func (*KeyExchange_SharedSecret_Time) ProtoMessage()       {}

func (this *KeyExchange_SharedSecret_Time) GetDay() int32 {
	if this != nil && this.Day != nil {
		return *this.Day
	}
	return 0
}

func (this *KeyExchange_SharedSecret_Time) GetMonth() int32 {
	if this != nil && this.Month != nil {
		return *this.Month
	}
	return 0
}

func (this *KeyExchange_SharedSecret_Time) GetYear() int32 {
	if this != nil && this.Year != nil {
		return *this.Year
	}
	return 0
}

func (this *KeyExchange_SharedSecret_Time) GetHours() int32 {
	if this != nil && this.Hours != nil {
		return *this.Hours
	}
	return 0
}

func (this *KeyExchange_SharedSecret_Time) GetMinutes() int32 {
	if this != nil && this.Minutes != nil {
		return *this.Minutes
	}
	return 0
}

func init() {
	proto.RegisterEnum("panda.KeyExchange_Status", KeyExchange_Status_name, KeyExchange_Status_value)
}
