package protos

import "code.google.com/p/go.crypto/nacl/box"
import "code.google.com/p/go.crypto/nacl/secretbox"

// TransportSize is the number of bytes that all payloads are padded to before
// sending on the network.
const TransportSize = 16384 - 2 - secretbox.Overhead
// MessageOverhead is the number of bytes reserved for wrapping a Message up in
// protobufs. That includes the overhead of the protobufs themselves, as well
// as the metadata in the protobuf and the group signature.
const MessageOverhead = 512
// MaxSerializedMessage is the maximum size of the serialized Message protobuf.
// The message will end up looking like this:
//    [nonce - 24 bytes       ]             -|
//    [box.Overhead - 16 bytes] -|           |
//    [length - 4 bytes       ]  | NaCl box  | Message that server sees.
//    [serialized message     ]  |           |
//    [padding                ] -|          -|
const MaxSerializedMessage = TransportSize-box.Overhead-MessageOverhead-24-4
