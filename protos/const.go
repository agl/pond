package protos

import "golang.org/x/crypto/nacl/secretbox"

// TransportSize is the number of bytes that all payloads are padded to before
// sending on the network.
const TransportSize = 16384 - 2 - secretbox.Overhead

// MessageOverhead is the number of bytes reserved for wrapping a Message up in
// protobufs. That includes the overhead of the protobufs themselves, as well
// as the metadata in the protobuf and the group signature.
const MessageOverhead = 512

// MaxSerializedMessage is the maximum size of the serialized Message protobuf.
// The message will end up looking like this:
//    [length - 4 bytes       ]  | NaCl box  | Message that server sees.
//    [nonce - 24 bytes               ]
//
//      [secretbox.Overhead - 16 bytes]
//      [message count - 4 bytes      ]
//      [prev message count - 4 bytes ]
//      [ratchet public - 32 bytes    ]
//      [inner nonce - 32 bytes       ]
//
//      [secretbox.Overhead - 16 bytes]
//      [serialized message           ]
const MaxSerializedMessage = TransportSize - (secretbox.Overhead + 4 + 4 + 32 + 24) - secretbox.Overhead - MessageOverhead
