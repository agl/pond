package protos

import "code.google.com/p/go.crypto/nacl/secretbox"

// TransportSize is the number of bytes that all payloads are padded to before
// sending on the network.
const TransportSize = 16384 - 2 - secretbox.Overhead
// MessageOverhead is the number of bytes reserved for wrapping a Message up in
// protobufs. That includes the overhead of the protobufs themselves, as well
// as the metadata in the protobuf and the group signature.
const MessageOverhead = 512
