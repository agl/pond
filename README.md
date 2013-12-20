Pond
====

(Or, how to better organise a discreet relationship with the Director of the CIA.)

At this point, I welcome technical feedback on the design and comments from the sort of (often non-technical) folks who need this sort of thing about whether it actually meets their needs.

For details, see [the main website](https://pond.imperialviolet.org).

The code here is broken down as follows:

 - `bbssig` contains an implementation of the BBS group signature scheme. This is used in Pond to allow servers to reject messages from non-contacts without the server being able to identify those contacts.
 - `bn256cgo` contains a wrapping of Naehrig, Niederhagen and Schwabe's pairing library. This is a drop in replacement for the bn256 package from go.crypto and speeds up bbssig. See https://github.com/agl/dclxvi.
 - `client` contains the Pond GUI and CLI client and package for manipulating state files.
 - `doc` contains the https://pond.imperialviolet.org site in Jeykll format.
 - `editstate` contains a debugging utility for manipulating state files.
 - `panda` contains a library for performing shared-key exchanges. It's used by `client/` to implement that functionality.
 - `protos` contains the protocol buffer files for client to server communication.
 - `server` contains the Pond server.
 - `transport` contains code to implement the, low-level, client to server transport protocol.
