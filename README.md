Pond
====

*Pond is in stasis*, and has been for several years. I hope that some of the ideas prove useful in the future, but people should use something [better polished and reviewed](https://whispersystems.org). I've no plans to shutdown down the default server, but **new users should look elsewhere**.

The code here is broken down as follows:

 - `bbssig` contains an implementation of the BBS group signature scheme. This is used in Pond to allow servers to reject messages from non-contacts without the server being able to identify those contacts.
 - `bn256cgo` contains a wrapping of Naehrig, Niederhagen and Schwabe's pairing library. This is a drop in replacement for the bn256 package from go.crypto and speeds up bbssig. See https://github.com/agl/dclxvi.
 - `client` contains the Pond GUI and CLI client and package for manipulating state files.
 - `doc` contains the https://pond.imperialviolet.org site in Jekyll format.
 - `editstate` contains a debugging utility for manipulating state files.
 - `panda` contains a library for performing shared-key exchanges. It's used by `client/` to implement that functionality.
 - `protos` contains the protocol buffer files for client-server communication.
 - `server` contains the Pond server.
 - `transport` contains code to implement the low-level client-server transport protocol.
