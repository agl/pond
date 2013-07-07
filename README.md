Pond
====

(Or, how to better organise a discreet relationship with the Director of the CIA.)

*Pond is experimental software. By this I don't just mean "use it but don't blame me if the FBI raids your biographer". I mean that there are no build instructions and, if you do manage to build it, it won't run unless you know what to do.*

At this point, I welcome technical feedback on the design and comments from the sort of (often non-technical) folks who need this sort of thing about whether it actually meets their needs.

Initially I expect people to highlight areas that I've failed to document.

Introduction
------------

For secure, synchronous communication we have OTR and, when run over Tor, this is pretty good. But while we have secure asynchronous messaging in the form of PGP email, it's not forward secure and it gratuitously leaks traffic information. While a desire for forward secure PGP [is hardly new](http://tools.ietf.org/html/draft-brown-pgp-pfs-03), it still hasn't materialised in a widely usable manner.

Additionally, email is used predominately for insecure communications (mailing lists, etc) and is useful because it allows previously unconnected people to communicate as long as a (public) email address is known to one party. But the flip side to this is that volume and spam is driving people to use centralised email services. These provide such huge benefits to the majority of email communication, it's unlikely that this trend is going to reverse. But, even with PGP, these services are trusted with hugely valuable traffic information if any party uses them.

So Pond is not email. Pond is forward secure, asynchronous messaging for the discerning connoisseur. Pond messages are asynchronous, but are not a record; they expire automatically a week after they are received. Pond seeks to prevent leaking traffic information against everyone except a global passive attacker.

Overview
--------

Pond consists of users and servers. Servers exist in order to provide availability by accepting messages for a user while that user may be offline. Servers may be freely chosen by users and each user may have their own server if they wish.

We assume the existence of an overlay network that prevents a network attacker from learning which servers a user is connecting to. That network is assumed to be Tor for the remainder of this document and servers are assumed to be Tor hidden services. Since a global, passive attacker can deanonymise Tor, that attacker is capable of violating this assumption and breaking Pond. Other attacks on Tor may also break this assumption.

Users are assumed to have trustworthy computers with storage that reliably deletes old information. (Although see Storage, below, about helping things along in this respect.)

Communicating users are also assumed to be able to establish secure communications by exchanging initial messages authentically and confidentially. (Which is a _significant_ assumption.)

Under these assumptions, the following should be true:

1.  The network cannot learn who a Pond user is communicating with.
2.  The network cannot learn when a Pond user is sending messages, nor the sizes of those messages.
3.  The network can know that a given host is running Pond.
4.  A server cannot learn the identity of a Pond user.
5.  A server cannot learn who a Pond user is receiving messages from.
5.  A server cannot learn the contents nor size of any messages.
6.  A server cannot learn when a Pond user is sending messages.
7.  A server can learn when a user is online.
8.  A server can learn how many messages a user receives, and when they receive them.
9.  A server can ensure that only authorised users can communicate with a Pond user to prevent spam.

Transport
---------

Users communicate with servers (and only with servers, never with other users directly) using the transport protocol. Although Tor hidden services already provide authentication of the server to the client, we don't rely on that. The transport layer provides integrity, forward secure confidentiality and mutual authentication. It's assumed that the public key of the server is already known to the user and the public key of the user isn't revealed to anyone other than the expected server. (Tor does provide another layer of forward secrecy which means that a compromise of the server's keys does not compromise the public keys of users that connected to it.)

After authentication, the user sends a fixed amount (currently 16KB) of data to the server and the server replies with an identically sized flow. Finally the user sends a secure close message and the connection is complete. Connections are never reused. (The actual messages between the user and the server might be very small, but those messages will be padded to 16KB before being encrypted in order to make the traffic profile constant.)

Users make connections periodically in order to send and receive messages. The time between each connection is exponentially distributed. Each connection is either to the user's own server, to fetch any messages that may be waiting, or to the server of another user, to deliver a message. Connections to the user's own server for fetching messages are authenticated as that user. Connections for delivering messages (whether to a user on the same server or not) are authenticated as fresh, random identities. These connections need not be authenticated, but it's easier to keep the traffic profile identical if they are authenticated with a random key.

From the point of view of the network close to the user, all that is seen are randomly timed connections over Tor, all with an identical traffic profiles. That profile is fairly distinctive and would allow the network to learn that a host is using Pond, but the network cannot tell when messages are being sent or received.

From the point of view of the user's server, it receives exponentially distributed connections from the user, over Tor, and can reply with a message when one is waiting. The connections are randomly timed, rather than having a constant period, in order to avoid the server learning when the user is sending messages. If a server saw connections at 11 minutes past the hour, 21 minutes and 41 minutes, it's not too hard to guess when the user connected to another server in order to deliver a message. With an exponential distribution, although there is a slight, probabilistic bias in the timing between two fetches when the user sent a message in between, we can assume that messages are sent by users on a reasonably random basis and so there's no practical use for the bias.

An attacker who can monitor the network of the server and the user can tell when the user is sending messages to another server because the connection from the user doesn't appear in the expected place. This attacker breaks our overlay network assumptions and therefore breaks our security guarantees.

Message encryption
------------------

Message encryption follows the lead of OTR. Parties exchange a stream of Diffie-Hellman public values as they exchange messages. We omit OTR's key identifier because that counter reveals information about the number of messages that a pair of users have exchanged. Rather we simply use trial decryption to find the DH values that a particular message is using.

In addition to omitting the key identifier, we also omit OTR's anti-replay counter for the same reason. This allows servers to replay messages to users, although each message has a unique ID and a timestamp. Users have a time-limited anti-replay window within which duplicate messages are suppressed and, outside of that, using the timestamp on the message is viable and abnormally old messages should be highlighted.

As a matter of custom, users delete messages after a number of days (currently a week). Of course, there is nothing to enforce this in the same way that there's nothing to enforce the custom that OTR IM conversations aren't logged.

Spam
----

Since the bandwidth of this system is so low, a user can trivially be incapacitated by a small number of messages. Because of this, we make the system closed: only authorised users can cause a message to be queued for delivery. This very clearly sets Pond apart from email. There are no public addresses to which a Pond message can be sent. Likewise, it's no longer true that the network is fully connected; if you send a message to two people, they may not be able to reply to each other.

This policy has to be enforced at the servers as they're the parties who accept and enqueue messages. However, we don't want the servers to learn who is sending each message, so we cannot have them authenticate against a list of allowed senders for each user. We could give all allowed senders some shared secret, but then we cannot revoke someone's access without rekeying the entire user's contact list.

So we use a [group signature scheme](http://www.robotics.stanford.edu/~xb/crypto04a/groupsigs.pdf). A server knows a group public key for each user that it accepts mail for. The user provides their contacts with a distinct member private key during key exchange. In order for a message to be delivered to a user's server, the message must be signed by that user's group and the server cannot learn which member of the group signed it.

However, if access needs to be revoked, the user can calculate a revocation for a specific member private key and hand it to the server. In order that the server not then be able to deanonymise all previous messages from the newly revoked contact, the revocation works in such a way that all previous signatures become invalid and each member has to update their private keys given the revocation information. (Except the revoked user, who cannot update their key.). Contacts learn the revocation information when they next contact the user's server and attempt to deliver a message. The delivery will fail, but non-revoked users can update their member private keys and retry successfully.

Storage
-------

In order for forward secrecy to be effective, we need a method of deleting expired data so that it cannot be recovered. This is largely an implementation issue. Normal disks work fairly well, but backup schemes can confound secure deletion and so can bad-block remapping. To address the latter as much as possible, we save all state in a single file that is encrypted with a random session key and overwritten for every update. This causes large amounts of overwriting as a matter of course and we also smear the random nonce over 32KB of disk, all of which must be recovered in order to decrypt the file. (And the session key may itself be encrypted with a pass-phrase.)

(With the advent of SSDs, this may not be sufficient, but see below.)

Implementation
--------------

Currently very threadbare, although all of the above works in a basic fashion save for revocation.

![Pond UI](https://raw.github.com/agl/pond/master/pond.png)


Transport Details
-----------------

The transport protocol falls into the category of mutual authentication with identity hiding and is very much taken from the SIGMA-I protocol in section 5.2 of [this paper](http://webee.technion.ac.il/~hugo/sigma-pdf.pdf).

Initially both sides exchange fresh Diffie-Hellman public values in the curve25519 group. From the shared secret, sessions keys for each direction are derived as `SHA256("client keys\x00" + shared_secret)` and `SHA256("server keys\x00" + shared_secret)`. All future messages on the connection are encrypted and authenticated as described in section 9 of [naclcrypto](http://cr.yp.to/highspeed/naclcrypto-20090310.pdf) (i.e. NaCl's secretbox) with a counter nonce.

The server calculates the Diffie-Hellman shared secret between the client's ephemeral public value and the server's long-term, Diffie-Hellman public value, which we'll call `k`. It then sends `HMAC_SHA256(key = k, message = "server proof\x00" + SHA256(clients_ephemeral_public + servers_ephemeral_public))`.

The client is assumed to know the server's long-term key via other means and decrypts and verifies the HMAC. If correct, it sends its long-term, Diffie-Hellman public, as well as a similar HMAC keyed with the shared-secret between the two long-term keys: `HMAC_SHA256(key = k2, message = "client proof\x00" + SHA256(clients_ephemeral_public + servers_ephemeral_public + hmac_from_server))`. (Note that the client's long-term key may actually be ephemeral if the client wishes to authenticate anonymously.)

At this point, the handshake is complete. The client now sends a padded request to the server, the server replies with an identically padded message and the client finishes by sending an empty message. All these are encrypted and authenticated with NaCl secretbox, as everything since the initial Diffie-Hellman exchange has been.

For details of the higher level protocol, see the [protobufs](https://github.com/agl/pond/blob/master/protos/pond.proto).

It's currently an unanswered question whether timing differences between the home server and other servers will reveal to a network attacker which the user is communicating with and thus when the user is sending messages. Pond sets a random SOCKS5 username in order to request of Tor that different paths be used for every connection but it may be that servers need to delay their replies for a fixed amount of time.

Key Exchange Details
--------------------

Key exchange between two users involves each creating a KeyExchange protobuf (see [protobufs](https://github.com/agl/pond/blob/master/protos/pond.proto) ). Since Pond servers demand a group signature before accepting a message for delivery, there are no public Pond addresses that can be used to bootstrap a Pond relationship. Rather we currently assume an external, confidential and authentic means for users to exchange KeyExchange messages.

(This may be an important weakness. One obvious answer is to have servers accept, say, 10% of a user's quota of unsigned 'introduction' messages.)

A KeyExchange contains a group member private key (which is why they need to be confidential), as well as the information needed to direct a message to a user: their home server and public identity at that server. They also contain an Ed25519 key and the intent is that, in the future, users will be able to update their home servers by sending messages to each of their contacts. Group member revocations will also be signed by this key.

Lastly, key exchange establishes a pair of initial Diffie-Hellman values for encrypting messages. These Diffie-Hellman values are advanced in a way similar to OTR, as detailed next.


Message Details
---------------

Messages are protocol buffers which are padded to a fixed size (currently 16KB - 512 bytes) and then encrypted and authenticated in a NaCl box. The random, 24-byte nonce is prepended to the boxed message. Messages contain within them a 'next' Diffie-Hellman public value from the client. For each contact, the client maintains a 'last' and 'current' Diffie-Hellman private key, as well as a 'last' and 'current' Diffie-Hellman public key from the contact.

On receipt of a message, the client tries each of the four combinations in order to avoid numbering the keys and having the maintain state that reveals the number of messages exchanged. If the client finds that a message was encrypting using its 'current' DH key, the contact has clearly received that key and the client rotates keys and generates a new 'current' private key which will be included in future messages to that contact.

In order to facilitate the exchange of messages (and the ratcheting of Diffie-Hellman values) when, semantically, the flow of information may be more unidirectional, Pond encourages messages to be acknowledged. An acknowledgment is a user-initiated action that involves sending an empty reply to a message. This both lets the sender know that their message has been received and allows new Diffie-Hellman values to flow back.

Storage Details
---------------

Pond depends, critically, on the ability to erase information. Forward security can be rendered moot if old state can be recovered and decrypted from a disk.

Pond allows the user to choose an encryption passphrase for the state file, which is processed with scrypt (N=32768, r=12). The scrypt salt is stored in the first 32 bytes of the file. Following that, a 24-byte nonce is XOR smeared over 32KB and every bit must be recovered in order to decrypt the file.

The remainder of the file is a NaCl secretbox, the plaintext contents of which are padded up to the nearest power of two with a minimum size of 128KB.

The whole state file is overridden on each update in the hope that this makes older versions impossible to recover.

Importantly, this may be ineffective for SSDs, which are becoming more common. Internally, SSDs run a log-structured file-system and so when the state file is intended to be overridden, it's more likely that a new copy is written. [One paper](http://www.dfrws.org/2011/proceedings/17-349.pdf) suggests that the TRIM command is very effective against attacks that fall short of opening and reading the flash chips directly. However, it appears that Linux doesn't send TRIM commands for every file erase by default for performance reasons.

Weaknesses
----------

1. The code is terribly incomplete, unreviewed and I pulled the design out of my backside without consulting anyone.
1. It's not clear that the method of erasing previous state works at all for SSDs.
1. Although the protocol doesn't expose too much opportunity for timing attacks (esp given that it works over Tor), several of the primitives do not have constant time implementations on non-amd64 systems, or at all.
1. The key exchange system may be too hard for users to get right.
1. The system may be too slow for anyone to bother using.
1. Measurements about whether timing information can distinguish servers over Tor needs to be collected.
1. *your idea here*
