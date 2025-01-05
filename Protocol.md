# Kiwi protocol

- Packets are sent using UDP containing a packet kind and checksum.
- The peer ip should be verified against the known peers.
- The encrypted data which can be decoded using the private key.

### 0x39 Hello

The connecting client send 32 bytes of random encrypted data for the peer to verify encryption status.

### 0x2d Hello Verify

The peer acknowledges the original hello and responds with 32 bytes of random encrypted data.

### 0x92 Hello Finish

The original peer responds acknowledging encryption and messages can start.

### 0xb6 Ping

The peer responds with `0x1a Pong`

### 0x1a Pong

The response to `0xb6 Ping`

### 0x7f Ack

Used to acknowledge receipt of user data packets

### 0x55 Whole Data

Data sent by the application encrypted using the previously acknowledged encryption.
