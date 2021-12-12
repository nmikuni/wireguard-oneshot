package wireguard

import (
	"bytes"
	"encoding/binary"
	"net"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

type Handshake struct {
	hash                      [blake2s.Size]byte       // hash value
	chainKey                  [blake2s.Size]byte       // chain key
	presharedKey              NoisePresharedKey        // psk
	localEphemeral            NoisePrivateKey          // ephemeral secret key
	localIndex                uint32                   // used to clear hash-table
	remoteIndex               uint32                   // index for sending
	remoteStatic              NoisePublicKey           // long term key
	precomputedStaticStatic   [NoisePublicKeySize]byte // precomputed shared secret
}

type MessageInitiation struct {
	Type      uint32
	Sender    uint32
	Ephemeral NoisePublicKey
	Static    [NoisePublicKeySize + chacha20poly1305.Overhead]byte
	Timestamp [timestampSize + chacha20poly1305.Overhead]byte
	MAC1      [blake2s.Size128]byte
	MAC2      [blake2s.Size128]byte
}

type MessageResponse struct {
	Type      uint32
	Sender    uint32
	Receiver  uint32
	Ephemeral NoisePublicKey
	Empty     [chacha20poly1305.Overhead]byte
	MAC1      [blake2s.Size128]byte
	MAC2      [blake2s.Size128]byte
}

const (
	NoiseConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	WGIdentifier      = "WireGuard v1 zx2c4 Jason@zx2c4.com"
)

const (
	MessageInitiationType  = 1
	MessageResponseType    = 2
	MessageCookieReplyType = 3
	MessageTransportType   = 4
)

const (
	MessageInitiationSize      = 148                                           // size of handshake initiation message
	MessageResponseSize        = 92                                            // size of response message
	MessageCookieReplySize     = 64                                            // size of cookie reply message
	MessageTransportHeaderSize = 16                                            // size of data preceding content in transport message
	MessageTransportSize       = MessageTransportHeaderSize + chacha20poly1305.Overhead // size of empty transport
	MessageKeepaliveSize       = MessageTransportSize                          // size of keepalive
	MessageHandshakeSize       = MessageInitiationSize                         // size of largest handshake related message
)

var (
	InitialHash     [blake2s.Size]byte
	ZeroNonce       [chacha20poly1305.NonceSize]byte
)

func handshake(config Configuration) (*Keypair, net.Conn, error) {
	handshake := new(Handshake)
	handshake.chainKey = blake2s.Sum256([]byte(NoiseConstruction))
	mixHash(&handshake.hash, &handshake.chainKey, []byte(WGIdentifier))

	var privateKey NoisePrivateKey
	err := decodeBase64(privateKey[:], config.PrivateKey)
	if err != nil {
		return nil, nil, err
	}
	privateKey.clamp()

	publicKey := privateKey.publicKey()

	var peerPublicKey NoisePublicKey
	err = decodeBase64(peerPublicKey[:], config.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	cookieGenerator := new(CookieGenerator)
	cookieGenerator.init(peerPublicKey)
	handshake.precomputedStaticStatic = privateKey.sharedSecret(peerPublicKey)
	handshake.remoteStatic = peerPublicKey
	handshake.localEphemeral, err = newPrivateKey()

	if err != nil {
		return nil, nil, err
	}

	handshake.mixHash(handshake.remoteStatic[:])
	msg := MessageInitiation{
		Type:      MessageInitiationType,
		Ephemeral: handshake.localEphemeral.publicKey(),
	}

	handshake.mixKey(msg.Ephemeral[:])
	handshake.mixHash(msg.Ephemeral[:])

	ss := handshake.localEphemeral.sharedSecret(handshake.remoteStatic)
	if isZero(ss[:]) {
		return nil, nil, err
	}

	var key1 [chacha20poly1305.KeySize]byte
	kdf2(
		&handshake.chainKey,
		&key1,
		handshake.chainKey[:],
		ss[:],
	)

	aead, _ := chacha20poly1305.New(key1[:])
	aead.Seal(msg.Static[:0], ZeroNonce[:], publicKey[:], handshake.hash[:])
	handshake.mixHash(msg.Static[:])

	if isZero(handshake.precomputedStaticStatic[:]) {
		return nil, nil, err
	}

	kdf2(
		&handshake.chainKey,
		&key1,
		handshake.chainKey[:],
		handshake.precomputedStaticStatic[:],
	)

	timestamp := stamp(time.Now())
	aead, _ = chacha20poly1305.New(key1[:])
	aead.Seal(msg.Timestamp[:0], ZeroNonce[:], timestamp[:], handshake.hash[:])

	msg.Sender = randUint32()
	handshake.localIndex = msg.Sender

	handshake.mixHash(msg.Timestamp[:])

	var buff [MessageInitiationSize]byte
	writer := bytes.NewBuffer(buff[:0])
	binary.Write(writer, binary.LittleEndian, msg)
	packet := writer.Bytes()
	cookieGenerator.addMacs(packet)

	conn, err := net.Dial("udp4", config.Endpoint)
    if err != nil {
		return nil, nil, err
    }

    _, err = conn.Write(packet)
    if err != nil {
        return nil, nil, err
    }

    buffer := make([]byte, UdpRecieveSize)
    length, err := conn.Read(buffer)
    if err != nil {
        return nil, nil, err
    }

	var response MessageResponse
	reader := bytes.NewReader(buffer[:length])
	err = binary.Read(reader, binary.LittleEndian, &response)
	if err != nil {
		return nil, nil, err
	}

	var (
		hash     [blake2s.Size]byte
		chainKey [blake2s.Size]byte
	)

	mixHash(&hash, &handshake.hash, response.Ephemeral[:])
	mixKey(&chainKey, &handshake.chainKey, response.Ephemeral[:])

	ss1 := handshake.localEphemeral.sharedSecret(response.Ephemeral)
	mixKey(&chainKey, &chainKey, ss1[:])
	setZero(ss1[:])

	ss2 := privateKey.sharedSecret(response.Ephemeral)
	mixKey(&chainKey, &chainKey, ss2[:])
	setZero(ss2[:])

	var tau [blake2s.Size]byte
	var key2 [chacha20poly1305.KeySize]byte
	kdf3(
		&chainKey,
		&tau,
		&key2,
		chainKey[:],
		handshake.presharedKey[:],
	)
	mixHash(&hash, &hash, tau[:])

	aead1, _ := chacha20poly1305.New(key2[:])
	_, err = aead1.Open(nil, ZeroNonce[:], response.Empty[:], hash[:])
	if err != nil {
		return nil, nil, err
	}
	mixHash(&hash, &hash, response.Empty[:])

	handshake.hash = hash
	handshake.chainKey = chainKey
	handshake.remoteIndex = response.Sender

	setZero(hash[:])
	setZero(chainKey[:])

	var sendKey [chacha20poly1305.KeySize]byte
	var recvKey [chacha20poly1305.KeySize]byte

	kdf2(
		&sendKey,
		&recvKey,
		handshake.chainKey[:],
		nil,
	)

	setZero(handshake.chainKey[:])
	setZero(handshake.hash[:])
	setZero(handshake.localEphemeral[:])

	keypair := new(Keypair)
	keypair.send, _ = chacha20poly1305.New(sendKey[:])
	keypair.receive, _ = chacha20poly1305.New(recvKey[:])

	setZero(sendKey[:])
	setZero(recvKey[:])

	keypair.created = time.Now()
	keypair.localIndex = handshake.localIndex
	keypair.remoteIndex = handshake.remoteIndex

	return keypair, conn, nil
}

func (h *Handshake) mixHash(data []byte) {
	mixHash(&h.hash, &h.hash, data)
}

func (h *Handshake) mixKey(data []byte) {
	mixKey(&h.chainKey, &h.chainKey, data)
}