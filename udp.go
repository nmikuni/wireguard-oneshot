package wireguard

import (
	"encoding/binary"
	"net"

	"golang.org/x/crypto/chacha20poly1305"
)

const PaddingSize = 16
const UdpRecieveSize = 1500

const (
	MessageTransportOffsetReceiver = 4
	MessageTransportOffsetCounter  = 8
	MessageTransportOffsetContent  = 16
)

func udpOneShot(payload []byte, destinationIpAddress string, destinationPort int, clientIpAddress string, keypair *Keypair, conn net.Conn) ([]byte, error) {
	err := udpSend(payload, destinationIpAddress, destinationPort, clientIpAddress, keypair, conn)
	if err != nil {
		return nil, err
	}

    receivedBuffer, err := udpReceive(keypair, conn)
    if err != nil {
        return nil, err
    }
	
	return receivedBuffer, nil
}

func createHeader(payload []byte, sourceIpAddress string, destinationIpAddress string, destinationPort int) []byte {
	udpHeader := make([]byte, 8)
	sourcePort := randUint16()

	binary.BigEndian.PutUint16(udpHeader[0:2], sourcePort)
	binary.BigEndian.PutUint16(udpHeader[2:4], uint16(destinationPort))
	binary.BigEndian.PutUint16(udpHeader[4:6], uint16(len(udpHeader) + len(payload)))

	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45
	ipHeader[1] = 0x00
	binary.BigEndian.PutUint16(ipHeader[2:4], uint16(len(ipHeader) + len(udpHeader) + len(payload)))
	binary.BigEndian.PutUint16(ipHeader[4:6], randUint16())
	binary.BigEndian.PutUint16(ipHeader[6:8], 0x02 << 13)
	ipHeader[8] = 0x40
	ipHeader[9] = 0x11

	sourceIp := net.ParseIP(sourceIpAddress).To4()
	copy(ipHeader[12:16], sourceIp)
	destinationIp := net.ParseIP(destinationIpAddress).To4()
	copy(ipHeader[16:20], destinationIp)
	var ipChecksum uint32 = 0
	for i := 0; i < len(ipHeader) ; i += 2 {
		ipChecksum += (uint32(ipHeader[i]) << 8) + uint32(ipHeader[i + 1])
	}
	ipChecksum = (ipChecksum & 0xffff) + (ipChecksum >> 16)
	binary.BigEndian.PutUint16(ipHeader[10:12], ^(uint16(ipChecksum)))

	var udpChecksum uint32 = 0
	for i := 12; i < 20; i += 2 {
		udpChecksum += (uint32(ipHeader[i]) << 8) + uint32(ipHeader[i + 1])
	}
	udpChecksum += uint32(ipHeader[9])
	udpChecksum += uint32(len(udpHeader) + len(payload))
	for i := 0; i < len(udpHeader) ; i += 2 {
		udpChecksum += (uint32(udpHeader[i]) << 8) + uint32(udpHeader[i + 1])
	}
	for i := 0; i < len(payload) ; i += 2 {
		udpChecksum += uint32(payload[i]) << 8
		if i + 1 < len(payload) {
			udpChecksum += uint32(payload[i + 1])
		}
	}
	udpChecksum = (udpChecksum & 0xffff) + (udpChecksum >> 16)
	binary.BigEndian.PutUint16(udpHeader[6:8], ^(uint16(udpChecksum)))

	ret := append(ipHeader, udpHeader...)
	return ret
}

func udpSend(payload []byte, destinationIpAddress string, destinationPort int, clientIpAddress string, keypair *Keypair, conn net.Conn) error {
	payloadHeader := createHeader(payload, clientIpAddress, destinationIpAddress, destinationPort)

	packet := make([]byte, len(payloadHeader) + len(payload))
	var header [MessageTransportHeaderSize]byte
	copy(packet[0:len(payloadHeader)], payloadHeader[:])
	copy(packet[len(payloadHeader):len(payloadHeader) + len(payload)], payload[:])

	var senderNonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint32(header[0:4], MessageTransportType)
	binary.LittleEndian.PutUint32(header[4:8], keypair.remoteIndex)
	binary.LittleEndian.PutUint64(header[8:16], 0)

	paddingData := make([]byte, PaddingSize)
	paddingSize := (PaddingSize - (len(packet) % PaddingSize)) % PaddingSize
	packet = append(packet, paddingData[:paddingSize]...)

	binary.LittleEndian.PutUint64(senderNonce[4:], 0)
	packet = keypair.send.Seal(
		header[:],
		senderNonce[:],
		packet,
		nil,
	)

	_, err := conn.Write(packet)
	if err != nil {
        return err
    }

	return nil
}

func udpReceive(keypair *Keypair, conn net.Conn) ([]byte, error) {
	receiveBuffer := make([]byte, UdpRecieveSize)
    receivedLength, err := conn.Read(receiveBuffer)
    if err != nil {
        return nil, err
    }

	var receiverNonce [chacha20poly1305.NonceSize]byte
	counter := receiveBuffer[MessageTransportOffsetCounter:MessageTransportOffsetContent]
	content := receiveBuffer[MessageTransportOffsetContent:receivedLength]
	copy(receiverNonce[0x4:0xc], counter)
	receivedPacket, err := keypair.receive.Open(
		content[:0],
		receiverNonce[:],
		content,
		nil,
	)
	if err != nil {
		return nil, err
	}

	receivedBuffer := receivedPacket[20 + 8:]
	return receivedBuffer, nil
}