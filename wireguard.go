package wireguard

type Configuration struct {
    PrivateKey     string
    PublicKey      string
    Endpoint             string 
	ClientIpAddress      string 
}

func UdpOneShot(payload []byte, destinationIpAddress string, destinationPort int, config Configuration) ([]byte, error) {
	keypair, conn, err := handshake(config)
	if err != nil {
		return nil, err
	}

	ret, err := udpOneShot(payload, destinationIpAddress, destinationPort, config.ClientIpAddress, keypair, conn)
	if err != nil {
		return nil, err
	}

	return ret, nil
}
