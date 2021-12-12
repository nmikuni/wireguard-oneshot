package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"

	"github.com/1stship/wireguard-oneshot"
)

func main() {
	var privateKey string
	var publicKey string
	var endpoint string
	var clientIpAddress string
	var destinationIpAddress string
	var destinationPort int
	var payload string
	var payloadFormat string
	flag.StringVar(&privateKey, "privateKey", "", "サーバーの秘密鍵")
	flag.StringVar(&publicKey, "publicKey", "", "サーバーの公開鍵")
	flag.StringVar(&endpoint, "endpoint", "", "サーバーのエンドポイント")
	flag.StringVar(&clientIpAddress, "clientIpAddress", "", "クライアントのIPアドレス")
	flag.StringVar(&destinationIpAddress, "destinationIpAddress", "", "宛先のIPアドレス")
	flag.IntVar(&destinationPort, "destinationPort", 0, "宛先ポート")
	flag.StringVar(&payload, "payload", "", "ペイロード")
	flag.StringVar(&payloadFormat, "payloadFormat", "", "ペイロードの形式(text or base64)")
	flag.Parse()

	var payloadBytes []byte
	var err error
	if payloadFormat == "base64" {
		payloadBytes, err = base64.StdEncoding.DecodeString(payload)
	    if err != nil {
		    fmt.Println(err)
			os.Exit(1)
	    }
	} else {
		payloadBytes = []byte(payload)
	}

	valid := true

	if privateKey == "" {
		fmt.Println("Private key must not be empty.")
		valid = false
	}

	if publicKey == "" {
		fmt.Println("Public key must not be empty.")
		valid = false
	}

	if endpoint == "" {
		fmt.Println("Endpoint must not be empty.")
		valid = false
	}

	if clientIpAddress == "" {
		fmt.Println("Client IP address must not be empty.")
		valid = false
	}

	if destinationIpAddress == "" {
		fmt.Println("Destination IP address must not be empty.")
		valid = false
	}

	if destinationPort == 0 {
		fmt.Println("Destination Port must not be empty.")
		valid = false
	}

	if !valid {
		flag.PrintDefaults()
		os.Exit(1)
	}

	config := wireguard.Configuration {
		PrivateKey: privateKey,
		PublicKey: publicKey,
		Endpoint: endpoint,
		ClientIpAddress: clientIpAddress,
	}

	receivedBuffer, err := wireguard.UdpOneShot(payloadBytes, destinationIpAddress, destinationPort, config)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(string(receivedBuffer))
}