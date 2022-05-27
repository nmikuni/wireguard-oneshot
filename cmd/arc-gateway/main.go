package main

import (
	"fmt"

	"github.com/1stship/wireguard-oneshot"
	"github.com/aws/aws-lambda-go/lambda"
)

type ArcGateway struct {
	PrivateKey           string `json:"privateKey"`
	PublicKey            string `json:"publicKey"`
	Endpoint             string `json:"endpoint"`
	ClientIpAddress      string `json:"clientIpAddress"`
	DestinationIpAddress string `json:"destinationIpAddress"`
	DestinationPort      int    `json:"destinationPort"`
	Payload              string `json:"payload"`
	PayloadFormat        string `json:"payloadFormat"`
}

func main() {
	lambda.Start(handler)
}

func handler(event ArcGateway) error {

	// TODO: We should handle error case of wrong type of event
	var input = event

	config := wireguard.Configuration{
		PrivateKey:      input.PrivateKey,
		PublicKey:       input.PublicKey,
		Endpoint:        input.Endpoint,
		ClientIpAddress: input.ClientIpAddress,
	}

	var payload []byte
	payload = []byte(input.Payload)

	receivedBuffer, err := wireguard.UdpOneShot(payload, input.DestinationIpAddress, input.DestinationPort, config)
	if err != nil {
		fmt.Println("Error sending data to Harvest Data")
		return nil
	}

	for i := 0; i < len(receivedBuffer); i++ {
		if receivedBuffer[i] == 0 {
			receivedBuffer = receivedBuffer[0:i]
			break
		}
	}

	// It is better to return not nil but the returned value
	return nil
}
