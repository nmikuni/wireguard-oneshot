package main

import (
	"encoding/base64"
	"encoding/json"

	"github.com/1stship/wireguard-oneshot"
	"github.com/aws/aws-lambda-go/events"
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

func handler(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	body := request.Body
	var bodyDecoded []byte
	if request.IsBase64Encoded {
		bodyDecoded, _ = base64.StdEncoding.DecodeString(body)
	} else {
		bodyDecoded = []byte(body)
	}
	
	var input ArcGateway
	err := json.Unmarshal(bodyDecoded, &input)
	if err != nil {
		return events.APIGatewayProxyResponse{
			Body:       string(err.Error()),
			StatusCode: 400,
		}, err
	}

	config := wireguard.Configuration {
		PrivateKey: input.PrivateKey,
		PublicKey: input.PublicKey,
		Endpoint: input.Endpoint,
		ClientIpAddress: input.ClientIpAddress,
	}

	var payload []byte
	if input.PayloadFormat == "base64" {
		payload, err = base64.StdEncoding.DecodeString(input.Payload)
	    if err != nil {
		    return events.APIGatewayProxyResponse{
				Body:       string(err.Error()),
				StatusCode: 400,
			}, err
	    }
	} else {
		payload = []byte(input.Payload)
	}

	receivedBuffer, err := wireguard.UdpOneShot(payload, input.DestinationIpAddress, input.DestinationPort, config)
	if err != nil {
		return events.APIGatewayProxyResponse{
			Body:       string(err.Error()),
			StatusCode: 400,
		}, err
	}

	for i := 0; i < len(receivedBuffer); i++ {
		if (receivedBuffer[i] == 0) {
			receivedBuffer = receivedBuffer[0:i]
			break
		}
	}

	return events.APIGatewayProxyResponse{
        Body:       string(receivedBuffer),
        StatusCode: 200,
    }, nil
}
