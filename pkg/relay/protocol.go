package relay

import "encoding/json"

// ParseRequest parses a request from the client.
// The return value can be:
//
//	Publish
//	Subscribe
func ParseRequest(data []byte) (any, error) {
	request := &Request{}
	if err := json.Unmarshal(data, request); err != nil {
		return nil, err
	}

	if request.Publish != nil {
		return request.Publish, nil
	}

	if request.Subscribe != nil {
		return request.Subscribe, nil
	}

	return nil, nil
}

// ParseResponse parses a response from the server.
// The return value can be:
//
//	EventPublishResponse
//	RelayServerIdentifyResponse
//	SubscribeResponse
//	RelayServerNotice
func ParseResponse(data []byte) (any, error) {
	response := &Response{}
	if err := json.Unmarshal(data, response); err != nil {
		return nil, err
	}

	if response.EventPublishResponse != nil {
		return response.EventPublishResponse, nil
	}

	if response.RelayServerIdentifyResponse != nil {
		return response.RelayServerIdentifyResponse, nil
	}

	if response.SubscribeResponse != nil {
		return response.SubscribeResponse, nil
	}

	if response.Notice != nil {
		return response.Notice, nil
	}

	return nil, nil
}
