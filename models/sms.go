/*
Copyright © 2022 THINKINGATOMS LLC <atom@thinkingatoms.com>
*/

package models

import (
	"github.com/rs/zerolog/log"
	"github.com/twilio/twilio-go"
	openapi "github.com/twilio/twilio-go/rest/api/v2010"
)

type SMSClient struct {
	*twilio.RestClient
	from       string
	serviceSID string
}

func SMSFromConfig(config map[string]any) *SMSClient {
	return &SMSClient{
		RestClient: twilio.NewRestClientWithParams(
			twilio.ClientParams{
				Username: config["account_id"].(string),
				Password: config["auth_token"].(string),
			}),
		from:       config["from"].(string),
		serviceSID: config["service_sid"].(string),
	}
}

func (self *SMSClient) Send(to, msg string) error {
	log.Info().Msgf("Sending SMS to %s: %s", to, msg)
	log.Info().Msgf("%+v", self)
	_, err := self.RestClient.Api.CreateMessage(&openapi.CreateMessageParams{
		MessagingServiceSid: &self.serviceSID,
		To:                  &to,
		From:                &self.from,
		Body:                &msg,
	})
	return err
}
