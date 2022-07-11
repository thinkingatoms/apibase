/*
Copyright © 2022 THINKINGATOMS LLC <atom@thinkingatoms.com>
*/

package models

import "github.com/rs/zerolog/log"

type SMSClient struct {
	From       string
	ServiceSID string
}

func SMSFromConfig(config map[string]any) *SMSClient {
	return &SMSClient{
		From:       config["from"].(string),
		ServiceSID: config["service_sid"].(string),
	}
}

func (self *SMSClient) Send(to, msg string) error {
	log.Info().Msgf("Sending SMS to %s: %s", to, msg)
	return nil
}
