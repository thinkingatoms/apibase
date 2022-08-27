/*
Copyright © 2022 THINKINGATOMS LLC <atom@thinkingatoms.com>
*/

package models

import (
	"context"
	"github.com/twilio/twilio-go"
	openapi "github.com/twilio/twilio-go/rest/api/v2010"
	errors "golang.org/x/xerrors"
	"strconv"
	"strings"
)

type SMSClient struct {
	from         string
	serviceSID   string
	twilioClient *twilio.RestClient
	emailClient  *EmailClient
	smsGateways  *SMSGateways
}

type SMSMessage struct {
	Phone   string `json:"phone"`
	Body    string `json:"body,omitempty"`
	Gateway string `json:"gateway,omitempty"`
	Country string `json:"country,omitempty"`
}

func (self *SMSMessage) GetPhone(client *SMSClient, withCountryCode bool) (string, error) {
	phone := self.Phone
	countryCode, err := client.GetCountryCode(self.Country)
	if err != nil {
		return "", err
	}
	switch self.Country {
	case "US":
		phone = strings.ReplaceAll(phone, "-", "")
		phone = strings.ReplaceAll(phone, "(", "")
		phone = strings.ReplaceAll(phone, ")", "")
		phone = strings.ReplaceAll(phone, "+", "")
		if _, err := strconv.ParseInt(phone, 10, 64); err != nil {
			return "", err
		}
		if len(phone) <= 9 {
			return "", errors.New("phone number too small")
		}
	default:
		return "", errors.New("does not support country " + self.Country)
	}
	if withCountryCode {
		return countryCode + phone, nil
	}
	return phone, nil
}

func (self *SMSMessage) GetEmail(client *SMSClient) (string, error) {
	phone, err := self.GetPhone(client, false)
	if err != nil {
		return "", err
	}
	var server string
	server, err = client.GetSMSServer(self.Country, self.Gateway)
	if err != nil {
		return "", err
	}
	return phone + "@" + server, nil
}

type SMSGateways struct {
	Countries map[string]SMSGatewayCountry `json:"countries"`
	Gateways  map[string]map[string]string `json:"gateways"`
}

type SMSGatewayCountry struct {
	CountryCode string              `json:"code"`
	Gateways    map[string]struct{} `json:"gateways"`
}

func SMSFromConfig(config map[string]any, emailClient *EmailClient) (*SMSClient, error) {
	c := SMSClient{
		emailClient: emailClient,
		twilioClient: twilio.NewRestClientWithParams(
			twilio.ClientParams{
				Username: config["account_id"].(string),
				Password: config["auth_token"].(string),
			}),
		from:       config["from"].(string),
		serviceSID: config["service_sid"].(string),
	}
	if config["sms_gateways"] != nil {
		config = config["sms_gateways"].(map[string]any)
		countries := make(map[string]SMSGatewayCountry)
		gateways := make(map[string]map[string]string)
		for k, v := range config["countries"].(map[string]any) {
			vv := v.(map[string]any)
			gateways := vv["gateways"].([]any)
			gs := make(map[string]struct{}, len(gateways))
			for _, g := range gateways {
				gs[g.(string)] = struct{}{}
			}
			gc := SMSGatewayCountry{
				CountryCode: vv["code"].(string),
				Gateways:    gs,
			}
			countries[k] = gc
		}
		for k, v := range config["gateways"].(map[string]any) {
			d := make(map[string]string)
			gateways[k] = d
			for k, g := range v.(map[string]any) {
				d[k] = g.(string)
			}
		}
		c.smsGateways = &SMSGateways{
			Gateways:  gateways,
			Countries: countries,
		}
	}
	return &c, nil
}

func (self *SMSClient) GetSMSGatewayCountries() map[string]SMSGatewayCountry {
	if self.smsGateways == nil {
		return make(map[string]SMSGatewayCountry)
	}
	return self.smsGateways.Countries
}

func (self *SMSClient) Send(msg *SMSMessage) error {
	if msg.Gateway != "" {
		email, err := msg.GetEmail(self)
		if err != nil {
			return err
		}
		return self.emailClient.Send(context.Background(), email, "", msg.Body)
	}
	phone, err := msg.GetPhone(self, true)
	if err != nil {
		return err
	}
	_, err = self.twilioClient.Api.CreateMessage(&openapi.CreateMessageParams{
		MessagingServiceSid: &self.serviceSID,
		To:                  &phone,
		From:                &self.from,
		Body:                &msg.Body,
	})
	return err
}

func (self *SMSClient) GetCountryCode(country string) (string, error) {
	if c, ok := self.smsGateways.Countries[country]; ok {
		return c.CountryCode, nil
	}
	return "", errors.New("unknown country specified: " + country)
}

func (self *SMSClient) GetSMSServer(country, gateway string) (string, error) {
	if self.smsGateways == nil {
		return "", errors.New("not configured to send SMS via email gateway")
	}
	if v, ok := self.smsGateways.Gateways[gateway]; ok {
		if c, ok := self.smsGateways.Countries[country]; ok {
			if _, ok := c.Gateways[gateway]; ok {
				return v["sms"], nil
			}
		}
	}
	return "", errors.New("unknown gateway/country specified: " + gateway + "/" + country)
}
