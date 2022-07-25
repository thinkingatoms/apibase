package models

import (
	"context"
	"github.com/jordan-wright/email"
	"github.com/thinkingatoms/apibase/ez"
	errors "golang.org/x/xerrors"
	"net/smtp"
	"strconv"
)

type EmailClient struct {
	From         string `json:"from,omitempty"`
	To           string `json:"to,omitempty"`
	SMTPHost     string `json:"smtp_host,omitempty"`
	SMTPPort     int    `json:"smtp_port,omitempty"`
	SMTPUser     string `json:"smtp_user,omitempty"`
	SMTPPassword string `json:"smtp_password,omitempty"`
	smtpURI      string
	auth         smtp.Auth
}

func EmailClientFromConfig(config map[string]any) *EmailClient {
	ec := EmailClient{SMTPPort: 587}
	ez.PanicIfErr(ez.MapToObject(config, &ec))
	ec.smtpURI = ec.SMTPHost + ":" + strconv.Itoa(ec.SMTPPort)
	ec.auth = smtp.PlainAuth("", ec.SMTPUser, ec.SMTPPassword, ec.SMTPHost)
	return &ec
}

func (self *EmailClient) Send(_ context.Context, to, subject, body string) error {
	if to == "" {
		to = self.To
	}
	if to == "" {
		return errors.New("must specify recipients")
	}

	e := email.Email{
		To:      []string{to},
		From:    self.From,
		Subject: subject,
		Text:    []byte(body),
	}
	return e.Send(self.smtpURI, self.auth)
}
