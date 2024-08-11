package email

import (
	"fmt"
	"net/netip"
	"net/smtp"

	"github.com/jordan-wright/email"
	"github.com/starnuik/golang_jwt_service/pkg/model"
)

type Sender struct {
	smtpUrl      string
	smtpHostname string
}

func NewSender(smtpUrl string, smtpHostname string) *Sender {
	return &Sender{
		smtpUrl:      smtpUrl,
		smtpHostname: smtpHostname,
	}
}

func (s *Sender) send(e email.Email) error {
	return e.Send(s.smtpUrl, smtp.PlainAuth("", "", "", s.smtpHostname))
}

func (s *Sender) AddressChanged(user *model.User, lastAddr netip.Addr, newAddr netip.Addr) error {
	return s.send(email.Email{
		To:      []string{user.Email},
		From:    "auth service <auth@jwt_service>",
		Subject: "Security Notice: New Ip Detected",
		Text: []byte(fmt.Sprintf(`Dear %s,
We detected a new login from a different Ip address
New Ip: %s
Old Ip: %s
- Tech Support`,
			user.Name, newAddr.String(), lastAddr.String())),
	})
}

func (s *Sender) TokenStolen(user *model.User) error {
	return s.send(email.Email{
		To:      []string{user.Email},
		From:    "auth service <auth@jwt_service>",
		Subject: "Security Notice: Attack Prevention",
		Text: []byte(fmt.Sprintf(`Dear %s
We detected a cyber attack on your account.
As a preventive measure, you were automatically logged out from our services.
- Tech Support`,
			user.Name)),
	})
}
