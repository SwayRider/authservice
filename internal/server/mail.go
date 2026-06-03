package server

import "github.com/swayrider/grpcclients/mailclient"

// MailSender abstracts the mail client used for sending transactional emails.
// This allows server handlers to be tested without a real mail service connection.
type MailSender interface {
	SendTemplateInternal(mail *mailclient.TemplateMail) (string, error)
}
