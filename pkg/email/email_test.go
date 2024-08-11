package email_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"testing"

	_ "github.com/joho/godotenv/autoload"
	"github.com/starnuik/golang_jwt_service/pkg/email"
	"github.com/starnuik/golang_jwt_service/pkg/model"
	"github.com/stretchr/testify/require"
)

// these tests require a deployed smtp (rnwood/smtp4dev) instance
var (
	smtpHostname = os.Getenv("TESTING_SMTP_HOSTNAME")
	smtpUrl      = os.Getenv("TESTING_SMTP_URL")
	smtpWeb      = os.Getenv("TESTING_SMTP_WEB")
)

// A sanity check.
// This test will fail if the testing server is down / env variables are not set correctly.
func TestSmtpConnection(t *testing.T) {
	require := require.New(t)

	url := fmt.Sprintf("%s/api/Version", smtpWeb)
	resp, err := http.Get(url)
	require.Nil(err)

	defer resp.Body.Close()

	into := struct {
		Version     string `json:"version"`
		InfoVersion string `json:"infoVersion"`
	}{}
	err = json.NewDecoder(resp.Body).Decode(&into)
	require.Nil(err)
	require.NotEqual("", into.Version)
	require.NotEqual("", into.InfoVersion)
}

func TestMailSender(t *testing.T) {
	require := require.New(t)
	mail := email.NewSender(smtpUrl, smtpHostname)

	user := &model.User{
		Name:  "Mock Human",
		Email: "mock_human@test.com",
	}

	lastSeen := smtpLastSeen()

	err := mail.AddressChanged(user, netip.AddrFrom4([4]byte{12, 34, 56, 78}), netip.AddrFrom4([4]byte{34, 56, 78, 90}))
	require.Nil(err)

	// check that the smtp server received the message
	newCount := smtpCountNew(lastSeen)
	require.Equal(1, newCount)

	err = mail.TokenStolen(user)
	require.Nil(err)

	// check that the smtp server received the message
	newCount = smtpCountNew(lastSeen)
	require.Equal(2, newCount)
}

func smtpLastSeen() string {
	url := fmt.Sprintf("%s/api/Messages/new?pageSize=1", smtpWeb)
	resp, _ := http.Get(url)

	defer resp.Body.Close()

	into := []struct {
		Id string `json:"id"`
	}{}
	json.NewDecoder(resp.Body).Decode(&into)
	if len(into) == 0 {
		return ""
	}
	return into[0].Id
}

func smtpCountNew(lastSeen string) int {
	url := fmt.Sprintf("%s/api/Messages/new?pageSize=100&lastSeenMessageId=%s", smtpWeb, lastSeen)
	resp, _ := http.Get(url)

	defer resp.Body.Close()

	into := []struct {
		Id string `json:"id"`
	}{}
	json.NewDecoder(resp.Body).Decode(&into)
	return len(into)
}
