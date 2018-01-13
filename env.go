package middleauth

import (
	"fmt"
	"strings"
)

// AuthProvider defines a login provider in details
type AuthProvider struct {

	// ID is the unique identifier among providers that
	// also used in the callback path.
	ID string

	// Name is the human readable name
	// for frontend display, such as the login page buttons.
	Name string

	// ClientID is the OAuth client ID from the provider.
	ClientID string

	// ClientID is the OAuth client secret from the provider.
	ClientSecret string
}

// EnvProviders gets login providers from environment
func EnvProviders(getEnv func(string) string) (providers []AuthProvider) {
	providers = make([]AuthProvider, 0, 4)
	protoProviders := []AuthProvider{
		{
			ID:   "google",
			Name: "Google",
		},
		{
			ID:   "facebook",
			Name: "Facebook",
		},
		{
			ID:   "twitter",
			Name: "Twitter",
		},
		{
			ID:   "github",
			Name: "Github",
		},
	}

	// read client id and key from environment
	var clientIDKey, clientSecretKey string
	for _, provider := range protoProviders {
		clientIDKey = fmt.Sprintf("OAUTH2_%s_CLIENT_ID", strings.ToUpper(provider.ID))
		clientSecretKey = fmt.Sprintf("OAUTH2_%s_CLIENT_SECRET", strings.ToUpper(provider.ID))
		if clientID, clientSecret := getEnv(clientIDKey), getEnv(clientSecretKey); clientID != "" && clientSecret != "" {
			provider.ClientID, provider.ClientSecret = clientID, clientSecret
			providers = append(
				providers,
				provider,
			)
		}
	}
	return
}

// FindProvider find provider of given ID, or return nil
func FindProvider(id string, providers []AuthProvider) *AuthProvider {
	for _, provider := range providers {
		if provider.ID == id {
			return &provider
		}
	}
	return nil
}
