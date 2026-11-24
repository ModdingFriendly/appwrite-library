// Package credentials seals provider settings using stable Reparix context AAD.
// Changing an AAD format makes existing stored values undecryptable.
package credentials

import "github.com/ModdingFriendly/appwrite-library/reparix/sealed"

// SealIntegrationJSON seals settings using the historical integration AAD
// credentials|<team>|<provider>.
func SealIntegrationJSON(team, provider string, value any) (string, error) {
	return sealed.SealJSON(value, integrationAAD(team, provider))
}

// OpenIntegrationJSON opens settings sealed with SealIntegrationJSON.
func OpenIntegrationJSON(team, provider, envelope string, out any) error {
	return sealed.OpenJSON(envelope, integrationAAD(team, provider), out)
}

func integrationAAD(team, provider string) []byte {
	return []byte("credentials|" + team + "|" + provider)
}

// SealMessagingJSON seals settings using the historical messaging AAD
// reparix:messaging:v1:<team>:<channel>:<provider>.
func SealMessagingJSON(team, channel, provider string, value any) (string, error) {
	return sealed.SealJSON(value, messagingAAD(team, channel, provider))
}

// OpenMessagingJSON opens settings sealed with SealMessagingJSON.
func OpenMessagingJSON(team, channel, provider, envelope string, out any) error {
	return sealed.OpenJSON(envelope, messagingAAD(team, channel, provider), out)
}

func messagingAAD(team, channel, provider string) []byte {
	return []byte("reparix:messaging:v1:" + team + ":" + channel + ":" + provider)
}
