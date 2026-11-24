# reparix/credentials

Context-aware JSON sealing for provider credentials. The integration AAD is
`credentials|<team>|<provider>`; the messaging AAD is
`reparix:messaging:v1:<team>:<channel>:<provider>`. These byte formats are a
storage compatibility contract: changing them makes existing values
undecryptable. The package delegates key parsing, JSON encoding, and the `v1:`
AES-GCM envelope to `reparix/sealed`.
