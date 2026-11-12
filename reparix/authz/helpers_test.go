package authz

import "github.com/ModdingFriendly/appwrite-library/appwrite"

func appwriteConfig(endpoint, project string) appwrite.Config {
	return appwrite.Config{Endpoint: endpoint, ProjectID: project, APIKey: "should-be-dropped", DatabaseID: "db"}
}
