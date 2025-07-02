package registry

import (
	"context"

	"github.com/google/go-containerregistry/pkg/authn"

	"github.com/aquasecurity/trivy/pkg/fanal/image/registry/azure"
	"github.com/aquasecurity/trivy/pkg/fanal/image/registry/ecr"
	"github.com/aquasecurity/trivy/pkg/fanal/image/registry/google"
	"github.com/aquasecurity/trivy/pkg/fanal/image/registry/intf"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

var (
	registries []intf.Registry
)

func init() {
	RegisterRegistry(&google.Registry{})
	RegisterRegistry(&ecr.ECR{})
	RegisterRegistry(&azure.Registry{})
}

func RegisterRegistry(registry intf.Registry) {
	registries = append(registries, registry)
}

func GetToken(ctx context.Context, domain string, opt types.RegistryOptions) (auth authn.Basic) {
	log.Debug("Getting token for registry", log.String("domain", domain))

	// check registry which particular to get credential
	for _, registry := range registries {
		log.Debug("Checking registry for domain", log.String("domain", domain))

		client, err := registry.CheckOptions(domain, opt)
		if err != nil {
			log.Debug("Registry check failed", log.String("domain", domain), log.Err(err))
			continue
		}

		log.Debug("Registry matched, attempting to get credentials", log.String("domain", domain))
		username, password, err := client.GetCredential(ctx)
		if err != nil {
			// only skip check registry if error occurred
			log.Debug("Credential error", log.String("domain", domain), log.Err(err))
			break
		}

		log.Debug("Successfully obtained credentials", log.String("domain", domain), log.String("username", username))
		return authn.Basic{
			Username: username,
			Password: password,
		}
	}

	log.Debug("No suitable registry found or credentials obtained", log.String("domain", domain))
	return authn.Basic{}
}
