package azure

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/preview/preview/containerregistry/runtime/containerregistry"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/image/registry/intf"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

type RegistryClient struct {
	domain string
	scope  string
	cloud  cloud.Configuration
}

type Registry struct {
}

const (
	azureURL      = ".azurecr.io"
	chinaAzureURL = ".azurecr.cn"
	scope         = "https://management.azure.com/.default"
	chinaScope    = "https://management.chinacloudapi.cn/.default"
	scheme        = "https"
)

func (r *Registry) CheckOptions(domain string, _ types.RegistryOptions) (intf.RegistryClient, error) {
	if strings.HasSuffix(domain, azureURL) {
		return &RegistryClient{
			domain: domain,
			scope:  scope,
			cloud:  cloud.AzurePublic,
		}, nil
	} else if strings.HasSuffix(domain, chinaAzureURL) {
		return &RegistryClient{
			domain: domain,
			scope:  scope,
			cloud:  cloud.AzureChina,
		}, nil
	}

	return nil, xerrors.Errorf("Azure registry: %w", types.InvalidURLPattern)
}

func (r *RegistryClient) GetCredential(ctx context.Context) (string, string, error) {
	log.Info("Starting Azure Container Registry credential retrieval", log.String("domain", r.domain), log.String("scope", r.scope))

	opts := azcore.ClientOptions{Cloud: r.cloud}
	cred, err := azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{ClientOptions: opts})
	if err != nil {
		log.Info("Failed to generate Azure credential", log.String("domain", r.domain), log.Err(err))
		return "", "", xerrors.Errorf("unable to generate acr credential error: %w", err)
	}
	log.Info("Successfully generated Azure credential", log.String("domain", r.domain))

	aadToken, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{r.scope}})
	if err != nil {
		log.Info("Failed to get AAD access token", log.String("domain", r.domain), log.String("scope", r.scope), log.Err(err))
		return "", "", xerrors.Errorf("unable to get an access token: %w", err)
	}
	log.Info("Successfully obtained AAD access token", log.String("domain", r.domain), log.String("scope", r.scope))

	rt, err := refreshToken(ctx, aadToken.Token, r.domain)
	if err != nil {
		log.Info("Failed to refresh token", log.String("domain", r.domain), log.Err(err))
		return "", "", xerrors.Errorf("unable to refresh token: %w", err)
	}
	log.Info("Successfully refreshed token", log.String("domain", r.domain))

	log.Info("Azure Container Registry credential retrieval completed successfully", log.String("domain", r.domain))
	return "00000000-0000-0000-0000-000000000000", *rt.RefreshToken, err
}

func refreshToken(ctx context.Context, accessToken, domain string) (containerregistry.RefreshToken, error) {
	log.Info("Starting token refresh process", log.String("domain", domain))

	tenantID := os.Getenv("AZURE_TENANT_ID")
	if tenantID == "" {
		log.Info("Missing AZURE_TENANT_ID environment variable", log.String("domain", domain))
		return containerregistry.RefreshToken{}, errors.New("missing environment variable AZURE_TENANT_ID")
	}
	log.Info("Found AZURE_TENANT_ID environment variable", log.String("domain", domain), log.String("tenantID", tenantID))

	log.Info("Creating refresh tokens client", log.String("domain", domain))
	repoClient := containerregistry.NewRefreshTokensClient(fmt.Sprintf("%s://%s", scheme, domain))

	log.Info("Attempting to exchange access token for refresh token", log.String("domain", domain), log.String("tenantID", tenantID))
	refreshToken, err := repoClient.GetFromExchange(ctx, "access_token", domain, tenantID, "", accessToken)
	if err != nil {
		log.Info("Failed to exchange access token for refresh token", log.String("domain", domain), log.String("tenantID", tenantID), log.Err(err))
		return containerregistry.RefreshToken{}, err
	}

	log.Info("Successfully exchanged access token for refresh token", log.String("domain", domain), log.String("tenantID", tenantID))
	return refreshToken, nil
}
