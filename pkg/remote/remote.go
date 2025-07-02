package remote

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/hashicorp/go-multierror"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/image/registry"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/version/app"
)

type Descriptor = remote.Descriptor

// Get is a wrapper of google/go-containerregistry/pkg/v1/remote.Get
// so that it can try multiple authentication methods.
func Get(ctx context.Context, ref name.Reference, option types.RegistryOptions) (*Descriptor, error) {
	log.Info("Starting remote Get operation", log.String("ref", ref.String()))

	tr, err := httpTransport(option)
	if err != nil {
		log.Error("Failed to create http transport", log.Err(err))
		return nil, xerrors.Errorf("failed to create http transport: %w", err)
	}

	var errs error
	authCount := 0
	// Try each authentication method until it succeeds
	for _, authOpt := range authOptions(ctx, ref, option) {
		authCount++
		log.Info("Attempting authentication", log.Int("attempt", authCount), log.String("ref", ref.String()))

		remoteOpts := []remote.Option{
			remote.WithTransport(tr),
			authOpt,
		}

		if option.Platform.Platform != nil {
			p, err := resolvePlatform(ref, option.Platform, remoteOpts)
			if err != nil {
				log.Error("Platform resolution failed", log.Err(err), log.String("ref", ref.String()))
				return nil, xerrors.Errorf("platform error: %w", err)
			}
			// Don't pass platform when the specified image is single-arch.
			if p.Platform != nil {
				remoteOpts = append(remoteOpts, remote.WithPlatform(*p.Platform))
				log.Info("Using platform", log.String("platform", p.Platform.String()), log.String("ref", ref.String()))
			}
		}

		desc, err := remote.Get(ref, remoteOpts...)
		if err != nil {
			log.Info("Authentication attempt failed", log.Int("attempt", authCount), log.Err(err), log.String("ref", ref.String()))
			errs = multierror.Append(errs, err)
			continue
		}

		log.Info("Authentication successful", log.Int("attempt", authCount), log.String("ref", ref.String()))

		if option.Platform.Force {
			if err = satisfyPlatform(desc, lo.FromPtr(option.Platform.Platform)); err != nil {
				log.Error("Platform satisfaction check failed", log.Err(err), log.String("ref", ref.String()))
				return nil, err
			}
		}

		log.Info("Remote Get operation completed successfully", log.String("ref", ref.String()))
		return desc, nil
	}

	// No authentication succeeded
	log.Error("All authentication attempts failed", log.Int("total_attempts", authCount), log.Err(errs), log.String("ref", ref.String()))
	return nil, errs
}

// Image is a wrapper of google/go-containerregistry/pkg/v1/remote.Image
// so that it can try multiple authentication methods.
func Image(ctx context.Context, ref name.Reference, option types.RegistryOptions) (v1.Image, error) {
	tr, err := httpTransport(option)
	if err != nil {
		return nil, xerrors.Errorf("failed to create http transport: %w", err)
	}

	var errs error
	// Try each authentication method until it succeeds
	for _, authOpt := range authOptions(ctx, ref, option) {
		remoteOpts := []remote.Option{
			remote.WithTransport(tr),
			authOpt,
		}
		index, err := remote.Image(ref, remoteOpts...)
		if err != nil {
			errs = multierror.Append(errs, err)
			continue
		}
		return index, nil
	}

	// No authentication succeeded
	return nil, errs
}

// Referrers is a wrapper of google/go-containerregistry/pkg/v1/remote.Referrers
// so that it can try multiple authentication methods.
func Referrers(ctx context.Context, d name.Digest, option types.RegistryOptions) (v1.ImageIndex, error) {
	tr, err := httpTransport(option)
	if err != nil {
		return nil, xerrors.Errorf("failed to create http transport: %w", err)
	}

	var errs error
	// Try each authentication method until it succeeds
	for _, authOpt := range authOptions(ctx, d, option) {
		remoteOpts := []remote.Option{
			remote.WithTransport(tr),
			authOpt,
		}
		index, err := remote.Referrers(d, remoteOpts...)
		if err != nil {
			errs = multierror.Append(errs, err)
			continue
		}
		return index, nil
	}

	// No authentication succeeded
	return nil, errs
}

func httpTransport(option types.RegistryOptions) (http.RoundTripper, error) {
	log.Info("Configuring HTTP transport")

	d := &net.Dialer{
		Timeout: 10 * time.Minute,
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = d.DialContext
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: option.Insecure}

	if option.Insecure {
		log.Info("TLS certificate verification disabled (insecure mode)")
	} else {
		log.Info("TLS certificate verification enabled")
	}

	if len(option.ClientCert) != 0 && len(option.ClientKey) != 0 {
		log.Info("Configuring client certificate authentication")
		cert, err := tls.X509KeyPair(option.ClientCert, option.ClientKey)
		if err != nil {
			log.Error("Failed to load client certificate", log.Err(err))
			return nil, err
		}
		tr.TLSClientConfig.Certificates = []tls.Certificate{cert}
		log.Info("Client certificate configured successfully")
	}

	tripper := transport.NewUserAgent(tr, fmt.Sprintf("trivy/%s", app.Version()))
	log.Info("HTTP transport configured successfully", log.String("user_agent", fmt.Sprintf("trivy/%s", app.Version())))
	return tripper, nil
}

func authOptions(ctx context.Context, ref name.Reference, option types.RegistryOptions) []remote.Option {
	domain := ref.Context().RegistryStr()
	log.Info("Configuring authentication options", log.String("domain", domain))

	var opts []remote.Option

	// Add basic auth credentials
	if len(option.Credentials) > 0 {
		log.Info("Adding basic auth credentials", log.Int("count", len(option.Credentials)), log.String("domain", domain))
		for _, cred := range option.Credentials {
			opts = append(opts, remote.WithAuth(&authn.Basic{
				Username: cred.Username,
				Password: cred.Password,
			}))
		}
	} else {
		log.Info("No basic auth credentials provided", log.String("domain", domain))
	}

	// Check for domain-specific token
	token := registry.GetToken(ctx, domain, option)
	if !lo.IsEmpty(token) {
		log.Info("Adding domain-specific token authentication", log.String("domain", domain))
		opts = append(opts, remote.WithAuth(&token))
	} else {
		log.Info("No domain-specific token found", log.String("domain", domain))
	}

	switch {
	case option.RegistryToken != "":
		log.Info("Using registry bearer token authentication", log.String("domain", domain))
		bearer := authn.Bearer{Token: option.RegistryToken}
		return []remote.Option{remote.WithAuth(&bearer)}
	default:
		// Use the keychain anyway at the end
		log.Info("Adding keychain authentication as fallback", log.String("domain", domain))
		opts = append(opts, remote.WithAuthFromKeychain(authn.DefaultKeychain))
		log.Info("Authentication options configured", log.Int("total_options", len(opts)), log.String("domain", domain))
		return opts
	}
}

// resolvePlatform resolves the OS platform for a given image reference.
// If the platform has an empty OS, the function will attempt to find the first OS
// in the image's manifest list and return the platform with the detected OS.
// It ignores the specified platform if the image is not multi-arch.
func resolvePlatform(ref name.Reference, p types.Platform, options []remote.Option) (types.Platform, error) {
	if p.OS != "" {
		return p, nil
	}

	// OS wildcard, implicitly pick up the first os found in the image list.
	// e.g. */amd64
	d, err := remote.Get(ref, options...)
	if err != nil {
		return types.Platform{}, xerrors.Errorf("image get error: %w", err)
	}
	switch d.MediaType {
	case v1types.OCIManifestSchema1, v1types.DockerManifestSchema2:
		// We want an index but the registry has an image, not multi-arch. We just ignore "--platform".
		log.Info("Ignore `--platform` as the image is not multi-arch")
		return types.Platform{}, nil
	case v1types.OCIImageIndex, v1types.DockerManifestList:
		// These are expected.
	}

	index, err := d.ImageIndex()
	if err != nil {
		return types.Platform{}, xerrors.Errorf("image index error: %w", err)
	}

	m, err := index.IndexManifest()
	if err != nil {
		return types.Platform{}, xerrors.Errorf("remote index manifest error: %w", err)
	}
	if len(m.Manifests) == 0 {
		log.Info("Ignore '--platform' as the image is not multi-arch")
		return types.Platform{}, nil
	}
	if m.Manifests[0].Platform != nil {
		newPlatform := p.DeepCopy()
		// Replace with the detected OS
		// e.g. */amd64 => linux/amd64
		newPlatform.OS = m.Manifests[0].Platform.OS

		// Return the platform with the found OS
		return types.Platform{
			Platform: newPlatform,
			Force:    p.Force,
		}, nil
	}
	return types.Platform{}, nil
}

func satisfyPlatform(desc *remote.Descriptor, platform v1.Platform) error {
	img, err := desc.Image()
	if err != nil {
		return err
	}
	c, err := img.ConfigFile()
	if err != nil {
		return err
	}
	if !lo.FromPtr(c.Platform()).Satisfies(platform) {
		return xerrors.Errorf("the specified platform not found")
	}
	return nil
}
