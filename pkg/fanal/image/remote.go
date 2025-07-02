package image

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/remote"
)

func tryRemote(ctx context.Context, imageName string, ref name.Reference, option types.ImageOptions) (types.Image, func(), error) {
	log.Info("Attempting to fetch remote image", log.String("image", imageName), log.String("reference", ref.String()))

	// This function doesn't need cleanup
	cleanup := func() {}

	desc, err := remote.Get(ctx, ref, option.RegistryOptions)
	if err != nil {
		log.Info("Failed to get remote image descriptor", log.String("image", imageName), log.String("reference", ref.String()), log.Err(err))
		return nil, cleanup, err
	}
	log.Info("Successfully retrieved remote image descriptor", log.String("image", imageName), log.String("reference", ref.String()))

	log.Info("Converting descriptor to image", log.String("image", imageName), log.String("reference", ref.String()), log.String("mediaType", string(desc.MediaType)), log.String("digest", desc.Digest.String()))
	img, err := desc.Image()
	if err != nil {
		log.Info("Failed to get image from descriptor", log.String("image", imageName), log.String("reference", ref.String()), log.Err(err))
		return nil, cleanup, err
	}
	log.Info("Successfully converted descriptor to image", log.String("image", imageName), log.String("reference", ref.String()))

	log.Info("Successfully loaded remote image", log.String("image", imageName), log.String("reference", ref.String()))

	// Return v1.Image if the image is found in Docker Registry
	return remoteImage{
		name:       imageName,
		Image:      img,
		ref:        implicitReference{ref: ref},
		descriptor: desc,
	}, cleanup, nil

}

type remoteImage struct {
	name       string
	ref        implicitReference
	descriptor *remote.Descriptor
	v1.Image
}

func (img remoteImage) Name() string {
	return img.name
}

func (img remoteImage) ID() (string, error) {
	return ID(img)
}

func (img remoteImage) RepoTags() []string {
	tag := img.ref.TagName()
	if tag == "" {
		return []string{}
	}
	return []string{fmt.Sprintf("%s:%s", img.ref.RepositoryName(), tag)}
}

func (img remoteImage) RepoDigests() []string {
	repoDigest := fmt.Sprintf("%s@%s", img.ref.RepositoryName(), img.descriptor.Digest.String())
	return []string{repoDigest}
}

type implicitReference struct {
	ref name.Reference
}

func (r implicitReference) TagName() string {
	if t, ok := r.ref.(name.Tag); ok {
		return t.TagStr()
	}
	return ""
}

func (r implicitReference) RepositoryName() string {
	ctx := r.ref.Context()
	reg := ctx.RegistryStr()
	repo := ctx.RepositoryStr()

	// Default registry
	if reg != name.DefaultRegistry {
		return fmt.Sprintf("%s/%s", reg, repo)
	}

	// Trim default namespace
	// See https://docs.docker.com/docker-hub/official_repos
	return strings.TrimPrefix(repo, "library/")
}
