package image

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	multierror "github.com/hashicorp/go-multierror"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

type imageSourceFunc func(ctx context.Context, imageName string, ref name.Reference, option types.ImageOptions) (types.Image, func(), error)

var imageSourceFuncs = map[types.ImageSource]imageSourceFunc{
	types.ContainerdImageSource: tryContainerdDaemon,
	types.PodmanImageSource:     tryPodmanDaemon,
	types.DockerImageSource:     tryDockerDaemon,
	types.RemoteImageSource:     tryRemote,
}

func NewContainerImage(ctx context.Context, imageName string, opt types.ImageOptions) (types.Image, func(), error) {
	log.Info("Creating new container image", log.String("image", imageName), log.Any("sources", opt.ImageSources))

	if len(opt.ImageSources) == 0 {
		log.Error("No image sources provided", log.String("image", imageName))
		return nil, func() {}, xerrors.New("no image sources supplied")
	}

	var errs error
	var nameOpts []name.Option
	if opt.RegistryOptions.Insecure {
		nameOpts = append(nameOpts, name.Insecure)
		log.Info("Using insecure registry option", log.String("image", imageName))
	}

	log.Info("Parsing image reference", log.String("image", imageName))
	ref, err := name.ParseReference(imageName, nameOpts...)
	if err != nil {
		log.Error("Failed to parse image name", log.String("image", imageName), log.Err(err))
		return nil, func() {}, xerrors.Errorf("failed to parse the image name: %w", err)
	}
	log.Info("Successfully parsed image reference", log.String("image", imageName), log.String("reference", ref.String()))

	for _, src := range opt.ImageSources {
		log.Info("Trying image source", log.String("image", imageName), log.String("source", string(src)))

		trySrc, ok := imageSourceFuncs[src]
		if !ok {
			log.Warn("Unknown image source", log.String("image", imageName), log.String("source", string(src)))
			continue
		}

		img, cleanup, err := trySrc(ctx, imageName, ref, opt)
		if err == nil {
			log.Info("Successfully loaded image", log.String("image", imageName), log.String("source", string(src)))
			// Return v1.Image if the image is found
			return img, cleanup, nil
		}
		log.Debug("Failed to load image from source", log.String("image", imageName), log.String("source", string(src)), log.Err(err))

		err = multierror.Prefix(err, fmt.Sprintf("%s error:", src))
		errs = multierror.Append(errs, err)
	}

	log.Error("Unable to find image in any source", log.String("image", imageName), log.Any("sources", opt.ImageSources), log.Err(errs))
	return nil, func() {}, xerrors.Errorf("unable to find the specified image %q in %q: %w", imageName, opt.ImageSources, errs)
}

func ID(img v1.Image) (string, error) {
	h, err := img.ConfigName()
	if err != nil {
		return "", xerrors.Errorf("unable to get the image ID: %w", err)
	}
	return h.String(), nil
}

func LayerIDs(img v1.Image) ([]string, error) {
	conf, err := img.ConfigFile()
	if err != nil {
		return nil, xerrors.Errorf("unable to get the config file: %w", err)
	}

	var layerIDs []string
	for _, d := range conf.RootFS.DiffIDs {
		layerIDs = append(layerIDs, d.String())
	}
	return layerIDs, nil
}

// GuessBaseImageIndex tries to guess index of base layer
//
// e.g. In the following example, we should detect layers in debian:8.
//
//	FROM debian:8
//	RUN apt-get update
//	COPY mysecret /
//	ENTRYPOINT ["entrypoint.sh"]
//	CMD ["somecmd"]
//
// debian:8 may be like
//
//	ADD file:5d673d25da3a14ce1f6cf66e4c7fd4f4b85a3759a9d93efb3fd9ff852b5b56e4 in /
//	CMD ["/bin/sh"]
//
// In total, it would be like:
//
//	ADD file:5d673d25da3a14ce1f6cf66e4c7fd4f4b85a3759a9d93efb3fd9ff852b5b56e4 in /
//	CMD ["/bin/sh"]              # empty layer (detected)
//	RUN apt-get update
//	COPY mysecret /
//	ENTRYPOINT ["entrypoint.sh"] # empty layer (skipped)
//	CMD ["somecmd"]              # empty layer (skipped)
//
// This method tries to detect CMD in the second line and assume the first line is a base layer.
//  1. Iterate histories from the bottom.
//  2. Skip all the empty layers at the bottom. In the above example, "entrypoint.sh" and "somecmd" will be skipped
//  3. If it finds CMD, it assumes that it is the end of base layers.
//  4. It gets all the layers as base layers above the CMD found in #3.
func GuessBaseImageIndex(histories []v1.History) int {
	baseImageIndex := -1
	var foundNonEmpty bool
	for i := len(histories) - 1; i >= 0; i-- {
		h := histories[i]

		// Skip the last CMD, ENTRYPOINT, etc.
		if !foundNonEmpty {
			if h.EmptyLayer {
				continue
			}
			foundNonEmpty = true
		}

		if !h.EmptyLayer {
			continue
		}

		// Detect CMD instruction in base image
		if strings.HasPrefix(h.CreatedBy, "/bin/sh -c #(nop)  CMD") ||
			strings.HasPrefix(h.CreatedBy, "CMD") { // BuildKit
			baseImageIndex = i
			break
		}
	}
	return baseImageIndex
}
