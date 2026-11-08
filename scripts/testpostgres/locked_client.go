package main

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"

	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	tc "github.com/testcontainers/testcontainers-go"
)

type imagePolicy struct{ postgres, ryuk string }

func newImagePolicy(postgres, ryuk string) (imagePolicy, error) {
	if !regexp.MustCompile(`^postgres:[^@\s]+@sha256:[a-f0-9]{64}$`).MatchString(postgres) ||
		!regexp.MustCompile(`^`+regexp.QuoteMeta(tc.ReaperDefaultImage)+`@sha256:[a-f0-9]{64}$`).MatchString(ryuk) {
		return imagePolicy{}, fmt.Errorf("PostgreSQL and matching Ryuk images must be digest locked")
	}
	return imagePolicy{postgres: postgres, ryuk: ryuk}, nil
}

// Testcontainers recognizes its reaper by the default tag internally. Resolve
// that tag only at the Docker API boundary, including cache lookups and pulls.
// Giving Testcontainers a digest directly would bypass its reaper recognition.
type lockedDockerClient struct {
	client.APIClient
	images imagePolicy
}

func (c *lockedDockerClient) image(ref string) (string, error) {
	switch ref {
	case tc.ReaperDefaultImage, c.images.ryuk:
		return c.images.ryuk, nil
	case c.images.postgres:
		return c.images.postgres, nil
	default:
		return "", fmt.Errorf("image is outside the owned test image lock")
	}
}

func (c *lockedDockerClient) ImageInspect(ctx context.Context, ref string, opts ...client.ImageInspectOption) (client.ImageInspectResult, error) {
	image, err := c.image(ref)
	if err != nil {
		return client.ImageInspectResult{}, err
	}
	return c.APIClient.ImageInspect(ctx, image, opts...)
}

func (c *lockedDockerClient) ImagePull(ctx context.Context, ref string, opts client.ImagePullOptions) (client.ImagePullResponse, error) {
	image, err := c.image(ref)
	if err != nil {
		return nil, err
	}
	if opts.All {
		return nil, fmt.Errorf("pulling all image tags is forbidden")
	}
	return c.APIClient.ImagePull(ctx, image, opts)
}

func (c *lockedDockerClient) ContainerCreate(ctx context.Context, opts client.ContainerCreateOptions) (client.ContainerCreateResult, error) {
	if opts.Config == nil || opts.HostConfig == nil || opts.Image != "" {
		return client.ContainerCreateResult{}, fmt.Errorf("owned container configuration is required")
	}
	image, err := c.image(opts.Config.Image)
	if err != nil {
		return client.ContainerCreateResult{}, err
	}
	port := network.MustParsePort("5432/tcp")
	if image == c.images.ryuk {
		port = network.MustParsePort("8080/tcp")
	}
	host := *opts.HostConfig
	if image == c.images.ryuk {
		host.SecurityOpt = append(append([]string(nil), host.SecurityOpt...), "label=disable")
	}
	if host.NetworkMode.IsHost() || host.PublishAllPorts || len(host.PortBindings) != 1 || len(host.PortBindings[port]) != 1 {
		return client.ContainerCreateResult{}, fmt.Errorf("only the owned random loopback port may be published")
	}
	binding := host.PortBindings[port][0]
	if binding.HostPort != "" && binding.HostPort != "0" {
		return client.ContainerCreateResult{}, fmt.Errorf("owned ports must be randomly assigned")
	}
	// Enforce before creation: a post-start inspection cannot undo exposure.
	binding.HostIP = netip.MustParseAddr("127.0.0.1")
	host.PortBindings = network.PortMap{port: {binding}}
	config := *opts.Config
	config.Image = image
	opts.Config, opts.HostConfig = &config, &host
	return c.APIClient.ContainerCreate(ctx, opts)
}
