package main

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	tc "github.com/testcontainers/testcontainers-go"
)

const testPostgres = "postgres:17-test@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const testRyuk = "testcontainers/ryuk:0.14.0@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

type recordedAPI struct {
	client.APIClient
	created           *client.ContainerCreateOptions
	inspected, pulled string
}

func (r *recordedAPI) ContainerCreate(_ context.Context, opts client.ContainerCreateOptions) (client.ContainerCreateResult, error) {
	r.created = &opts
	return client.ContainerCreateResult{}, nil
}
func (r *recordedAPI) ImageInspect(_ context.Context, ref string, _ ...client.ImageInspectOption) (client.ImageInspectResult, error) {
	r.inspected = ref
	return client.ImageInspectResult{}, nil
}
func (r *recordedAPI) ImagePull(_ context.Context, ref string, _ client.ImagePullOptions) (client.ImagePullResponse, error) {
	r.pulled = ref
	return nil, nil
}

func ownedCreate(image, port string, address netip.Addr) client.ContainerCreateOptions {
	return client.ContainerCreateOptions{
		Config: &container.Config{Image: image},
		HostConfig: &container.HostConfig{PortBindings: network.PortMap{
			network.MustParsePort(port): {{HostIP: address, HostPort: "0"}},
		}},
	}
}

func TestPublishedPortsAreLoopbackBeforeDockerCreate(t *testing.T) {
	for _, host := range []string{"", "0.0.0.0", "::", "::1", "127.0.0.1"} {
		t.Run(host, func(t *testing.T) {
			var address netip.Addr
			if host != "" {
				address = netip.MustParseAddr(host)
			}
			for _, service := range []struct{ image, port, pinned string }{
				{tc.ReaperDefaultImage, "8080/tcp", testRyuk},
				{testPostgres, "5432/tcp", testPostgres},
			} {
				api := &recordedAPI{}
				locked := &lockedDockerClient{APIClient: api, images: imagePolicy{testPostgres, testRyuk}}
				_, err := locked.ContainerCreate(context.Background(), ownedCreate(service.image, service.port, address))
				if err != nil {
					t.Fatal(err)
				}
				binding := api.created.HostConfig.PortBindings[network.MustParsePort(service.port)][0]
				if binding.HostIP != netip.MustParseAddr("127.0.0.1") || binding.HostPort != "0" {
					t.Fatal("Docker received an unsafe or fixed port")
				}
				if api.created.Config.Image != service.pinned {
					t.Fatal("Docker received an unlocked image")
				}
			}
		})
	}
}

func TestRyukCacheLookupAndPullUseLockedDigest(t *testing.T) {
	api := &recordedAPI{}
	locked := &lockedDockerClient{APIClient: api, images: imagePolicy{testPostgres, testRyuk}}
	if _, err := locked.ImageInspect(context.Background(), tc.ReaperDefaultImage); err != nil {
		t.Fatal(err)
	}
	if _, err := locked.ImagePull(context.Background(), tc.ReaperDefaultImage, client.ImagePullOptions{}); err != nil {
		t.Fatal(err)
	}
	if api.inspected != testRyuk || api.pulled != testRyuk {
		t.Fatal("cache lookup or pull used a mutable tag")
	}
}

func TestSELinuxExceptionAppliesOnlyToRyuk(t *testing.T) {
	for _, service := range []struct {
		name, image, port string
		securityOptions   []string
	}{
		{"ryuk-tag", tc.ReaperDefaultImage, "8080/tcp", []string{"no-new-privileges", "label=disable"}},
		{"ryuk-digest", testRyuk, "8080/tcp", []string{"no-new-privileges", "label=disable"}},
		{"postgres", testPostgres, "5432/tcp", []string{"no-new-privileges"}},
	} {
		t.Run(service.name, func(t *testing.T) {
			api := &recordedAPI{}
			locked := &lockedDockerClient{APIClient: api, images: imagePolicy{testPostgres, testRyuk}}
			opts := ownedCreate(service.image, service.port, netip.Addr{})
			opts.HostConfig.SecurityOpt = []string{"no-new-privileges"}
			if _, err := locked.ContainerCreate(context.Background(), opts); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(api.created.HostConfig.SecurityOpt, service.securityOptions) {
				t.Fatalf("Docker security options = %v, want %v", api.created.HostConfig.SecurityOpt, service.securityOptions)
			}
			if api.created.HostConfig.Privileged {
				t.Fatal("SELinux exception must not enable privileged mode")
			}
			if !slices.Equal(opts.HostConfig.SecurityOpt, []string{"no-new-privileges"}) {
				t.Fatal("caller security options were modified")
			}
		})
	}
}

func TestUnapprovedImagesNeverReachDocker(t *testing.T) {
	for _, image := range []string{"postgres:17-test", "testcontainers/ryuk:latest", "docker.io/" + tc.ReaperDefaultImage, strings.Replace(testRyuk, ":0.14.0", ":0.13.0", 1)} {
		t.Run(image, func(t *testing.T) {
			api := &recordedAPI{}
			locked := &lockedDockerClient{APIClient: api, images: imagePolicy{testPostgres, testRyuk}}
			if _, err := locked.ImageInspect(context.Background(), image); err == nil {
				t.Fatal("unapproved image lookup accepted")
			}
			if _, err := locked.ImagePull(context.Background(), image, client.ImagePullOptions{}); err == nil {
				t.Fatal("unapproved image pull accepted")
			}
			if _, err := locked.ContainerCreate(context.Background(), ownedCreate(image, "8080/tcp", netip.Addr{})); err == nil {
				t.Fatal("unapproved image creation accepted")
			}
			if api.created != nil || api.inspected != "" || api.pulled != "" {
				t.Fatal("unapproved image reached Docker")
			}
		})
	}
}

func TestAlternatePublicationModesAreRejected(t *testing.T) {
	for _, mode := range []string{"host-network", "all-ports", "fixed-port", "extra-port", "all-tags", "image-option"} {
		t.Run(mode, func(t *testing.T) {
			api := &recordedAPI{}
			locked := &lockedDockerClient{APIClient: api, images: imagePolicy{testPostgres, testRyuk}}
			opts := ownedCreate(tc.ReaperDefaultImage, "8080/tcp", netip.Addr{})
			switch mode {
			case "host-network":
				opts.HostConfig.NetworkMode = "host"
			case "all-ports":
				opts.HostConfig.PublishAllPorts = true
			case "fixed-port":
				opts.HostConfig.PortBindings[network.MustParsePort("8080/tcp")][0].HostPort = "8080"
			case "extra-port":
				opts.HostConfig.PortBindings[network.MustParsePort("9090/tcp")] = []network.PortBinding{{}}
			case "image-option":
				opts.Image = tc.ReaperDefaultImage
			case "all-tags":
				if _, err := locked.ImagePull(context.Background(), tc.ReaperDefaultImage, client.ImagePullOptions{All: true}); err == nil {
					t.Fatal("all-tags pull accepted")
				}
				if api.pulled != "" {
					t.Fatal("all-tags pull reached Docker")
				}
				return
			}
			if _, err := locked.ContainerCreate(context.Background(), opts); err == nil {
				t.Fatal("alternate publication accepted")
			}
			if api.created != nil {
				t.Fatal("unsafe publication reached Docker")
			}
		})
	}
}

func TestImagePolicyRequiresMatchingDigestLocks(t *testing.T) {
	if _, err := newImagePolicy(testPostgres, testRyuk); err != nil {
		t.Fatal(err)
	}
	for _, image := range []string{"", tc.ReaperDefaultImage, strings.Replace(testRyuk, ":0.14.0", ":0.13.0", 1)} {
		if _, err := newImagePolicy(testPostgres, image); err == nil {
			t.Fatal("missing, mutable or mismatched Ryuk lock accepted")
		}
	}
}
