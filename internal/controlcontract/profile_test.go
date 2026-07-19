package controlcontract

import (
	"strings"
	"testing"
)

func TestProfileValidateAcceptsClientIKEv2Profile(t *testing.T) {
	profile := Profile{
		SchemaVersion: SchemaVersionV1,
		Kind:          BundleKindClient,
		Client: &ClientProfile{
			ID:          "client-profile-1",
			PrincipalID: "device-1",
			Transport:   TransportIKEv2,
			POPs: []PopReference{
				{ID: "pop-a", Endpoint: "198.51.100.10:500"},
			},
			MITM: &MITMProfile{
				AllowedDomainSuffixes: []string{"example.com"},
				RequireConsent:        true,
				BlockQUIC:             true,
				BlockPinnedTLS:        true,
				MetadataRetentionDays: RequiredMetadataRetentionDays,
			},
		},
	}

	if err := profile.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestProfileValidateAcceptsFailClosedPopServiceChain(t *testing.T) {
	profile := Profile{
		SchemaVersion: SchemaVersionV1,
		Kind:          BundleKindPop,
		Pop: &PopProfile{
			ID:          "pop-profile-a",
			PrincipalID: "pop-a",
			Routes: []RoutePolicy{
				{
					ID: "route-enterprise-tcp",
					Selector: RouteSelector{
						SourceCIDR:      "10.10.0.0/16",
						DestinationCIDR: "203.0.113.0/24",
						Protocol:        ProtocolTCP,
						Ports:           &PortRange{Start: 443, End: 443},
					},
					Chain: ServiceChain{
						ID:   "a-b-c-d",
						Hops: []string{"pop-b", "pop-c", "pop-d"},
					},
				},
			},
		},
	}

	if err := profile.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestProfileValidateRejectsInvalidProfileInputs(t *testing.T) {
	tests := []struct {
		name    string
		profile Profile
		wantErr string
	}{
		{
			name: "both payloads",
			profile: Profile{
				SchemaVersion: SchemaVersionV1,
				Kind:          BundleKindClient,
				Client:        validClientProfile(),
				Pop:           validPopProfile(),
			},
			wantErr: "only client payload",
		},
		{
			name: "unsupported client transport",
			profile: Profile{
				SchemaVersion: SchemaVersionV1,
				Kind:          BundleKindClient,
				Client: &ClientProfile{
					ID:          "client-profile-1",
					PrincipalID: "device-1",
					Transport:   Transport("wireguard"),
					POPs:        []PopReference{{ID: "pop-a", Endpoint: "198.51.100.10:500"}},
				},
			},
			wantErr: "unsupported client transport",
		},
		{
			name: "invalid pop endpoint",
			profile: Profile{
				SchemaVersion: SchemaVersionV1,
				Kind:          BundleKindClient,
				Client: &ClientProfile{
					ID:          "client-profile-1",
					PrincipalID: "device-1",
					Transport:   TransportIKEv2,
					POPs:        []PopReference{{ID: "pop-a", Endpoint: "not-an-endpoint"}},
				},
			},
			wantErr: "invalid endpoint",
		},
		{
			name: "mitm missing allowlist",
			profile: Profile{
				SchemaVersion: SchemaVersionV1,
				Kind:          BundleKindClient,
				Client: &ClientProfile{
					ID:          "client-profile-1",
					PrincipalID: "device-1",
					Transport:   TransportIKEv2,
					POPs:        []PopReference{{ID: "pop-a", Endpoint: "198.51.100.10:500"}},
					MITM: &MITMProfile{
						RequireConsent:        true,
						BlockQUIC:             true,
						BlockPinnedTLS:        true,
						MetadataRetentionDays: RequiredMetadataRetentionDays,
					},
				},
			},
			wantErr: "allowlisted domain",
		},
		{
			name: "mitm allows selected quic",
			profile: Profile{
				SchemaVersion: SchemaVersionV1,
				Kind:          BundleKindClient,
				Client: &ClientProfile{
					ID:          "client-profile-1",
					PrincipalID: "device-1",
					Transport:   TransportIKEv2,
					POPs:        []PopReference{{ID: "pop-a", Endpoint: "198.51.100.10:500"}},
					MITM: &MITMProfile{
						AllowedDomainSuffixes: []string{"example.com"},
						RequireConsent:        true,
						BlockPinnedTLS:        true,
						MetadataRetentionDays: RequiredMetadataRetentionDays,
					},
				},
			},
			wantErr: "must block QUIC",
		},
		{
			name: "mitm metadata retention differs from policy",
			profile: Profile{
				SchemaVersion: SchemaVersionV1,
				Kind:          BundleKindClient,
				Client: &ClientProfile{
					ID:          "client-profile-1",
					PrincipalID: "device-1",
					Transport:   TransportIKEv2,
					POPs:        []PopReference{{ID: "pop-a", Endpoint: "198.51.100.10:500"}},
					MITM: &MITMProfile{
						AllowedDomainSuffixes: []string{"example.com"},
						RequireConsent:        true,
						BlockQUIC:             true,
						BlockPinnedTLS:        true,
						MetadataRetentionDays: RequiredMetadataRetentionDays - 1,
					},
				},
			},
			wantErr: "metadata retention",
		},
		{
			name: "direct fallback",
			profile: Profile{
				SchemaVersion: SchemaVersionV1,
				Kind:          BundleKindPop,
				Pop: &PopProfile{
					ID:          "pop-profile-a",
					PrincipalID: "pop-a",
					Routes: []RoutePolicy{
						{
							ID:             "route-1",
							Selector:       RouteSelector{DestinationCIDR: "203.0.113.0/24"},
							Chain:          ServiceChain{ID: "a-b", Hops: []string{"pop-b"}},
							DirectFallback: true,
						},
					},
				},
			},
			wantErr: "direct fallback",
		},
		{
			name: "empty service chain",
			profile: Profile{
				SchemaVersion: SchemaVersionV1,
				Kind:          BundleKindPop,
				Pop: &PopProfile{
					ID:          "pop-profile-a",
					PrincipalID: "pop-a",
					Routes: []RoutePolicy{
						{
							ID:       "route-1",
							Selector: RouteSelector{DestinationCIDR: "203.0.113.0/24"},
							Chain:    ServiceChain{ID: "a-b"},
						},
					},
				},
			},
			wantErr: "at least one hop",
		},
		{
			name: "invalid selector cidr",
			profile: Profile{
				SchemaVersion: SchemaVersionV1,
				Kind:          BundleKindPop,
				Pop: &PopProfile{
					ID:          "pop-profile-a",
					PrincipalID: "pop-a",
					Routes: []RoutePolicy{
						{
							ID:       "route-1",
							Selector: RouteSelector{SourceCIDR: "not-a-cidr"},
							Chain:    ServiceChain{ID: "a-b", Hops: []string{"pop-b"}},
						},
					},
				},
			},
			wantErr: "invalid source CIDR",
		},
		{
			name: "ports without protocol",
			profile: Profile{
				SchemaVersion: SchemaVersionV1,
				Kind:          BundleKindPop,
				Pop: &PopProfile{
					ID:          "pop-profile-a",
					PrincipalID: "pop-a",
					Routes: []RoutePolicy{
						{
							ID:       "route-1",
							Selector: RouteSelector{DestinationCIDR: "203.0.113.0/24", Ports: &PortRange{Start: 443, End: 443}},
							Chain:    ServiceChain{ID: "a-b", Hops: []string{"pop-b"}},
						},
					},
				},
			},
			wantErr: "ports require TCP or UDP",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.profile.Validate()
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func validClientProfile() *ClientProfile {
	return &ClientProfile{
		ID:          "client-profile-1",
		PrincipalID: "device-1",
		Transport:   TransportIKEv2,
		POPs:        []PopReference{{ID: "pop-a", Endpoint: "198.51.100.10:500"}},
	}
}

func validPopProfile() *PopProfile {
	return &PopProfile{
		ID:          "pop-profile-a",
		PrincipalID: "pop-a",
		Routes: []RoutePolicy{
			{
				ID:       "route-1",
				Selector: RouteSelector{DestinationCIDR: "203.0.113.0/24"},
				Chain:    ServiceChain{ID: "a-b", Hops: []string{"pop-b"}},
			},
		},
	}
}
