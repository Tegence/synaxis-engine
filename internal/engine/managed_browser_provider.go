package engine

import "context"

// Managed sign-in passes submitted values directly to the provider. Neither
// these status types nor the durable browser flow contain credential values.
type ManagedBrowserField struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Type     string `json:"type"`
	Required bool   `json:"required"`
}

type ManagedBrowserChoice struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type ManagedBrowserStatus struct {
	State            string                 `json:"state"`
	InteractionID    string                 `json:"interactionId,omitempty"`
	Fields           []ManagedBrowserField  `json:"fields,omitempty"`
	Choices          []ManagedBrowserChoice `json:"choices,omitempty"`
	Message          string                 `json:"message,omitempty"`
	BrowserSessionID string                 `json:"-"`
}

type managedBrowserSignInProvider interface {
	browserSignInProvider
	CreateLogin(context.Context, string, string) (string, error)
	BeginLogin(context.Context, string) error
	LoginStatus(context.Context, string) (ManagedBrowserStatus, error)
	SubmitLogin(context.Context, string, string, map[string]string, string) error
	DeleteLogin(context.Context, string) error
}

// Providers with name-addressable resources let callers checkpoint cleanup
// references before the allocation request, including a crash before response.
type namedBrowserResources interface {
	ProfileReference(string) string
	SessionReference(string) string
	CreateNamedSession(context.Context, string, string) (string, string, error)
	CreateNamedRuntimeSession(context.Context, BrowserProfile, string) (string, string, error)
}
