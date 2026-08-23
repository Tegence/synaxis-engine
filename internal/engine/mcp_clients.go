package engine

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// MCPClient is a named, subject-bound AI client registration. It deliberately
// contains no bearer credential: the OAuth/MCP delivery layer binds an
// OAuth client ID and issues resource-bound tokens separately. The durable
// Epoch changes whenever authorization-relevant state changes so that layer
// can reject a token minted before a namespace grant changed or a client was
// revoked.
//
// Slug is the stable, human-safe endpoint identifier for a scoped MCP surface
// (for example, /mcp/clients/<slug>). It is distinct from ID, which is
// opaque and remains the authority key for management requests.
type MCPClient struct {
	ID            string `json:"id"`
	Slug          string `json:"slug"`
	Name          string `json:"name"`
	Subject       string `json:"subject"`
	OAuthClientID string `json:"oauth_client_id,omitempty"`
	// RuntimeAttestorPublicKey is an optional, canonical raw-base64url
	// Ed25519 public key. It authorizes only the separate host-attestation
	// endpoint; it is neither an OAuth credential nor an MCP bearer token.
	RuntimeAttestorPublicKey string          `json:"runtime_attestor_public_key,omitempty"`
	ConnectionNamespaceIDs   []string        `json:"connection_namespace_ids"`
	Status                   MCPClientStatus `json:"status"`
	Epoch                    string          `json:"epoch"`
	Revision                 int64           `json:"revision"`
	CreatedBy                string          `json:"created_by,omitempty"`
	CreatedAt                time.Time       `json:"created_at,omitempty"`
	UpdatedAt                time.Time       `json:"updated_at,omitempty"`
	RevokedAt                *time.Time      `json:"revoked_at,omitempty"`
	RevokedBy                string          `json:"revoked_by,omitempty"`
	// runtimeAttestorKeySet is an update-only presence bit. It is intentionally
	// not persisted, so an empty public key can explicitly disable attestation.
	runtimeAttestorKeySet bool `json:"-"`
}

type MCPClientStatus string

const (
	MCPClientStatusActive  MCPClientStatus = "active"
	MCPClientStatusRevoked MCPClientStatus = "revoked"

	// These caps bound live Engine lookup/list work without turning a revoked
	// client history into a permanent workspace lifetime cap. A future archive
	// job can compact revoked records independently of live authorization.
	maxActiveMCPClients         = 256
	maxMCPClientNamespaceGrants = 64
	maxMCPClientNameRunes       = 120
	maxMCPClientSlugBytes       = 96
	// oauthas permits DCR client IDs up to 1024 bytes. Keep the registry
	// compatible with that upper bound; a shorter limit would make a valid
	// OAuth registration impossible to bind after consent.
	maxMCPClientOAuthClientIDBytes = 1024
)

// MCPClientPrecondition is the optimistic-concurrency identity for every
// mutable client record. IDs are never reused, so ID+revision is sufficient
// to prevent a stale browser operation from undoing a revocation or grant
// update.
type MCPClientPrecondition struct {
	ID       string `json:"id"`
	Revision int64  `json:"revision"`
}

// MCPClientStore is a deliberately small registry facet. Gateway/Main uses
// ActiveMCPClient and ActiveMCPClientByOAuthClientID to resolve a scoped
// endpoint and its Platform subject without learning console authorization
// details. Console mutations remain CAS-protected below.
//
// This interface does not issue tokens or install an MCP route. It is the
// durable control-plane policy consumed by those delivery pieces.
type MCPClientStore interface {
	MCPClients(ctx context.Context) ([]MCPClient, error)
	ActiveMCPClients(ctx context.Context) ([]MCPClient, error)
	MCPClient(ctx context.Context, id string) (MCPClient, bool)
	MCPClientBySlug(ctx context.Context, slug string) (MCPClient, bool)
	// ActiveMCPClient resolves either the opaque registration ID or its stable
	// endpoint slug and fails closed for revoked records.
	ActiveMCPClient(ctx context.Context, endpointIdentifier string) (MCPClient, bool)
	ActiveMCPClientByOAuthClientID(ctx context.Context, oauthClientID string) (MCPClient, bool)
	CreateMCPClient(ctx context.Context, client MCPClient) (MCPClient, error)
	UpdateMCPClient(ctx context.Context, update MCPClient, precondition MCPClientPrecondition) (MCPClient, error)
	SetMCPClientNamespaces(ctx context.Context, id string, namespaceIDs []string, precondition MCPClientPrecondition) (MCPClient, error)
	// BindMCPClientOAuthClient atomically associates a public OAuth client ID
	// with this subject-bound registration. Replacing a DCR identity requires
	// an explicit reset first; there is never an implicit rebind.
	BindMCPClientOAuthClient(ctx context.Context, id, oauthClientID string, precondition MCPClientPrecondition, actor PlatformActor) (MCPClient, error)
	// ResetMCPClientOAuthClient clears a stale DCR identity but keeps the
	// stable endpoint slug and namespace grants. It always rotates Epoch so
	// previously issued path tokens fail closed before a later explicit bind.
	ResetMCPClientOAuthClient(ctx context.Context, id string, precondition MCPClientPrecondition) (MCPClient, error)
	RevokeMCPClient(ctx context.Context, id, revokedBy string, precondition MCPClientPrecondition) (MCPClient, error)
}

var (
	ErrMCPClientExists           = errors.New("MCP client already exists")
	ErrMCPClientNotFound         = errors.New("MCP client not found")
	ErrMCPClientRevision         = errors.New("MCP client revision conflict")
	ErrMCPClientRevoked          = errors.New("MCP client is revoked")
	ErrMCPClientOAuthBinding     = errors.New("OAuth client ID is already bound")
	ErrMCPClientLimit            = errors.New("active MCP client limit reached")
	ErrMCPClientNamespaceLimit   = errors.New("MCP client namespace grant limit reached")
	ErrMCPClientNamespaceSubject = errors.New("MCP client subject cannot access a personal connection in this namespace")
	ErrInvalidMCPClient          = errors.New("invalid MCP client")
)

func newMCPClientID() string { return "mcpcli_" + newEpoch() }

func copyMCPClient(client MCPClient) MCPClient {
	cp := client
	cp.ConnectionNamespaceIDs = append([]string(nil), client.ConnectionNamespaceIDs...)
	if client.RevokedAt != nil {
		revokedAt := *client.RevokedAt
		cp.RevokedAt = &revokedAt
	}
	return cp
}

func copyMCPClients(in []*MCPClient) []*MCPClient {
	out := make([]*MCPClient, len(in))
	for i, client := range in {
		if client == nil {
			continue
		}
		copy := copyMCPClient(*client)
		out[i] = &copy
	}
	return out
}

func normalizeMCPClientNamespaceIDs(namespaceIDs []string) ([]string, error) {
	seen := make(map[string]struct{}, len(namespaceIDs))
	for _, namespaceID := range namespaceIDs {
		namespaceID = strings.TrimSpace(namespaceID)
		if namespaceID == "" {
			continue
		}
		seen[namespaceID] = struct{}{}
	}
	if len(seen) > maxMCPClientNamespaceGrants {
		return nil, ErrMCPClientNamespaceLimit
	}
	out := make([]string, 0, len(seen))
	for namespaceID := range seen {
		out = append(out, namespaceID)
	}
	sort.Strings(out)
	return out, nil
}

func normalizeMCPClientSlug(value string) string {
	return normalizeConnectionNamespaceSlug(value)
}

func validMCPClientOAuthClientID(value string) bool {
	if len(value) == 0 || len(value) > maxMCPClientOAuthClientIDBytes || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func normalizeMCPClientRuntimeAttestorPublicKey(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if strings.TrimSpace(value) != value {
		return "", fmt.Errorf("%w: runtime attestor public key is invalid", ErrInvalidMCPClient)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return "", fmt.Errorf("%w: runtime attestor public key is invalid", ErrInvalidMCPClient)
	}
	return value, nil
}

func mcpClientRuntimeAttestorPublicKey(value string) (ed25519.PublicKey, bool) {
	normalized, err := normalizeMCPClientRuntimeAttestorPublicKey(value)
	if err != nil || normalized == "" {
		return nil, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(normalized)
	if err != nil {
		return nil, false
	}
	return ed25519.PublicKey(decoded), true
}

func validateMCPClientName(value string) error {
	if value == "" || utf8.RuneCountInString(value) > maxMCPClientNameRunes {
		return fmt.Errorf("%w: name is required and must be at most %d characters", ErrInvalidMCPClient, maxMCPClientNameRunes)
	}
	return nil
}

func validateMCPClientSubject(value string) error {
	if !validActorIdentifier(value) || value == platformServiceActorID {
		return fmt.Errorf("%w: subject is invalid", ErrInvalidMCPClient)
	}
	return nil
}

func normalizeMCPClientStatus(status MCPClientStatus) (MCPClientStatus, error) {
	switch MCPClientStatus(strings.ToLower(strings.TrimSpace(string(status)))) {
	case "", MCPClientStatusActive:
		return MCPClientStatusActive, nil
	case MCPClientStatusRevoked:
		return MCPClientStatusRevoked, nil
	default:
		return "", fmt.Errorf("%w: status is invalid", ErrInvalidMCPClient)
	}
}

func mcpClientPreconditionMatches(client MCPClient, precondition MCPClientPrecondition) bool {
	return precondition.ID != "" && precondition.ID == client.ID && precondition.Revision >= 1 && precondition.Revision == client.Revision
}

// mcpClientDeliversAccount reports whether a client registration is eligible
// to receive an account in its scoped MCP endpoint. It intentionally models
// the durable delivery boundary rather than the live tool cache: a change in
// this result can add or remove every cached tool for the account, and must
// therefore invalidate tokens minted for the previous endpoint generation.
//
// Keep this predicate aligned with Gateway.buildMCPClient and
// Gateway.mcpClientMayUseAccount. Having it at the store layer lets an account
// move atomically rotate the affected client epochs before another Engine
// replica can project the new namespace assignment.
func mcpClientDeliversAccount(client MCPClient, account Account) bool {
	if client.Status != MCPClientStatusActive || account.ConnectionNamespaceID == "" {
		return false
	}
	if !toSet(client.ConnectionNamespaceIDs)[account.ConnectionNamespaceID] {
		return false
	}
	return !account.IsPersonal() || client.Subject == account.OwnerSubject
}

func mcpClientDeliveryChangesForAccountMove(client MCPClient, before, after Account) bool {
	return mcpClientDeliversAccount(client, before) != mcpClientDeliversAccount(client, after)
}

// accountOwnershipChanged reports whether a whole-account write changed the
// durable boundary that decides which scoped MCP clients receive the account.
// Group is intentionally absent: it is a display alias, while the namespace
// ID, scope, and personal owner are the authorization facts. Keeping this
// predicate shared by explicit moves and compatibility writes ensures a
// legacy group-only Upsert cannot sidestep scoped-client epoch rotation.
func accountOwnershipChanged(before, after Account) bool {
	return before.ConnectionNamespaceID != after.ConnectionNamespaceID ||
		before.ConnectionScope != after.ConnectionScope ||
		before.OwnerSubject != after.OwnerSubject
}

// MCPClientAllowsActor is the narrow runtime predicate for the future
// subject-bound client endpoint. A registration is never a workspace-wide
// bearer capability: a signed Platform actor must be the same subject and be
// a connection-capable member. Shared/root delivery remains a separate
// owner/admin-only decision in Gateway/OAuth wiring.
func MCPClientAllowsActor(client MCPClient, actor PlatformActor) bool {
	if client.Status != MCPClientStatusActive || actor.UserID == "" || actor.UserID != client.Subject {
		return false
	}
	switch actor.Role {
	case "owner", "admin", "operator":
		return true
	default:
		return false
	}
}

func prepareMCPClientForCreate(client *MCPClient) error {
	now := time.Now().UTC()
	client.ID = strings.TrimSpace(client.ID)
	if client.ID == "" {
		client.ID = newMCPClientID()
	}
	client.Name = strings.TrimSpace(client.Name)
	if err := validateMCPClientName(client.Name); err != nil {
		return err
	}
	client.Slug = normalizeMCPClientSlug(client.Slug)
	if client.Slug == "" {
		client.Slug = normalizeMCPClientSlug(client.Name)
	}
	if client.Slug == "" {
		client.Slug = "client"
	}
	if len(client.Slug) > maxMCPClientSlugBytes {
		return fmt.Errorf("%w: slug is too long", ErrInvalidMCPClient)
	}
	client.Subject = strings.TrimSpace(client.Subject)
	if err := validateMCPClientSubject(client.Subject); err != nil {
		return err
	}
	var keyErr error
	client.RuntimeAttestorPublicKey, keyErr = normalizeMCPClientRuntimeAttestorPublicKey(client.RuntimeAttestorPublicKey)
	if keyErr != nil {
		return keyErr
	}
	client.CreatedBy = strings.TrimSpace(client.CreatedBy)
	if client.CreatedBy != "" && !validActorIdentifier(client.CreatedBy) {
		return fmt.Errorf("%w: creator is invalid", ErrInvalidMCPClient)
	}
	client.OAuthClientID = strings.TrimSpace(client.OAuthClientID)
	if client.OAuthClientID != "" {
		// A caller cannot smuggle a DCR identity into registration. The first
		// OAuth bind must pass through BindMCPClientOAuthClient with the signed
		// subject actor, after the registry record exists.
		return fmt.Errorf("%w: OAuth client ID must be bound explicitly", ErrInvalidMCPClient)
	}
	status, err := normalizeMCPClientStatus(client.Status)
	if err != nil || status != MCPClientStatusActive {
		return fmt.Errorf("%w: new clients must be active", ErrInvalidMCPClient)
	}
	client.Status = MCPClientStatusActive
	var namespaceErr error
	client.ConnectionNamespaceIDs, namespaceErr = normalizeMCPClientNamespaceIDs(client.ConnectionNamespaceIDs)
	if namespaceErr != nil {
		return namespaceErr
	}
	// Callers never choose a credential generation or CAS version.
	client.Epoch = newEpoch()
	client.Revision = 1
	client.RevokedAt = nil
	client.RevokedBy = ""
	if client.CreatedAt.IsZero() {
		client.CreatedAt = now
	}
	client.UpdatedAt = client.CreatedAt
	return nil
}

func prepareLoadedMCPClient(client *MCPClient, existingIDs, existingSlugs, existingOAuth map[string]struct{}, namespaceSafeForSubject func(string, string) bool) (changed bool, err error) {
	if client == nil {
		return false, fmt.Errorf("%w: empty stored record", ErrInvalidMCPClient)
	}
	before := copyMCPClient(*client)
	client.ID = strings.TrimSpace(client.ID)
	if client.ID == "" {
		client.ID = newMCPClientID()
	}
	if _, used := existingIDs[client.ID]; used {
		return false, fmt.Errorf("%w: duplicate stored ID", ErrMCPClientExists)
	}
	client.Name = strings.TrimSpace(client.Name)
	if err := validateMCPClientName(client.Name); err != nil {
		return false, err
	}
	client.Slug = normalizeMCPClientSlug(client.Slug)
	if client.Slug == "" {
		client.Slug = normalizeMCPClientSlug(client.Name)
	}
	if client.Slug == "" {
		client.Slug = "client"
	}
	if len(client.Slug) > maxMCPClientSlugBytes {
		return false, fmt.Errorf("%w: stored slug is too long", ErrInvalidMCPClient)
	}
	baseSlug := client.Slug
	for n := 2; ; n++ {
		if _, used := existingSlugs[client.Slug]; !used {
			break
		}
		client.Slug = fmt.Sprintf("%s-%d", baseSlug, n)
		if len(client.Slug) > maxMCPClientSlugBytes {
			return false, fmt.Errorf("%w: duplicate stored slug cannot be repaired", ErrInvalidMCPClient)
		}
	}
	client.Subject = strings.TrimSpace(client.Subject)
	if err := validateMCPClientSubject(client.Subject); err != nil {
		return false, err
	}
	client.RuntimeAttestorPublicKey, err = normalizeMCPClientRuntimeAttestorPublicKey(client.RuntimeAttestorPublicKey)
	if err != nil {
		return false, err
	}
	client.CreatedBy = strings.TrimSpace(client.CreatedBy)
	if client.CreatedBy != "" && !validActorIdentifier(client.CreatedBy) {
		return false, fmt.Errorf("%w: stored creator is invalid", ErrInvalidMCPClient)
	}
	status, err := normalizeMCPClientStatus(client.Status)
	if err != nil {
		return false, err
	}
	client.Status = status
	client.OAuthClientID = strings.TrimSpace(client.OAuthClientID)
	if client.OAuthClientID != "" {
		if !validMCPClientOAuthClientID(client.OAuthClientID) {
			return false, fmt.Errorf("%w: stored OAuth client ID is invalid", ErrInvalidMCPClient)
		}
		if _, used := existingOAuth[client.OAuthClientID]; used {
			return false, fmt.Errorf("%w: duplicate stored OAuth client ID", ErrMCPClientOAuthBinding)
		}
	}
	client.ConnectionNamespaceIDs, err = normalizeMCPClientNamespaceIDs(client.ConnectionNamespaceIDs)
	if err != nil {
		return false, err
	}
	unsafeNamespaceGrant := false
	for _, namespaceID := range client.ConnectionNamespaceIDs {
		if !namespaceSafeForSubject(namespaceID, client.Subject) {
			unsafeNamespaceGrant = true
			break
		}
	}
	if unsafeNamespaceGrant {
		// A stale handcrafted/preview record must never become an active
		// subject grant. In particular, a folder can now contain a personal
		// connection whose owner differs from this client subject. Revoke the
		// record rather than serving it or blocking the whole Engine startup.
		client.ConnectionNamespaceIDs = nil
		client.Status = MCPClientStatusRevoked
		client.Epoch = newEpoch()
	}
	if client.Epoch == "" {
		client.Epoch = newEpoch()
	}
	if client.Revision < 1 {
		client.Revision = 1
	}
	now := time.Now().UTC()
	if client.CreatedAt.IsZero() {
		client.CreatedAt = now
	}
	if client.UpdatedAt.IsZero() {
		client.UpdatedAt = client.CreatedAt
	}
	if client.Status == MCPClientStatusRevoked && client.RevokedAt == nil {
		revokedAt := now
		client.RevokedAt = &revokedAt
	}
	if client.Status == MCPClientStatusActive {
		client.RevokedAt = nil
		client.RevokedBy = ""
	}
	existingIDs[client.ID] = struct{}{}
	existingSlugs[client.Slug] = struct{}{}
	if client.OAuthClientID != "" {
		existingOAuth[client.OAuthClientID] = struct{}{}
	}
	return !sameMCPClient(before, *client), nil
}

func sameMCPClient(a, b MCPClient) bool {
	if a.ID != b.ID || a.Slug != b.Slug || a.Name != b.Name || a.Subject != b.Subject ||
		a.OAuthClientID != b.OAuthClientID || a.RuntimeAttestorPublicKey != b.RuntimeAttestorPublicKey || a.Status != b.Status || a.Epoch != b.Epoch ||
		a.Revision != b.Revision || a.CreatedBy != b.CreatedBy || !a.CreatedAt.Equal(b.CreatedAt) ||
		!a.UpdatedAt.Equal(b.UpdatedAt) || a.RevokedBy != b.RevokedBy || !sameStrings(a.ConnectionNamespaceIDs, b.ConnectionNamespaceIDs) {
		return false
	}
	if a.RevokedAt == nil || b.RevokedAt == nil {
		return a.RevokedAt == nil && b.RevokedAt == nil
	}
	return a.RevokedAt.Equal(*b.RevokedAt)
}

func (s *FileStore) backfillMCPClientsLocked() (bool, error) {
	if len(s.mcpClients) == 0 {
		return false, nil
	}
	ids := make(map[string]struct{}, len(s.mcpClients))
	slugs := make(map[string]struct{}, len(s.mcpClients))
	oauth := make(map[string]struct{}, len(s.mcpClients))
	changed := false
	for _, client := range s.mcpClients {
		updated, err := prepareLoadedMCPClient(client, ids, slugs, oauth, func(id, subject string) bool {
			if _, ok := s.connectionNamespaceByIDLocked(id); !ok {
				return false
			}
			for _, account := range s.accounts {
				if account != nil && account.ConnectionNamespaceID == id && account.IsPersonal() && account.OwnerSubject != subject {
					return false
				}
			}
			return true
		})
		if err != nil {
			return false, err
		}
		changed = changed || updated
	}
	return changed, nil
}

func (s *FileStore) mcpClientByIDLocked(id string) (*MCPClient, bool) {
	for _, client := range s.mcpClients {
		if client != nil && client.ID == id {
			return client, true
		}
	}
	return nil, false
}

func (s *FileStore) mcpClientBySlugLocked(slug string) (*MCPClient, bool) {
	for _, client := range s.mcpClients {
		if client != nil && client.Slug == slug {
			return client, true
		}
	}
	return nil, false
}

func (s *FileStore) mcpClientByOAuthIDLocked(oauthClientID string) (*MCPClient, bool) {
	for _, client := range s.mcpClients {
		if client != nil && client.OAuthClientID == oauthClientID {
			return client, true
		}
	}
	return nil, false
}

func (s *FileStore) activeMCPClientCountLocked() int {
	count := 0
	for _, client := range s.mcpClients {
		if client != nil && client.Status == MCPClientStatusActive {
			count++
		}
	}
	return count
}

func (s *FileStore) validateMCPClientNamespacesLocked(client MCPClient) error {
	for _, namespaceID := range client.ConnectionNamespaceIDs {
		if _, ok := s.connectionNamespaceByIDLocked(namespaceID); !ok {
			return fmt.Errorf("%w: %s", ErrConnectionNamespaceNotFound, namespaceID)
		}
		for _, account := range s.accounts {
			if account == nil || account.ConnectionNamespaceID != namespaceID || !account.IsPersonal() {
				continue
			}
			if account.OwnerSubject != client.Subject {
				return ErrMCPClientNamespaceSubject
			}
		}
	}
	return nil
}

func (s *FileStore) validatePersonalAccountMCPClientGrantsLocked(account Account) error {
	if !account.IsPersonal() {
		return nil
	}
	for _, client := range s.mcpClients {
		if client == nil || client.Status != MCPClientStatusActive || client.Subject == account.OwnerSubject {
			continue
		}
		for _, namespaceID := range client.ConnectionNamespaceIDs {
			if namespaceID == account.ConnectionNamespaceID {
				return ErrMCPClientNamespaceSubject
			}
		}
	}
	return nil
}

// rotateMCPClientEpochsForAccountMoveLocked invalidates only active scoped
// clients whose account-delivery boundary changes. Account.Name and endpoint
// slugs are deliberately left alone: callers keep their stable tool prefixes
// and URLs, while existing OAuth grants must refresh before observing the
// moved credential through a newly different scope.
func (s *FileStore) rotateMCPClientEpochsForAccountMoveLocked(before, after Account) {
	now := time.Now().UTC()
	for _, client := range s.mcpClients {
		if client == nil || !mcpClientDeliveryChangesForAccountMove(*client, before, after) {
			continue
		}
		client.Epoch = newEpoch()
		client.Revision++
		client.UpdatedAt = now
	}
}

// ---- FileStore: MCPClientStore ----

func (s *FileStore) MCPClients(_ context.Context) ([]MCPClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]MCPClient, 0, len(s.mcpClients))
	for _, client := range s.mcpClients {
		if client != nil {
			out = append(out, copyMCPClient(*client))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Slug == out[j].Slug {
			return out[i].ID < out[j].ID
		}
		return out[i].Slug < out[j].Slug
	})
	return out, nil
}

func (s *FileStore) ActiveMCPClients(ctx context.Context) ([]MCPClient, error) {
	clients, err := s.MCPClients(ctx)
	if err != nil {
		return nil, err
	}
	out := clients[:0]
	for _, client := range clients {
		if client.Status == MCPClientStatusActive {
			out = append(out, client)
		}
	}
	return out, nil
}

func (s *FileStore) MCPClient(_ context.Context, id string) (MCPClient, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	client, ok := s.mcpClientByIDLocked(strings.TrimSpace(id))
	if !ok {
		return MCPClient{}, false
	}
	return copyMCPClient(*client), true
}

func (s *FileStore) MCPClientBySlug(_ context.Context, slug string) (MCPClient, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	client, ok := s.mcpClientBySlugLocked(normalizeMCPClientSlug(slug))
	if !ok {
		return MCPClient{}, false
	}
	return copyMCPClient(*client), true
}

func (s *FileStore) ActiveMCPClient(ctx context.Context, endpointIdentifier string) (MCPClient, bool) {
	if client, ok := s.MCPClient(ctx, endpointIdentifier); ok && client.Status == MCPClientStatusActive {
		return client, true
	}
	client, ok := s.MCPClientBySlug(ctx, endpointIdentifier)
	if !ok || client.Status != MCPClientStatusActive {
		return MCPClient{}, false
	}
	return client, true
}

func (s *FileStore) ActiveMCPClientByOAuthClientID(_ context.Context, oauthClientID string) (MCPClient, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	client, ok := s.mcpClientByOAuthIDLocked(strings.TrimSpace(oauthClientID))
	if !ok || client.Status != MCPClientStatusActive {
		return MCPClient{}, false
	}
	return copyMCPClient(*client), true
}

func (s *FileStore) CreateMCPClient(_ context.Context, client MCPClient) (MCPClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := prepareMCPClientForCreate(&client); err != nil {
		return MCPClient{}, err
	}
	if _, exists := s.mcpClientByIDLocked(client.ID); exists {
		return MCPClient{}, ErrMCPClientExists
	}
	if _, exists := s.mcpClientBySlugLocked(client.Slug); exists {
		base := client.Slug
		for n := 2; ; n++ {
			candidate := fmt.Sprintf("%s-%d", base, n)
			if len(candidate) > maxMCPClientSlugBytes {
				return MCPClient{}, ErrMCPClientExists
			}
			if _, exists := s.mcpClientBySlugLocked(candidate); !exists {
				client.Slug = candidate
				break
			}
		}
	}
	if client.OAuthClientID != "" {
		if _, exists := s.mcpClientByOAuthIDLocked(client.OAuthClientID); exists {
			return MCPClient{}, ErrMCPClientOAuthBinding
		}
	}
	if s.activeMCPClientCountLocked() >= maxActiveMCPClients {
		return MCPClient{}, ErrMCPClientLimit
	}
	if err := s.validateMCPClientNamespacesLocked(client); err != nil {
		return MCPClient{}, err
	}
	copy := copyMCPClient(client)
	s.mcpClients = append(s.mcpClients, &copy)
	if err := s.saveLocked(); err != nil {
		s.mcpClients = s.mcpClients[:len(s.mcpClients)-1]
		return MCPClient{}, err
	}
	return copyMCPClient(copy), nil
}

func (s *FileStore) UpdateMCPClient(_ context.Context, update MCPClient, precondition MCPClientPrecondition) (MCPClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	client, ok := s.mcpClientByIDLocked(strings.TrimSpace(update.ID))
	if !ok {
		return MCPClient{}, ErrMCPClientNotFound
	}
	if !mcpClientPreconditionMatches(*client, precondition) {
		return MCPClient{}, ErrMCPClientRevision
	}
	if client.Status == MCPClientStatusRevoked {
		return MCPClient{}, ErrMCPClientRevoked
	}
	name := strings.TrimSpace(update.Name)
	if err := validateMCPClientName(name); err != nil {
		return MCPClient{}, err
	}
	if update.Subject != "" && strings.TrimSpace(update.Subject) != client.Subject {
		return MCPClient{}, fmt.Errorf("%w: subject is immutable", ErrInvalidMCPClient)
	}
	if update.Slug != "" && normalizeMCPClientSlug(update.Slug) != client.Slug {
		return MCPClient{}, fmt.Errorf("%w: endpoint slug is immutable", ErrInvalidMCPClient)
	}
	key := client.RuntimeAttestorPublicKey
	if update.runtimeAttestorKeySet {
		var keyErr error
		key, keyErr = normalizeMCPClientRuntimeAttestorPublicKey(update.RuntimeAttestorPublicKey)
		if keyErr != nil {
			return MCPClient{}, keyErr
		}
	}
	if name == client.Name && key == client.RuntimeAttestorPublicKey {
		return copyMCPClient(*client), nil
	}
	before := copyMCPClient(*client)
	client.Name = name
	if key != client.RuntimeAttestorPublicKey {
		client.RuntimeAttestorPublicKey = key
		// A key rotation is an authorization boundary: pending signed receipts
		// for the old key must fail even before their expiry.
		client.Epoch = newEpoch()
	}
	client.Revision++
	client.UpdatedAt = time.Now().UTC()
	if err := s.saveLocked(); err != nil {
		*client = before
		return MCPClient{}, err
	}
	return copyMCPClient(*client), nil
}

func (s *FileStore) SetMCPClientNamespaces(_ context.Context, id string, namespaceIDs []string, precondition MCPClientPrecondition) (MCPClient, error) {
	namespaceIDs, err := normalizeMCPClientNamespaceIDs(namespaceIDs)
	if err != nil {
		return MCPClient{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	client, ok := s.mcpClientByIDLocked(strings.TrimSpace(id))
	if !ok {
		return MCPClient{}, ErrMCPClientNotFound
	}
	if !mcpClientPreconditionMatches(*client, precondition) {
		return MCPClient{}, ErrMCPClientRevision
	}
	if client.Status == MCPClientStatusRevoked {
		return MCPClient{}, ErrMCPClientRevoked
	}
	proposed := copyMCPClient(*client)
	proposed.ConnectionNamespaceIDs = namespaceIDs
	if err := s.validateMCPClientNamespacesLocked(proposed); err != nil {
		return MCPClient{}, err
	}
	if sameStrings(client.ConnectionNamespaceIDs, namespaceIDs) {
		return copyMCPClient(*client), nil
	}
	before := copyMCPClient(*client)
	client.ConnectionNamespaceIDs = namespaceIDs
	client.Epoch = newEpoch()
	client.Revision++
	client.UpdatedAt = time.Now().UTC()
	if err := s.saveLocked(); err != nil {
		*client = before
		return MCPClient{}, err
	}
	return copyMCPClient(*client), nil
}

func (s *FileStore) BindMCPClientOAuthClient(_ context.Context, id, oauthClientID string, precondition MCPClientPrecondition, actor PlatformActor) (MCPClient, error) {
	oauthClientID = strings.TrimSpace(oauthClientID)
	if !validMCPClientOAuthClientID(oauthClientID) {
		return MCPClient{}, fmt.Errorf("%w: OAuth client ID is invalid", ErrInvalidMCPClient)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	client, ok := s.mcpClientByIDLocked(strings.TrimSpace(id))
	if !ok {
		return MCPClient{}, ErrMCPClientNotFound
	}
	if !mcpClientPreconditionMatches(*client, precondition) {
		return MCPClient{}, ErrMCPClientRevision
	}
	if client.Status == MCPClientStatusRevoked {
		return MCPClient{}, ErrMCPClientRevoked
	}
	if !MCPClientAllowsActor(*client, actor) {
		return MCPClient{}, fmt.Errorf("%w: actor cannot bind this client", ErrInvalidMCPClient)
	}
	if client.OAuthClientID == oauthClientID {
		return copyMCPClient(*client), nil
	}
	if client.OAuthClientID != "" {
		return MCPClient{}, ErrMCPClientOAuthBinding
	}
	if existing, exists := s.mcpClientByOAuthIDLocked(oauthClientID); exists && existing.ID != client.ID {
		return MCPClient{}, ErrMCPClientOAuthBinding
	}
	before := copyMCPClient(*client)
	client.OAuthClientID = oauthClientID
	client.Epoch = newEpoch()
	client.Revision++
	client.UpdatedAt = time.Now().UTC()
	if err := s.saveLocked(); err != nil {
		*client = before
		return MCPClient{}, err
	}
	return copyMCPClient(*client), nil
}

func (s *FileStore) ResetMCPClientOAuthClient(_ context.Context, id string, precondition MCPClientPrecondition) (MCPClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	client, ok := s.mcpClientByIDLocked(strings.TrimSpace(id))
	if !ok {
		return MCPClient{}, ErrMCPClientNotFound
	}
	if !mcpClientPreconditionMatches(*client, precondition) {
		return MCPClient{}, ErrMCPClientRevision
	}
	if client.Status == MCPClientStatusRevoked {
		return MCPClient{}, ErrMCPClientRevoked
	}
	before := copyMCPClient(*client)
	client.OAuthClientID = ""
	client.Epoch = newEpoch()
	client.Revision++
	client.UpdatedAt = time.Now().UTC()
	if err := s.saveLocked(); err != nil {
		*client = before
		return MCPClient{}, err
	}
	return copyMCPClient(*client), nil
}

func (s *FileStore) RevokeMCPClient(_ context.Context, id, revokedBy string, precondition MCPClientPrecondition) (MCPClient, error) {
	revokedBy = strings.TrimSpace(revokedBy)
	if revokedBy != "" && !validActorIdentifier(revokedBy) {
		return MCPClient{}, fmt.Errorf("%w: revoker is invalid", ErrInvalidMCPClient)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	client, ok := s.mcpClientByIDLocked(strings.TrimSpace(id))
	if !ok {
		return MCPClient{}, ErrMCPClientNotFound
	}
	if !mcpClientPreconditionMatches(*client, precondition) {
		return MCPClient{}, ErrMCPClientRevision
	}
	if client.Status == MCPClientStatusRevoked {
		return copyMCPClient(*client), nil
	}
	before := copyMCPClient(*client)
	now := time.Now().UTC()
	client.Status = MCPClientStatusRevoked
	client.Epoch = newEpoch()
	client.Revision++
	client.UpdatedAt = now
	client.RevokedAt = &now
	client.RevokedBy = revokedBy
	if err := s.saveLocked(); err != nil {
		*client = before
		return MCPClient{}, err
	}
	return copyMCPClient(*client), nil
}
