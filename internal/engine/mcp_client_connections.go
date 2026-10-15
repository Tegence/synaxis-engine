package engine

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"
)

// MCPClientAccessStore atomically replaces folder and exact-connection grants.
// Older namespace-only callers retain exact grants; an explicit empty list
// through this facet removes them. Individual connections never imply a folder.
type MCPClientAccessStore interface {
	SetMCPClientAccess(context.Context, string, []string, []string, MCPClientPrecondition) (MCPClient, error)
}

func mcpClientConnectionIDs(grants map[string]string) []string {
	ids := make([]string, 0, len(grants))
	for id, incarnation := range grants {
		if id != "" && incarnation != "" {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

func (s *FileStore) captureMCPClientConnectionsLocked(client *MCPClient) error {
	grants := make(map[string]string, len(client.ConnectionIDs))
	for _, name := range client.ConnectionIDs {
		var found *Account
		for _, account := range s.accounts {
			if account != nil && account.Name == name {
				found = account
				break
			}
		}
		if found == nil || found.IncarnationID == "" {
			return ErrAccountNotFound
		}
		if found.IsPersonal() && (found.OwnerSubject != client.Subject || client.InteractiveClientID != "") {
			return ErrMCPClientNamespaceSubject
		}
		if previous := client.ConnectionGrants[name]; previous != "" && previous != found.IncarnationID {
			return ErrAccountIncarnation
		}
		grants[name] = found.IncarnationID
	}
	client.ConnectionGrants = grants
	client.ConnectionIDs = mcpClientConnectionIDs(grants)
	return nil
}

func captureMCPClientConnectionsTx(ctx context.Context, tx pgx.Tx, client *MCPClient) error {
	grants := make(map[string]string, len(client.ConnectionIDs))
	for _, name := range client.ConnectionIDs {
		var incarnation, scope, owner string
		err := tx.QueryRow(ctx, `SELECT incarnation_id,connection_scope,owner_subject FROM narthex_accounts WHERE name=$1 FOR SHARE`, name).Scan(&incarnation, &scope, &owner)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrAccountNotFound
		}
		if err != nil {
			return err
		}
		if incarnation == "" {
			return ErrAccountNotFound
		}
		if scope == string(ConnectionScopePersonal) && (owner != client.Subject || client.InteractiveClientID != "") {
			return ErrMCPClientNamespaceSubject
		}
		if previous := client.ConnectionGrants[name]; previous != "" && previous != incarnation {
			return ErrAccountIncarnation
		}
		grants[name] = incarnation
	}
	client.ConnectionGrants = grants
	client.ConnectionIDs = mcpClientConnectionIDs(grants)
	return nil
}

func (c *ConsoleAPI) validateMCPClientConnectionAccess(ctx context.Context, actor PlatformActor, subject string, ids []string) error {
	for _, id := range ids {
		account, ok := c.store.Account(id)
		if !ok || !c.canManageAccount(ctx, actor, account) {
			return ErrAccountNotFound
		}
		if account.IsPersonal() && account.OwnerSubject != subject {
			return ErrMCPClientNamespaceSubject
		}
	}
	return nil
}

func normalizeMCPClientConnectionIDs(ids []string) ([]string, error) {
	normalized, err := normalizeMCPClientNamespaceIDs(ids)
	if err != nil {
		return nil, err
	}
	for _, id := range normalized {
		if len(id) > 256 {
			return nil, fmt.Errorf("%w: connection identifier is too long", ErrInvalidMCPClient)
		}
	}
	return normalized, nil
}
