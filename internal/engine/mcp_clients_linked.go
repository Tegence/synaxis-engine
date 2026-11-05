package engine

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// A link joins product identity, never credentials or resource grants. The
// workload keeps its own subject, scoped endpoint, skills and output provenance.
func validateLinkedMCPClient(client MCPClient, creating bool) error {
	if client.InteractiveClientID == "" {
		if creating && client.SourceRevision != 0 {
			return fmt.Errorf("%w: source revision requires an interactive client", ErrInvalidMCPClient)
		}
		return nil
	}
	if mcpClientKind(client) != MCPClientKindWorkload || !validActorIdentifier(client.InteractiveClientID) || client.InteractiveClientID == client.ID {
		return fmt.Errorf("%w: only a workload may link an interactive client", ErrInvalidMCPClient)
	}
	if creating && client.SourceRevision < 1 {
		return fmt.Errorf("%w: source revision is required", ErrInvalidMCPClient)
	}
	return nil
}

func validateLinkedMCPClientSource(client, source MCPClient) error {
	if source.Status != MCPClientStatusActive {
		return ErrMCPClientRevoked
	}
	if mcpClientKind(source) != MCPClientKindInteractive {
		return ErrMCPClientKind
	}
	if source.Revision != client.SourceRevision {
		return ErrMCPClientRevision
	}
	return nil
}

func (s *FileStore) validateLinkedMCPClientCreateLocked(client MCPClient) error {
	if client.InteractiveClientID == "" {
		return nil
	}
	source, found := s.mcpClientByIDLocked(client.InteractiveClientID)
	if !found {
		return ErrMCPClientNotFound
	}
	if err := validateLinkedMCPClientSource(client, *source); err != nil {
		return err
	}
	for _, existing := range s.mcpClients {
		if existing != nil && existing.Status == MCPClientStatusActive && existing.InteractiveClientID == source.ID {
			return ErrMCPClientExists
		}
	}
	return nil
}

func validateLinkedMCPClientCreateTx(ctx context.Context, tx pgx.Tx, client MCPClient) error {
	if client.InteractiveClientID == "" {
		return nil
	}
	source, err := loadMCPClientForUpdate(ctx, tx, client.InteractiveClientID)
	if err != nil {
		return err
	}
	if err := validateLinkedMCPClientSource(client, source); err != nil {
		return err
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM narthex_mcp_clients WHERE interactive_client_id=$1 AND status='active')`, source.ID).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return ErrMCPClientExists
	}
	return nil
}

// Check the durable source too: this fails closed after a legacy writer or a
// repair revokes the source without performing the normal atomic cascade.
func linkedMCPClientSourceActive(ctx context.Context, store MCPClientStore, client MCPClient) bool {
	if client.InteractiveClientID == "" {
		return true
	}
	source, found := store.MCPClient(ctx, client.InteractiveClientID)
	return found && source.Status == MCPClientStatusActive && mcpClientKind(source) == MCPClientKindInteractive
}

func linkedMCPClientSourceActiveTx(ctx context.Context, q mcpClientQueryer, client MCPClient) (bool, error) {
	if client.InteractiveClientID == "" {
		return true, nil
	}
	var active bool
	err := q.QueryRow(ctx, `SELECT status='active' AND kind='interactive' FROM narthex_mcp_clients WHERE id=$1`, client.InteractiveClientID).Scan(&active)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return active, err
}
