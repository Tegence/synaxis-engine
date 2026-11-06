package engine

// Compile-time store contracts.
//
// The console and gateway discover optional store capabilities by type
// assertion (`s.store.(ConnectorStore)` and friends) and answer 501 when a
// store lacks one, so a method dropped from FileStore or PgStore would only
// surface at runtime, on the request that needed it. The assertions below turn
// that into a build failure.
//
// Add a line when a store gains an interface. Remove one only when the store
// deliberately stops offering that capability, and say so here: FileStore has
// no UsageStore because hosted usage enforcement requires durable Postgres
// storage, so hosted mode refuses to start on the file store.

var (
	_ AccountStore                             = (*FileStore)(nil)
	_ ApprovalLifecycle                        = (*FileStore)(nil)
	_ ApprovalLog                              = (*FileStore)(nil)
	_ AuditPurger                              = (*FileStore)(nil)
	_ AuditSink                                = (*FileStore)(nil)
	_ AuditTriage                              = (*FileStore)(nil)
	_ BuiltInLibraryCurrentVersionStore        = (*FileStore)(nil)
	_ BuiltInLibraryStore                      = (*FileStore)(nil)
	_ ConnectionGrantStore                     = (*FileStore)(nil)
	_ ConnectionNamespaceStore                 = (*FileStore)(nil)
	_ ConnectorStore                           = (*FileStore)(nil)
	_ ControlIdempotencyStore                  = (*FileStore)(nil)
	_ HealthAlertStore                         = (*FileStore)(nil)
	_ LibraryArtifactMediaStore                = (*FileStore)(nil)
	_ LibraryChatArtifactStore                 = (*FileStore)(nil)
	_ LibraryCollaborationStore                = (*FileStore)(nil)
	_ LibraryControlArtifactStore              = (*FileStore)(nil)
	_ LibraryMCPClientArtifactVersionStore     = (*FileStore)(nil)
	_ LibraryMCPClientSkillAuthoringAuditStore = (*FileStore)(nil)
	_ LibraryMCPClientSkillAuthoringStore      = (*FileStore)(nil)
	_ LibraryMCPClientSkillBlobStore           = (*FileStore)(nil)
	_ LibraryMemoryStore                       = (*FileStore)(nil)
	_ LibraryRunCorrelationStore               = (*FileStore)(nil)
	_ LibraryRuntimeAttestationStore           = (*FileStore)(nil)
	_ LibrarySkillBundleStore                  = (*FileStore)(nil)
	_ LibraryStore                             = (*FileStore)(nil)
	_ MCPClientAccessStore                     = (*FileStore)(nil)
	_ MCPClientStore                           = (*FileStore)(nil)
	_ MemberCredentialStore                    = (*FileStore)(nil)
	_ NamespaceStore                           = (*FileStore)(nil)
	_ PortableAccountConfigStore               = (*FileStore)(nil)
	_ SkillStore                               = (*FileStore)(nil)
	_ StaticOAuthConfigStore                   = (*FileStore)(nil)
)

var (
	_ AccountStore                             = (*PgStore)(nil)
	_ ApprovalLifecycle                        = (*PgStore)(nil)
	_ ApprovalLog                              = (*PgStore)(nil)
	_ AuditPurger                              = (*PgStore)(nil)
	_ AuditSink                                = (*PgStore)(nil)
	_ AuditTriage                              = (*PgStore)(nil)
	_ BuiltInLibraryCurrentVersionStore        = (*PgStore)(nil)
	_ BuiltInLibraryStore                      = (*PgStore)(nil)
	_ ConnectionGrantStore                     = (*PgStore)(nil)
	_ ConnectionNamespaceStore                 = (*PgStore)(nil)
	_ ConnectorStore                           = (*PgStore)(nil)
	_ ControlIdempotencyStore                  = (*PgStore)(nil)
	_ HealthAlertStore                         = (*PgStore)(nil)
	_ LibraryArtifactMediaStore                = (*PgStore)(nil)
	_ LibraryChatArtifactStore                 = (*PgStore)(nil)
	_ LibraryCollaborationStore                = (*PgStore)(nil)
	_ LibraryControlArtifactStore              = (*PgStore)(nil)
	_ LibraryMCPClientArtifactVersionStore     = (*PgStore)(nil)
	_ LibraryMCPClientSkillAuthoringAuditStore = (*PgStore)(nil)
	_ LibraryMCPClientSkillAuthoringStore      = (*PgStore)(nil)
	_ LibraryMCPClientSkillBlobStore           = (*PgStore)(nil)
	_ LibraryMemoryStore                       = (*PgStore)(nil)
	_ LibraryRunCorrelationStore               = (*PgStore)(nil)
	_ LibraryRuntimeAttestationStore           = (*PgStore)(nil)
	_ LibrarySkillBundleStore                  = (*PgStore)(nil)
	_ LibraryStore                             = (*PgStore)(nil)
	_ MCPClientAccessStore                     = (*PgStore)(nil)
	_ MCPClientStore                           = (*PgStore)(nil)
	_ MemberCredentialStore                    = (*PgStore)(nil)
	_ NamespaceStore                           = (*PgStore)(nil)
	_ PortableAccountConfigStore               = (*PgStore)(nil)
	_ SkillStore                               = (*PgStore)(nil)
	_ StaticOAuthConfigStore                   = (*PgStore)(nil)
	_ UsageStore                               = (*PgStore)(nil)
)
