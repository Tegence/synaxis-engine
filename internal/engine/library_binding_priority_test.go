package engine

import (
	"context"
	"strconv"
	"strings"
	"testing"
)

func authoredPriorityTestBinding(priority int) LibrarySkillBinding {
	return LibrarySkillBinding{
		SkillID: "libsk_priority_test", ScopeKind: LibraryScopeAgentSurface, ScopeID: "mcpcli_priority_test",
		Mode: LibraryBindingModeTrack, CapabilityCeiling: []string{}, Priority: priority, CreatedBy: "usr_priority_test",
	}
}

func TestAuthoredLibraryBindingPriorityBounds(t *testing.T) {
	for _, priority := range []int{libraryMinAuthoredBindingPriority, 0, libraryMaxAuthoredBindingPriority} {
		if _, err := normalizedLibraryBinding(authoredPriorityTestBinding(priority)); err != nil {
			t.Fatalf("authored priority %d rejected: %v", priority, err)
		}
	}

	invalid := []int{usingSynaxisBindingPriority}
	if strconv.IntSize > 32 {
		invalid = append(invalid, int(int64(libraryMinAuthoredBindingPriority)-1), int(int64(usingSynaxisBindingPriority)+1))
	}
	for _, priority := range invalid {
		if _, err := normalizedLibraryBinding(authoredPriorityTestBinding(priority)); err == nil || !strings.Contains(err.Error(), "binding priority") {
			t.Fatalf("out-of-range authored priority %d error=%v, want binding-priority rejection", priority, err)
		}
	}
}

func TestAuthoredLibraryBindingPriorityValidationMatchesFileAndPgStores(t *testing.T) {
	binding := authoredPriorityTestBinding(usingSynaxisBindingPriority)
	fileErrBinding, fileErr := (&FileStore{}).UpsertLibrarySkillBinding(context.Background(), binding)
	pgErrBinding, pgErr := (&PgStore{}).UpsertLibrarySkillBinding(context.Background(), binding)
	if fileErr == nil || pgErr == nil {
		t.Fatalf("reserved authored priority reached a store write: file=(%+v,%v) pg=(%+v,%v)", fileErrBinding, fileErr, pgErrBinding, pgErr)
	}
	if fileErr.Error() != pgErr.Error() || !strings.Contains(fileErr.Error(), "binding priority") {
		t.Fatalf("File/Pg priority validation diverged: file=%v pg=%v", fileErr, pgErr)
	}
}
