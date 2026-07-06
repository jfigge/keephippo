package inmem_test

import (
	"testing"

	"github.com/jfigge/keephippo/internal/physical/inmem"
	"github.com/jfigge/keephippo/internal/physical/physicaltest"
)

func TestInmemBackend(t *testing.T) {
	physicaltest.Exercise(t, inmem.New())
}
