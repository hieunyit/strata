package schema

import (
	"sort"
	"sync"
)

// Store provides operations to persist, query, and delete OpenAPI schemas.
type Store interface {
	Get(id string) (*ApiSchema, error)
	List() ([]*ApiSchema, error)
	Save(schema *ApiSchema) error
	Delete(id string) error
}

// MemoryStore provides a thread-safe in-memory implementation of Store.
type MemoryStore struct {
	mu      sync.RWMutex
	schemas map[string]*ApiSchema
}

// NewMemoryStore creates a new in-memory schema store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		schemas: make(map[string]*ApiSchema),
	}
}

// Get returns the schema with the given ID, or ErrNotFound.
func (m *MemoryStore) Get(id string) (*ApiSchema, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	s, ok := m.schemas[id]
	if !ok {
		return nil, ErrNotFound
	}

	// Return a copy to prevent external mutation
	clone := *s
	return &clone, nil
}

// List returns all registered schemas sorted by ID.
func (m *MemoryStore) List() ([]*ApiSchema, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	list := make([]*ApiSchema, 0, len(m.schemas))
	for _, s := range m.schemas {
		clone := *s
		list = append(list, &clone)
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].ID < list[j].ID
	})

	return list, nil
}

// Save stores or updates an API schema.
func (m *MemoryStore) Save(schema *ApiSchema) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	clone := *schema
	m.schemas[schema.ID] = &clone
	return nil
}

// Delete removes the schema with the given ID.
func (m *MemoryStore) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.schemas[id]; !ok {
		return ErrNotFound
	}
	delete(m.schemas, id)
	return nil
}
