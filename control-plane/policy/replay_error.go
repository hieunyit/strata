package policy

// ReplayError means a new replay and approval are needed before publishing.
type ReplayError struct{ Msg string }

func (e *ReplayError) Error() string { return e.Msg }
