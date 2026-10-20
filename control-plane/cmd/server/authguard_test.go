package main

import (
	"context"
	"errors"
	"testing"
)

func TestCheckLocalOff(t *testing.T) {
	users := func(n int) func(context.Context) (int, error) {
		return func(context.Context) (int, error) { return n, nil }
	}
	seen := func(ok bool) func(context.Context) (bool, error) {
		return func(context.Context) (bool, error) { return ok, nil }
	}
	broken := errors.New("database down")
	for name, tc := range map[string]struct {
		users func(context.Context) (int, error)
		seen  func(context.Context) (bool, error)
		want  error
	}{
		"no local account":            {users(0), seen(false), nil},
		"local accounts, admin seen":  {users(2), seen(true), nil},
		"local accounts, none seen":   {users(2), seen(false), errLocalOffUnsafe},
		"cannot count local accounts": {func(context.Context) (int, error) { return 0, broken }, seen(true), broken},
		"cannot read sign-ins":        {users(1), func(context.Context) (bool, error) { return false, broken }, broken},
	} {
		if err := checkLocalOff(context.Background(), tc.users, tc.seen); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
}
