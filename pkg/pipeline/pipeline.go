// Package pipeline carries typed, attributed values along the plugin chain of
// one query.
//
// The query context already had a bare set of uint marks: any plugin could add
// one and nothing recorded who added it or what it meant. Once several plugins
// share one code path (a fake ip range, an asn prefix, a source alias), that
// shape cannot answer the only question a reader has - which plugin decided
// this? - so every value here is stored under an explicit owner and recovered
// through a typed key instead of a name that two plugins may reuse.
//
// # Contract
//
//   - A key is a Go type plus a name. Reading it with the wrong owner yields
//     nothing rather than a plausible value from a different plugin.
//   - Owner is the plugin tag. It is the identity that reaches the log, so the
//     value and its origin are never separated.
//   - Values are request scoped. Copy and CopyTo snapshot them, so a parallel
//     branch sees what was decided before it forked and cannot silently rewrite
//     the decision its sibling depends on.
package pipeline

import (
	"github.com/ersonw/mosdns-v4/pkg/query_context"
)

// Owner names the plugin that produced a value. Callers pass the plugin tag
// they were registered under, so a value can always be traced back.
type Owner string

// Key is a typed value slot. The zero value is not usable; build one with NewKey
// so the slot keeps a name for diagnostics.
type Key[T any] struct {
	name string
}

// NewKey names a slot. The name is only for logs and verification output: the
// type parameter is what keeps two plugins from reading each other's value.
func NewKey[T any](name string) *Key[T] {
	return &Key[T]{name: name}
}

// Name reports the diagnostic name of the slot.
func (k *Key[T]) Name() string { return k.name }

// entryKey is what actually sits in the context. It carries the slot and the
// owner together, which is why a lookup cannot accidentally return another
// plugin's value.
type entryKey struct {
	key   *Key[any]
	owner Owner
}

// slotKey builds the storage key of a slot for one owner. The pointer identity
// of k is what distinguishes two slots of the same Go type.
func slotKey[T any](k *Key[T], owner Owner) entryKey {
	return entryKey{key: (*Key[any])(k), owner: owner}
}

// Set stores v for this owner. Re-setting the same owner replaces the previous
// value, which is what a plugin re-running on a retry should do.
func Set[T any](ctx *query_context.Context, k *Key[T], owner Owner, v T) {
	ctx.SetValue(slotKey(k, owner), v)
}

// Get returns the value this owner stored.
func Get[T any](ctx *query_context.Context, k *Key[T], owner Owner) (T, bool) {
	v, ok := ctx.Value(slotKey(k, owner))
	if !ok {
		var zero T
		return zero, false
	}
	typed, ok := v.(T)
	if !ok {
		var zero T
		return zero, false
	}
	return typed, true
}

// Has reports whether this owner stored a value.
func Has[T any](ctx *query_context.Context, k *Key[T], owner Owner) bool {
	_, ok := ctx.Value(slotKey(k, owner))
	return ok
}

// Snapshot returns every owner's value for this slot. It exists for the
// diagnostics path: when two plugins both decide a route for one query, the
// log can name each decision instead of the last write winning silently.
func Snapshot[T any](ctx *query_context.Context, k *Key[T]) map[Owner]T {
	out := make(map[Owner]T)
	for _, entry := range ctx.Values() {
		ek, ok := entry.Key.(entryKey)
		if !ok || ek.key != (*Key[any])(k) {
			continue
		}
		if v, ok := entry.Value.(T); ok {
			out[ek.owner] = v
		}
	}
	return out
}

// Delete removes this owner's value, for the path where a plugin withdraws a
// decision it made earlier in the same chain.
func Delete[T any](ctx *query_context.Context, k *Key[T], owner Owner) {
	ctx.DeleteValue(slotKey(k, owner))
}
