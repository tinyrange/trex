//go:build !(linux && amd64)

package power

const jitAvailable = false

type jitArena struct{}

func newJITArena(int) (*jitArena, error)        { return &jitArena{}, nil }
func (*jitArena) add([]byte) (uintptr, bool)    { return 0, false }
func (*jitArena) reset()                        {}
func (*jitArena) patch(uintptr, uintptr)        {}
func (*jitArena) release()                      {}
func jitEnter(uintptr, *CPU, *Machine, *jitCtx) { panic("power: no native JIT on this platform") }
func jitPointer[T any](s []T) uintptr           { return 0 }
