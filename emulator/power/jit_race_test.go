//go:build race

package power

// The race detector slows native-engine fuzzing; it checks fewer seeds.
const jitFuzzSeeds = 8
