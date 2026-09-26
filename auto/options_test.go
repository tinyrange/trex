package auto

import "testing"

func TestStreamingMaximumDefaultAndExplicit(t *testing.T) {
	for _, input := range []int64{0, 17, 512 << 20} {
		o := Options{MaxExpandedBytes: input}
		for i := 0; i < 4; i++ {
			o = o.defaults()
			if got := o.StreamingMaximum(); got != input {
				t.Fatalf("normalization %d, input %d: %d", i, input, got)
			}
			if o.MaxExpandedBytes <= 0 {
				t.Fatal("eager cap missing")
			}
		}
	}
	o := (Options{}).defaults()
	o.MaxExpandedBytes = 123
	if o.defaults().StreamingMaximum() != 123 {
		t.Fatal("changed explicit limit ignored")
	}
}

func TestWithExpandedMaximumOverridesDefaultProvenance(t *testing.T) {
	source := &SourceContext{}
	o := (Options{Source: source, MaxEntries: 7, MaxDepth: 3}).defaults()
	for _, maximum := range []int64{512 << 20, 123, 0, -1} {
		changed := o.WithExpandedMaximum(maximum).defaults()
		want := max(maximum, 0)
		if changed.StreamingMaximum() != want {
			t.Fatalf("maximum %d: streaming limit %d", maximum, changed.StreamingMaximum())
		}
		if changed.Source != source || changed.MaxEntries != 7 || changed.MaxDepth != 3 {
			t.Fatal("other options changed")
		}
		if maximum <= 0 && changed.MaxExpandedBytes != 512<<20 {
			t.Fatal("default eager bound lost")
		}
	}
	if o.StreamingMaximum() != 0 {
		t.Fatal("original options mutated")
	}
}
