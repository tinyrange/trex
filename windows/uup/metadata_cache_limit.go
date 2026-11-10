package uup

// SetLimit changes the shared decoded WIM/CAB budget for all stages using this
// cache. Existing readers remain valid; in-flight loads use the new limit on
// completion. Negative limits disable retention. Caller-held bytes and parser
// working memory are separate from this budget.
func (c *StageMetadataCache) SetLimit(maximumBytes int64) {
	if c != nil {
		c.store.SetLimit(maximumBytes)
	}
}
