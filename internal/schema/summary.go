package schema

import (
	"encoding/json"
	"sync"

	pub "github.com/peleduri/gop/schema"
)

var (
	summaryOnce sync.Once
	summaryC    *compiled
	summaryErr  error
)

// ValidateSummary checks a serialized gop.summary/v1 document against its
// published JSON Schema (schema/gop.summary.v1.schema.json). It returns the
// problems found; the error is only for a broken embedded schema.
func ValidateSummary(data []byte) ([]Problem, error) {
	summaryOnce.Do(func() { summaryC, summaryErr = compile(pub.SummaryV1) })
	if summaryErr != nil {
		return nil, summaryErr
	}
	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		return []Problem{{Pointer: "", Message: "not valid JSON: " + err.Error()}}, nil
	}
	ps := summaryC.validate(summaryC.root, doc, "")
	sortProblems(ps)
	return ps, nil
}
