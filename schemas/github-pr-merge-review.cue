// Shape of the evidence RSC.CMT.CTRL01.AR02 is evaluated against: recent
// merges to a GitHub repository's default branch, as fetched by
// evidence/*.sh. Matches tests/fixtures/RSC.CMT.CTRL01.AR02/{pass,fail}.json.
//
// window_days/number use `number` rather than `int`: complypack's JSON
// test-data loader decodes all numbers as float64, so CUE's strict `int`
// kind rejects them even for whole-valued integers (e.g. 30 becomes a CUE
// float literal, not an int literal).
generated_at: string
repository:   string
base_ref:     string
window_days:  number
pull_requests: [...{
	number:             number
	merged_at:          string
	author:             string
	merged_by:          string
	review_decision:    string
	status_check_state: string
}]
