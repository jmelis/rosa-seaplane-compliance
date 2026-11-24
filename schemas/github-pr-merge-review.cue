// Shape of the evidence RSC.CMT.CTRL01.AR02 is evaluated against: recent
// merges to a GitHub repository's default branch, as fetched by
// evidence/*.sh. Matches tests/fixtures/RSC.CMT.CTRL01.AR02/{pass,fail}.json.
//
// window_days/number use `number` rather than `int`: complypack's JSON
// test-data loader decodes all numbers as float64, so CUE's strict `int`
// kind rejects them even for whole-valued integers (e.g. 30 becomes a CUE
// float literal, not an int literal).
assessment_requirement: string
generated_at:           string
repository:             string
base_ref:               string
window_days:            number
pull_requests: [...{
	number:             number
	merged_at:          string
	author:             string
	merged_by:          string
	// True when the author is a bot account. A bot that labels its own PR has no
	// human approver; the policy decides what that means.
	author_is_bot:      bool
	// Facts for the documented automation exemption (config/automation.yaml). The
	// collector reports them; the policy decides.
	automated_change: {
		author_allowlisted:         bool
		gate_defined:               bool
		gate_labels_present:        bool
		merged_by_merge_automation: bool
		all_commits_by_author:      bool
	}
	// Normalized by the collector from GitHub reviews and Prow /lgtm history:
	// accounts other than the (non-bot) author that approved the change.
	approved_by:        [...string]
	approval_sources:   [..."github-review" | "prow"]
	// True when the comment/review history had more than one page, so an
	// approval could be missing from the evidence.
	history_truncated:  bool
	status_check_state: string
}]
