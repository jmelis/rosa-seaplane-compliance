// Shape of the evidence RSC.CMT.CTRL01.AR01 is evaluated against: a GitHub
// repository's branch-protection config, as fetched by evidence/*.sh.
// Matches tests/fixtures/RSC.CMT.CTRL01.AR01/{pass,fail}.json.
//
// required_approving_review_count uses `number` rather than `int`: complypack's
// JSON test-data loader decodes all numbers as float64, so CUE's strict `int`
// kind rejects them even for whole-valued integers.
generated_at: string
repository:   string
branch:       string
protection: {
	required_pull_request_reviews: {
		required_approving_review_count: number
		dismiss_stale_reviews?:          bool
		require_code_owner_reviews?:     bool
	}
	required_status_checks: null | {
		strict:    bool
		contexts: [...string]
	}
	enforce_admins: {
		enabled: bool
	}
	allow_force_pushes: {
		enabled: bool
	}
	allow_deletions: {
		enabled: bool
	}
	required_linear_history: {
		enabled: bool
	}
}
