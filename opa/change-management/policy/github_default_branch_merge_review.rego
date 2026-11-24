# RSC.CMT.CTRL01.AR02: every merge to the default branch must carry a
# non-author approval and pass required checks. Input: the flattened JSON
# from evidence/RSC.CMT.CTRL01.AR02.sh. Package name must match the "id"
# in complytime-mapping.json. Does NOT detect admin-bypass merges, see
# README "Known gaps".
#
# The opa provider evaluates every mapped package against every file in the
# target's input_path, so each rule is guarded on the evidence's own
# assessment_requirement (see github_default_branch_protection.rego).

# platform: github-pr-merge-review
package rosa_seaplane.change_management.github_default_branch_merge_review

import rego.v1

applies if input.assessment_requirement == "RSC.CMT.CTRL01.AR02"

deny contains msg if {
	applies
	some pr in input.pull_requests
	pr.review_decision != "APPROVED"
	msg := sprintf(
		"%s: PR #%d (%s) merged to %s without an approved review (review_decision=%s)",
		[input.repository, pr.number, pr.author, input.base_ref, pr.review_decision],
	)
}

deny contains msg if {
	applies
	some pr in input.pull_requests
	pr.author == pr.merged_by
	msg := sprintf(
		"%s: PR #%d merged to %s by its own author (%s): no non-author approval is possible",
		[input.repository, pr.number, input.base_ref, pr.author],
	)
}

deny contains msg if {
	applies
	some pr in input.pull_requests
	pr.status_check_state != "SUCCESS"
	msg := sprintf(
		"%s: PR #%d merged to %s with non-passing status checks (status_check_state=%s)",
		[input.repository, pr.number, input.base_ref, pr.status_check_state],
	)
}

# Empty pull_requests would otherwise vacuously "pass" every rule above.
deny contains msg if {
	applies
	count(input.pull_requests) == 0
	msg := sprintf(
		"%s: no merged pull requests found against %s in the evaluation window, cannot demonstrate the control; verify evidence/RSC.CMT.CTRL01.AR02.sh ran successfully and GITHUB_TOKEN has read access",
		[input.repository, input.base_ref],
	)
}
