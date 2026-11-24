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
# schema: schemas/github-pr-merge-review.cue
package rosa_seaplane.change_management.github_default_branch_merge_review

import rego.v1

applies if input.assessment_requirement == "RSC.CMT.CTRL01.AR02"

# Approval is normalized by the collector (GitHub reviews and Prow commands both
# end up in approved_by), so this rule does not care how the team approves. The
# author is filtered again here: an author's own approval never counts.
approvers(pr) := {a | some a in pr.approved_by; a != pr.author}

# A change by an allowlisted automation identity counts as approved by automation
# only when every fact holds (see config/automation.yaml): the repo's merge bot
# has a dedicated approval-requiring rule for that author, the approval labels are
# present, the merge bot merged it, and every commit is the author's own and
# signed. Failing status checks are still denied by their own rule below.
automation_facts := {"author_allowlisted", "gate_defined", "gate_labels_present", "merged_by_merge_automation", "all_commits_by_author"}

automation_exempt(pr) if {
	every fact in automation_facts {
		pr.automated_change[fact] == true
	}
}

unmet_automation_facts(pr) := sort([f | some f in automation_facts; not pr.automated_change[f] == true])

deny contains msg if {
	applies
	some pr in input.pull_requests
	count(approvers(pr)) == 0
	not automation_exempt(pr)
	msg := sprintf(
		"%s: PR #%d (%s) merged to %s without a non-author approval%s",
		[input.repository, pr.number, pr.author, input.base_ref, truncation_note(pr)],
	)
}

truncation_note(pr) := " (comment history was truncated, so an approval may be missing from the evidence)" if {
	pr.history_truncated == true
} else := sprintf(" (automation exemption not met, missing: %s)", [concat(", ", unmet_automation_facts(pr))]) if {
	pr.automated_change.author_allowlisted == true
} else := " (the author is a bot, so any approval labels were applied by the bot itself)" if {
	pr.author_is_bot == true
} else := ""

deny contains msg if {
	applies
	some pr in input.pull_requests
	pr.author == pr.merged_by
	msg := sprintf(
		"%s: PR #%d merged to %s by its own author (%s), bypassing the merge gate",
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
