# Unit tests for RSC.CMT.CTRL01.AR02. Run with `conftest verify` (or `make test`).
# Not shipped in the complypack: scripts/publish-complypack.sh skips *_test.rego.

package rosa_seaplane.change_management.github_default_branch_merge_review

import rego.v1

compliant_pr := {
	"number": 201,
	"author": "alice",
	"merged_by": "bob",
	"approved_by": ["bob"],
	"approval_sources": ["github-review"],
	"history_truncated": false,
	"status_check_state": "SUCCESS",
}

base := {
	"assessment_requirement": "RSC.CMT.CTRL01.AR02",
	"repository": "openshift-online/example",
	"base_ref": "main",
}

test_github_approval_passes if {
	count(deny) == 0 with input as object.union(base, {"pull_requests": [compliant_pr]})
}

test_prow_approval_passes if {
	pr := object.union(compliant_pr, {"approved_by": ["dave"], "approval_sources": ["prow"], "merged_by": "openshift-merge-bot"})
	count(deny) == 0 with input as object.union(base, {"pull_requests": [pr]})
}

test_no_approval_is_denied if {
	pr := object.union(compliant_pr, {"approved_by": [], "approval_sources": []})
	violations := deny with input as object.union(base, {"pull_requests": [pr]})
	some msg in violations
	contains(msg, "without a non-author approval")
}

test_self_approval_is_denied if {
	pr := object.union(compliant_pr, {"approved_by": ["alice"], "approval_sources": ["prow"]})
	violations := deny with input as object.union(base, {"pull_requests": [pr]})
	some msg in violations
	contains(msg, "without a non-author approval")
}

test_self_approval_among_others_still_needs_a_non_author if {
	pr := object.union(compliant_pr, {"approved_by": ["alice", "bob"]})
	count(deny) == 0 with input as object.union(base, {"pull_requests": [pr]})
}

test_truncated_history_is_noted if {
	pr := object.union(compliant_pr, {"approved_by": [], "history_truncated": true})
	violations := deny with input as object.union(base, {"pull_requests": [pr]})
	some msg in violations
	contains(msg, "history was truncated")
}

test_self_merge_is_denied if {
	violations := deny with input as {
		"assessment_requirement": "RSC.CMT.CTRL01.AR02",
		"repository": "openshift-online/example",
		"base_ref": "main",
		"pull_requests": [object.union(compliant_pr, {"merged_by": "alice"})],
	}
	some msg in violations
	contains(msg, "by its own author")
}

test_failing_checks_is_denied if {
	violations := deny with input as {
		"assessment_requirement": "RSC.CMT.CTRL01.AR02",
		"repository": "openshift-online/example",
		"base_ref": "main",
		"pull_requests": [object.union(compliant_pr, {"status_check_state": "FAILURE"})],
	}
	some msg in violations
	contains(msg, "non-passing status checks")
}

test_empty_window_is_denied if {
	violations := deny with input as {"assessment_requirement": "RSC.CMT.CTRL01.AR02", "repository": "openshift-online/example", "base_ref": "main", "pull_requests": []}
	some msg in violations
	contains(msg, "no merged pull requests found")
}

test_ignores_other_ars_evidence if {
	count(deny) == 0 with input as {
		"assessment_requirement": "RSC.CMT.CTRL01.AR01",
		"repository": "openshift-online/example",
		"branch": "main",
		"protection": {},
	}
}

test_deny_message_names_repo if {
	violations := deny with input as {
		"assessment_requirement": "RSC.CMT.CTRL01.AR02",
		"repository": "openshift-online/example",
		"base_ref": "main",
		"pull_requests": [],
	}
	some msg in violations
	contains(msg, "openshift-online/example")
}
