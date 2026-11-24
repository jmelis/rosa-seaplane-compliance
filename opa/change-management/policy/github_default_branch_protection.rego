# RSC.CMT.CTRL01.AR01: the default branch's protection configuration must
# require a pull request with at least one approving review and passing status
# checks, forbid force-pushes, and apply to administrators. Input: the JSON from
# evidence/RSC.CMT.CTRL01.AR01.sh. Package name must match the "id" in
# complytime-mapping.json.
#
# The opa provider evaluates every mapped package against every file in the
# target's input_path, so each rule is guarded on the evidence's own
# assessment_requirement. A missing evidence file therefore produces no denials;
# containers/complyctl/entrypoint.py fails the run when an AR has no evidence.

# platform: github-branch-protection
package rosa_seaplane.change_management.github_default_branch_protection

import rego.v1

applies if input.assessment_requirement == "RSC.CMT.CTRL01.AR01"

deny contains msg if {
	applies
	input.protected == false
	msg := sprintf("%s: %s has no branch protection configured", [input.repository, input.branch])
}

deny contains msg if {
	applies
	not review_required
	msg := sprintf(
		"%s: required_pull_request_reviews is missing, null, or required_approving_review_count is 0 on %s",
		[input.repository, input.branch],
	)
}

review_required if {
	input.protection.required_pull_request_reviews.required_approving_review_count >= 1
}

deny contains msg if {
	applies
	not status_checks_required
	msg := sprintf(
		"%s: required_status_checks is missing, null, or has no contexts on %s",
		[input.repository, input.branch],
	)
}

status_checks_required if {
	count(input.protection.required_status_checks.contexts) > 0
}

deny contains msg if {
	applies
	not input.protection.allow_force_pushes.enabled == false
	msg := sprintf(
		"%s: allow_force_pushes.enabled is true (or missing) on %s",
		[input.repository, input.branch],
	)
}

deny contains msg if {
	applies
	not input.protection.enforce_admins.enabled == true
	msg := sprintf(
		"%s: enforce_admins.enabled is false (or missing) on %s, so administrators can bypass the protection",
		[input.repository, input.branch],
	)
}
