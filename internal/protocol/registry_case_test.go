package protocol

import (
	"bytes"
	"testing"
)

func TestRegistryCaseFlagPayloadExcludesGeneratedCaseID(t *testing.T) {
	first := RegistryCasePayloadMessage(
		RegistryCaseActionFlag,
		"case_first",
		RegistryCaseSubjectDeployment,
		"dep_subject",
		"qmau-anomaly",
		RegistryCaseSeverityWarning,
		ZeroHash,
		"review:1",
		"review-team",
	)
	second := RegistryCasePayloadMessage(
		RegistryCaseActionFlag,
		"case_second",
		RegistryCaseSubjectDeployment,
		"dep_subject",
		"qmau-anomaly",
		RegistryCaseSeverityWarning,
		ZeroHash,
		"review:1",
		"review-team",
	)
	if !bytes.Equal(first, second) {
		t.Fatal("registry-generated flag case ID changed the idempotent caller payload")
	}
}

func TestRegistryCaseClearPayloadCommitsTargetCaseID(t *testing.T) {
	first := RegistryCasePayloadMessage(
		RegistryCaseActionClear,
		"case_first",
		RegistryCaseSubjectDeployment,
		"dep_subject",
		"qmau-anomaly",
		RegistryCaseSeverityWarning,
		ZeroHash,
		"resolution:1",
		"review-team",
	)
	second := RegistryCasePayloadMessage(
		RegistryCaseActionClear,
		"case_second",
		RegistryCaseSubjectDeployment,
		"dep_subject",
		"qmau-anomaly",
		RegistryCaseSeverityWarning,
		ZeroHash,
		"resolution:1",
		"review-team",
	)
	if bytes.Equal(first, second) {
		t.Fatal("registry case clear payload did not bind the target case")
	}
}
