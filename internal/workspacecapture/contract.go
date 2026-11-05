package workspacecapture

import (
	"commonroom-runtime/internal/taskcontract"
	"commonroom-runtime/internal/workspacesnapshot"
	"reflect"
	"sort"
)

// ContractRequest derives finite capture members from the exact task definition.
// All required file/bundle outputs are included. optionalOutputs may name only
// explicitly chosen optional file/bundle outputs, never values or arbitrary paths.
// This validates metadata only: current human/task/export authority, frozen source,
// quotas and durable journals remain mandatory. No root, launch or read is opened.
func ContractRequest(definition taskcontract.Definition, binding workspacesnapshot.Binding, challenge string, optionalOutputs []string) (Request, error) {
	if taskcontract.Validate(definition) != nil || binding.Execution.DefinitionDigest != taskcontract.Digest(definition) || len(optionalOutputs) > len(definition.DesiredOutputs) {
		return Request{}, ErrRefused
	}
	selected := map[string]bool{}
	for _, name := range optionalOutputs {
		if selected[name] {
			return Request{}, ErrRefused
		}
		selected[name] = true
	}
	members := []workspacesnapshot.Member{}
	for _, output := range definition.DesiredOutputs {
		file := output.Type == "file" || output.Type == "bundle"
		if selected[output.Name] && (output.Required || !file) {
			return Request{}, ErrRefused
		}
		if !file || !output.Required && !selected[output.Name] {
			continue
		}
		delete(selected, output.Name)
		if output.Type == "file" {
			members = append(members, workspacesnapshot.Member{OutputName: output.Name, Name: output.FileName, MaxBytes: output.MaxBytes})
		} else {
			for _, member := range output.Members {
				members = append(members, workspacesnapshot.Member{OutputName: output.Name, Name: member.Name, MaxBytes: member.MaxBytes})
			}
		}
	}
	if len(selected) != 0 {
		return Request{}, ErrRefused
	}
	sort.Slice(members, func(i, j int) bool {
		if members[i].OutputName != members[j].OutputName {
			return members[i].OutputName < members[j].OutputName
		}
		return members[i].Name < members[j].Name
	})
	request := Request{Binding: binding, Members: members, Challenge: challenge}
	if _, err := RequestDigest(request); err != nil {
		return Request{}, ErrRefused
	}
	return request, nil
}

// ValidateContractRequest requires the exact canonical selection, definition digest,
// required outputs, member identities and limits. A trusted parent authority MUST
// compare against its independently loaded current definition, never one supplied
// by the helper/model. It grants no authority and performs no I/O.
func ValidateContractRequest(definition taskcontract.Definition, request Request) error {
	if len(request.Members) < 1 || len(request.Members) > workspacesnapshot.MaxMembers || taskcontract.Validate(definition) != nil {
		return ErrRefused
	}
	optional := []string{}
	seen := map[string]bool{}
	for _, m := range request.Members {
		if !seen[m.OutputName] {
			seen[m.OutputName] = true
			for _, output := range definition.DesiredOutputs {
				if output.Name == m.OutputName && !output.Required {
					optional = append(optional, output.Name)
				}
			}
		}
	}
	expected, err := ContractRequest(definition, request.Binding, request.Challenge, optional)
	if err != nil || !reflect.DeepEqual(expected, request) {
		return ErrRefused
	}
	return nil
}
