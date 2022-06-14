package handlers

import "zntr.io/solid/sdk/types"

func optionalString(value string) *string {
	if value != "" {
		return types.StringRef(value)
	}
	return nil
}
