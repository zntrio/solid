// Licensed to SolID under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. SolID licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package token

import (
	sessionv1 "zntr.io/solid/api/oidc/session/v1"
)

// devicePollTiming adapts the device code session's poll-throttle fields
// (RFC 8628 sections 3.2/3.5) to the shared pollTiming accessor pair.
func devicePollTiming(s *sessionv1.DeviceCodeSession) pollTiming {
	return pollTiming{
		getInterval: func() int64 { return int64(s.PollInterval) }, //nolint:gosec // bounded protocol value
		setInterval: func(v int64) { s.PollInterval = uint64(v) },  //nolint:gosec // bounded protocol value
		getLast:     func() int64 { return int64(s.LastPolledAt) }, //nolint:gosec // epoch seconds fit int64
		setLast:     func(v int64) { s.LastPolledAt = uint64(v) },  //nolint:gosec // epoch seconds fit int64
	}
}

// backchannelPollTiming adapts the backchannel authentication session's
// poll-throttle fields (OpenID CIBA Core 1.0 sections 7.3/11) to the shared
// pollTiming accessor pair.
func backchannelPollTiming(s *sessionv1.BackchannelAuthenticationSession) pollTiming {
	return pollTiming{
		getInterval: func() int64 { return int64(s.PollInterval) }, //nolint:gosec // bounded protocol value
		setInterval: func(v int64) { s.PollInterval = uint64(v) },  //nolint:gosec // bounded protocol value
		getLast:     func() int64 { return int64(s.LastPolledAt) }, //nolint:gosec // epoch seconds fit int64
		setLast:     func(v int64) { s.LastPolledAt = uint64(v) },  //nolint:gosec // epoch seconds fit int64
	}
}
