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

package pairwise

import "testing"

func Test_hashEncoder_Encode(t *testing.T) {
	type fields struct {
		salt []byte
	}
	type args struct {
		sectorID string
		subject  string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name: "salt too short",
			fields: fields{
				salt: []byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
			},
			wantErr: true,
		},
		{
			name: "blank subject",
			fields: fields{
				salt: []byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
			},
			args: args{
				subject: "    ",
			},
			wantErr: true,
		},
		{
			name: "empty subject",
			fields: fields{
				salt: []byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
			},
			args: args{
				subject: "",
			},
			wantErr: true,
		},
		{
			name: "salt-16",
			fields: fields{
				salt: []byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
			},
			args: args{
				subject: "test",
			},
			want:    "B1Rgoyp3WChu145vxTBiczt8blE1Z2JFAmAO_vLTd_g",
			wantErr: false,
		},
		{
			name: "salt-32",
			fields: fields{
				salt: []byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
			},
			args: args{
				subject: "test",
			},
			want:    "m9C5Rbk-7DJw7B34_QhnBk1bIrjFzHt2S-XWEA4k8UM",
			wantErr: false,
		},
		{
			name: "salt-64",
			fields: fields{
				salt: []byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
			},
			args: args{
				subject: "test",
			},
			want:    "yRERMm_YJ0cNphNgEa9P-QbXW1zL8CEDwfApDkOepyU",
			wantErr: false,
		},
		{
			name: "salt too long",
			fields: fields{
				salt: []byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
			},
			args: args{
				subject: "test",
			},
			wantErr: true,
		},
		{
			name: "alternative sector id",
			fields: fields{
				salt: []byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
			},
			args: args{
				subject:  "test",
				sectorID: "http://backend.exmaple.com",
			},
			want:    "pR8ec4YcFV5MXaHAyWrGTWiWVnDg_JiJchFtcQrr3cU",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := Hash(tt.fields.salt)
			got, err := tr.Encode(tt.args.sectorID, tt.args.subject)
			if (err != nil) != tt.wantErr {
				t.Errorf("hashEncoder.Encode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("hashEncoder.Encode() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test_hashEncoder_Encode_sectorFraming pins the unambiguous framing of the
// sector identifier: naive concatenation would make ("ab","c") and ("a","bc")
// collide into the same pairwise subject.
func Test_hashEncoder_Encode_sectorFraming(t *testing.T) {
	salt := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	tr := Hash(salt)

	first, err := tr.Encode("ab", "c")
	if err != nil {
		t.Fatalf("Encode(ab, c) error = %v", err)
	}
	second, err := tr.Encode("a", "bc")
	if err != nil {
		t.Fatalf("Encode(a, bc) error = %v", err)
	}
	if first == second {
		t.Errorf("sector/subject boundary collision: Encode(ab,c) == Encode(a,bc) == %s", first)
	}
}
