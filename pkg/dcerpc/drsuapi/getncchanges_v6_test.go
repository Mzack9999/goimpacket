// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package drsuapi

import "testing"

func TestFirstRDNValue(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "Administrator,CN=Users,DC=example,DC=com", "Administrator"},
		{"no comma", "Administrator", "Administrator"},
		{"empty", "", ""},
		{"escaped comma", `Smith\, John,OU=Foo,DC=example`, "Smith, John"},
		{"escaped equals", `O\=ops,OU=Foo`, "O=ops"},
		{"escaped backslash", `back\\slash,OU=Foo`, `back\slash`},
		{"multiple escapes", `a\,b\,c,OU=Foo`, "a,b,c"},
		{"trailing backslash", `oops\`, "oops"},
		{"only escape", `\,`, ","},
		{"escape then end", `x\,`, "x,"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := firstRDNValue(tc.in)
			if got != tc.want {
				t.Errorf("firstRDNValue(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestCheckBounds(t *testing.T) {
	t.Run("fits exactly", func(t *testing.T) {
		d := NewDecoder(make([]byte, 64))
		if !d.CheckBounds(8, 8, "exact") {
			t.Fatalf("CheckBounds should accept count*size == remaining; err=%v", d.Err())
		}
		if d.Err() != nil {
			t.Fatalf("unexpected err: %v", d.Err())
		}
	})

	t.Run("rejects overflow of remaining", func(t *testing.T) {
		d := NewDecoder(make([]byte, 31))
		if d.CheckBounds(4, 8, "overflow") {
			t.Fatal("CheckBounds should reject 4*8=32 against 31 remaining")
		}
		if d.Err() == nil {
			t.Fatal("expected sticky error")
		}
	})

	t.Run("uint64 product is safe", func(t *testing.T) {
		// count near MaxUint32 * non-trivial elemSize would overflow int on
		// 32-bit builds. The check must reject before any int cast.
		d := NewDecoder(make([]byte, 100))
		if d.CheckBounds(1<<31, 8, "huge product") {
			t.Fatal("CheckBounds should reject pathologically large product")
		}
	})

	t.Run("zero count always fits", func(t *testing.T) {
		d := NewDecoder(nil)
		if !d.CheckBounds(0, 32, "empty") {
			t.Fatalf("CheckBounds(0, 32) on empty buffer should pass; err=%v", d.Err())
		}
	})

	t.Run("prior error is sticky", func(t *testing.T) {
		d := NewDecoder(make([]byte, 1024))
		d.Fail("seeded failure")
		if d.CheckBounds(1, 1, "post-failure") {
			t.Fatal("CheckBounds must return false when decoder already failed")
		}
		// And the original error must be preserved.
		if got := d.Err().Error(); got != "seeded failure" {
			t.Fatalf("original error overwritten: %v", got)
		}
	})

	t.Run("subsequent reads are no-ops after failure", func(t *testing.T) {
		d := NewDecoder(make([]byte, 4))
		if d.CheckBounds(10, 8, "trigger") {
			t.Fatal("expected failure")
		}
		// Decoder must now zero-return on reads.
		if v := d.ReadUint32(); v != 0 {
			t.Fatalf("expected 0 after failure, got %d", v)
		}
	})
}
