// Copyright 2022 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dhcp

import (
	"testing"

	"github.com/vcore8/fingerprintx/pkg/test"
)

func TestDHCP(t *testing.T) {
	// cwd, err := os.Getwd()
	// if err != nil {
	// 	t.Fatalf("failed to get current directory")
	// }
	// TODO more work is required to get this test working locally
	testcases := []test.Testcase{
		// {
		// 	Description: "dhcp",
		// 	Port:        67,
		// 	Protocol:    plugins.UDP,
		// 	Expected: func(res *plugins.PluginResults) bool {
		// 		return res != nil
		// 	},
		// 	RunConfig: dockertest.RunOptions{
		// 		Repository:   "wastrachan/dhcpd",
		// 		Mounts:       []string{fmt.Sprintf("%s/dhcpd.conf:/config/dhcpd.conf", cwd)},
		// 		ExposedPorts: []string{"67/udp"},
		// 	},
		// },
	}

	var p *Plugin

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Description, func(t *testing.T) {
			t.Parallel()
			err := test.RunTest(t, tc, p)
			if err != nil {
				t.Errorf(err.Error())
			}
		})
	}
}
