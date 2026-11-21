package egress_route

import "testing"

func TestParseDefaultRouteDev(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "vyos default route",
			in:   "default nhid 20 via 192.168.1.1 dev eth0 proto static metric 20\n",
			want: "eth0",
		},
		{
			name: "first default wins",
			in:   "default via 10.0.0.1 dev wan0 metric 10\ndefault via 10.0.0.2 dev wan1 metric 20\n",
			want: "wan0",
		},
		{
			name: "no dev field",
			in:   "default via 10.0.0.1 metric 10\n",
			want: "",
		},
		{
			name: "empty",
			in:   "",
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseDefaultRouteDev(tc.in); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
