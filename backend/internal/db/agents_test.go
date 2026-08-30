package db

import "testing"

func TestBuildTarget(t *testing.T) {
	for in, want := range map[[2]string]string{{"linux", "x86_64"}: "linux-amd64", {"Linux", "amd64"}: "linux-amd64", {"windows", "x86_64"}: "windows-amd64", {"darwin", "x86_64"}: "", {"linux", "aarch64"}: ""} {
		if got := BuildTarget(in[0], in[1]); got != want {
			t.Errorf("%v: got %q want %q", in, got, want)
		}
	}
}
