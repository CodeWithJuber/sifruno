// Package platform reports implementation scope, never inferred compatibility.
package platform

import "runtime"

type Profile struct {
	ID     string `json:"id"`
	OS     string `json:"os"`
	Label  string `json:"label"`
	Status string `json:"status"`
	Notes  string `json:"notes"`
}
type Report struct {
	OS                    string    `json:"os"`
	Arch                  string    `json:"arch"`
	OSName                string    `json:"os_name"`
	Mode                  string    `json:"mode"`
	ControlPlaneSupported bool      `json:"control_plane_supported"`
	HostingRuntime        string    `json:"hosting_runtime"`
	CompatibilityVerified bool      `json:"compatibility_verified"`
	Profiles              []Profile `json:"profiles"`
}

func Current() Report {
	name := map[string]string{"windows": "Windows", "linux": "Linux", "darwin": "macOS"}[runtime.GOOS]
	host := "linux-guest-required"
	if runtime.GOOS == "linux" {
		host = "linux-reference-required"
	}
	return Report{OS: runtime.GOOS, Arch: runtime.GOARCH, OSName: name, Mode: "native-control-plane", ControlPlaneSupported: name != "", HostingRuntime: host, Profiles: []Profile{
		{"windows-current", "windows", "Windows 10/11 and Server 2016+", "runtime-candidate", "Go runtime minimum. This host is tested; other versions require individual runtime checks. Original hosting ecosystem requires a Linux guest."},
		{"linux-current", "linux", "Current Linux distributions (kernel 3.2+)", "runtime-candidate", "CGO-free control plane builds. Distribution, libc-independent execution, kernel and filesystem behavior still need runtime checks; original hosting reference targets AlmaLinux/CloudLinux 9 x86_64."},
		{"mac-current", "darwin", "macOS 13+ (Intel and Apple Silicon)", "runtime-candidate", "Go 1.27 minimum. Builds are not runtime tests. Original x86_64 Linux hosting ecosystem requires a suitable Linux guest; ARM translation is unverified."},
		{"windows-legacy", "windows", "Older Windows and Windows Server", "legacy-connector-candidate", "XP, Vista, 7/8/8.1 and pre-2016 Server cannot run the current native build. Remote-browser access or a separately maintained connector must be qualified per version."},
		{"linux-legacy", "linux", "Older Linux distributions and kernels", "legacy-connector-candidate", "Compatibility depends on architecture, kernel, TLS, browser and service versions. Current native binaries require kernel 3.2+; older kernels need a qualified separate connector or guest."},
		{"mac-legacy", "darwin", "macOS 12 and earlier / historical OS X", "legacy-connector-candidate", "Current native build cannot cover these systems. Remote-browser access or a separately maintained connector must be qualified per version; historical CPUs are not built."},
	}}
}
