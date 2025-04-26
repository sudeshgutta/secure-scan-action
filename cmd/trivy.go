package cmd

import (
	"os"
	"os/exec"
)

func RunTrivy(severity string) error {
	cmd := exec.Command("trivy", "fs", "--exit-code", "1", "--severity", severity, "--no-progress", ".")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
