package main

import (
	"fmt"
	"os"
	"os/exec"
)

func main() {
	severity := os.Getenv("INPUT_SEVERITY")
	if severity == "" {
		severity = "CRITICAL"
	}

	fmt.Println("Running filesystem scan...")

	cmd := exec.Command("trivy", "fs", "--exit-code", "1", "--severity", severity, "--no-progress", ".")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			fmt.Printf("Scan found vulnerabilities! Exiting with code %d\n", exitError.ExitCode())
			os.Exit(exitError.ExitCode())
		} else {
			fmt.Printf("Error running scanner: %v\n", err)
			os.Exit(2)
		}
	}

	fmt.Println("No vulnerabilities found!")
}
