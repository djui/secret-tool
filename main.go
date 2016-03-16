// OS X port of Linux secret-tool for Gnome
// See https://www.mankier.com/1/secret-tool

package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/codegangsta/cli"
)

// secret-tool lookup pdftables STRIPE_SECRET_KEY)

func main() {
	s := &security{}

	app := cli.NewApp()
	app.Name = "secret-tool"
	app.Usage = "Store and retrieve passwords"
	app.Commands = []cli.Command{
		{
			Name:      "lookup",
			Usage:     "Lookup a password",
			ArgsUsage: "[attribute value...]",
			Before: func(c *cli.Context) error {
				if len(c.Args()) < 2 {
					return errors.New("Missing arguments")
				}
				return nil
			},
			Action: func(c *cli.Context) {
				service := c.Args().Get(0)
				account := c.Args().Get(1)
				pass, err := s.findGenericPassword(account, service, false, true)
				if err != nil {
					log.Println("Error:", err)
					os.Exit(s.exitCode)
				}
				fmt.Println(pass)
			},
		},
		{
			Name:      "store",
			Usage:     "Store a password",
			ArgsUsage: "[attribute value...]",
			Before: func(c *cli.Context) error {
				if len(c.Args()) < 2 {
					return errors.New("Missing arguments")
				}
				if !c.IsSet("label") {
					return errors.New("Missing flag label")
				}
				return nil
			},
			Action: func(c *cli.Context) {
				service := c.Args().Get(0)
				account := c.Args().Get(1)
				label := c.String("label")
				password, err := passwordFromStdin("Password: ")
				if err != nil {
					log.Println("Error:", err)
				}
				err = s.addGenericPassword(account, service, label, password)
				if err != nil {
					log.Println("Error:", err)
					os.Exit(s.exitCode)
				}
			},
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "label",
					Usage: "Label",
				},
			},
		},
		{
			Name:      "search",
			Usage:     "Search a password",
			ArgsUsage: "[attribute value...]",
			Before: func(c *cli.Context) error {
				if len(c.Args()) < 2 {
					return errors.New("Missing arguments")
				}
				return nil
			},
			Action: func(c *cli.Context) {
				service := c.Args().Get(0)
				account := c.Args().Get(1)
				all := c.Bool("all")
				unlock := c.Bool("unlock")
				pass, err := s.findGenericPassword(account, service, all, unlock)
				if err != nil {
					log.Println("Error:", err)
					os.Exit(s.exitCode)
				}
				fmt.Println(pass)
			},
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "all",
					Usage: "All",
				},
				cli.BoolFlag{
					Name:  "unlock",
					Usage: "Unlock",
				},
			},
		},
		{
			Name:      "clear",
			Usage:     "Remove a password",
			ArgsUsage: "[attribute value...]",
			Before: func(c *cli.Context) error {
				if len(c.Args()) < 2 {
					return errors.New("Missing arguments")
				}
				return nil
			},
			Action: func(c *cli.Context) {
				service := c.Args().Get(0)
				account := c.Args().Get(1)
				err := s.deleteGenericPassword(account, service)
				if err != nil {
					log.Println("Error:", err)
					os.Exit(s.exitCode)
				}
			},
		},
	}

	app.RunAndExitOnError()
}

type security struct {
	keychain string
	exitCode int
}

func (s *security) findGenericPassword(account, service string, all, unlock bool) (string, error) {
	// TODO(uwe): use all & unlock
	var buf bytes.Buffer
	cmd := exec.Command("/usr/bin/security", "find-generic-password",
		"-a", account,
		"-s", service,
		"-g")
	cmd.Stderr = &buf
	err := cmd.Run()

	s.exitCode = exitCode(err)
	if err != nil {
		return "", firstLineError(buf.Bytes())
	}

	out := buf.Bytes()
	// password: "..."\n
	pass := string(out[11 : len(out)-2])
	return pass, nil
}

func (s *security) addGenericPassword(account, service, label, password string) error {
	cmd := exec.Command("/usr/bin/security", "add-generic-password",
		"-a", account,
		"-s", service,
		"-l", label,
		"-w", password,
		"-U")
	err := cmd.Run()
	s.exitCode = exitCode(err)
	return execError(err)
}

func (s *security) deleteGenericPassword(account, service string) error {
	cmd := exec.Command("/usr/bin/security", "delete-generic-password",
		"-a", account,
		"-s", service)
	err := cmd.Run()
	s.exitCode = exitCode(err)
	return execError(err)
}

func passwordFromStdin(prompt string) (string, error) {
	if terminal.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Print(prompt)
		p, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return "", err
		}
		return string(p), nil
	}

	in := bufio.NewReader(os.Stdin)
	p, err := in.ReadString('\n')
	if err != nil {
		return "", err
	}
	return string(p[:len(p)-1]), nil
}

func exitCode(err error) int {
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				return status.ExitStatus()
			}
		}
		return 1
	}
	return 0
}

func execError(err error) error {
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return firstLineError(exitErr.Stderr)
		}
	}
	return err
}

func firstLineError(b []byte) error {
	lines := bytes.Split(b, []byte("\n"))
	if len(lines) > 0 {
		return errors.New(string(lines[0]))
	}
	return nil
}
