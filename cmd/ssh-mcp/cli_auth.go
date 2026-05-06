package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"os"

	"golang.org/x/term"

	"github.com/xjoker/ssh-mcp/internal/auth"
	"github.com/xjoker/ssh-mcp/internal/config"
)

// authService is the fixed keychain service name used by all auth subcommands.
const authService = "ssh-mcp"

func init() { registerSubcommand("auth", authCmd) }

func authCmd(args []string) int {
	fs := flag.NewFlagSet("auth", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ssh-mcp auth <subcommand> [options]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Subcommands:")
		fmt.Fprintln(os.Stderr, "  set <name>    Store a secret in the OS keychain")
		fmt.Fprintln(os.Stderr, "  get <name>    Check whether a secret is stored (does not print value)")
		fmt.Fprintln(os.Stderr, "  remove <name> Delete a secret from the OS keychain")
		fmt.Fprintln(os.Stderr, "  list          List stored accounts (not supported on all platforms)")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Non-interactive usage (AI assistants / CI):")
		fmt.Fprintln(os.Stderr, "  SSH_MCP_SECRET=<secret> ssh-mcp auth set <name>")
	}

	if len(args) == 0 {
		fs.Usage()
		return 1
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "set":
		return authSetCmd(subArgs)
	case "get":
		return authGetCmd(subArgs)
	case "remove":
		return authRemoveCmd(subArgs)
	case "list":
		return authListCmd(subArgs)
	default:
		fmt.Fprintf(os.Stderr, "auth: unknown subcommand %q\n", sub)
		fs.Usage()
		return 1
	}
}

// --------------------------------------------------------------------------
// auth set
// --------------------------------------------------------------------------

func authSetCmd(args []string) int {
	fs := flag.NewFlagSet("auth set", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return 1
	}

	remaining := fs.Args()
	if len(remaining) == 0 {
		fmt.Fprintln(os.Stderr, "auth set: missing account name")
		return 1
	}
	account := remaining[0]

	// Non-interactive path: SSH_MCP_SECRET env var (for AI assistants / CI).
	var secret []byte
	if envSecret := os.Getenv("SSH_MCP_SECRET"); envSecret != "" {
		secret = []byte(envSecret)
	} else {
		// Interactive path: prompt with hidden input.
		var err error
		secret, err = readPasswordConfirmed(account)
		if err != nil {
			fmt.Fprintf(os.Stderr, "auth set: %v\n", err)
			fmt.Fprintln(os.Stderr, "Tip: in non-interactive contexts set SSH_MCP_SECRET=<secret> before running this command.")
			return 1
		}
	}
	defer func() {
		// Zero the secret bytes after use.
		for i := range secret {
			secret[i] = 0
		}
	}()

	if err := auth.SetKeychain(authService, account, secret); err != nil {
		fmt.Fprintf(os.Stderr, "auth set: %v\n", err)
		return 1
	}

	fmt.Printf("Secret stored for account %q (service: %s)\n", account, authService)
	return 0
}

// readPasswordConfirmed prompts for a password twice and returns the bytes if
// they match.
func readPasswordConfirmed(account string) ([]byte, error) {
	fd := int(os.Stdin.Fd())

	fmt.Printf("Enter secret for %q: ", account)
	first, err := term.ReadPassword(fd)
	fmt.Println()
	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}

	fmt.Printf("Confirm secret for %q: ", account)
	second, err := term.ReadPassword(fd)
	fmt.Println()
	if err != nil {
		return nil, fmt.Errorf("read password (confirm): %w", err)
	}

	// Use constant-time comparison to avoid timing side-channels and to
	// prevent the Go compiler from materialising an extra string copy
	// (which would be harder to zero from memory).
	if subtle.ConstantTimeCompare(first, second) != 1 {
		// Zero both slices before returning the error.
		for i := range first {
			first[i] = 0
		}
		for i := range second {
			second[i] = 0
		}
		return nil, fmt.Errorf("passwords do not match")
	}

	// Zero the confirmation copy; caller is responsible for zeroing first.
	for i := range second {
		second[i] = 0
	}

	return first, nil
}

// --------------------------------------------------------------------------
// auth get
// --------------------------------------------------------------------------

func authGetCmd(args []string) int {
	fs := flag.NewFlagSet("auth get", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return 1
	}

	remaining := fs.Args()
	if len(remaining) == 0 {
		fmt.Fprintln(os.Stderr, "auth get: missing account name")
		return 1
	}
	account := remaining[0]

	ref := config.CredRef{
		Kind:    config.CredRefKeychain,
		Service: authService,
		Account: account,
		Raw:     fmt.Sprintf("keychain:%s:%s", authService, account),
	}

	ctx := context.Background()
	secret, err := auth.Resolve(ctx, ref, false)
	if err != nil {
		if errors.Is(err, auth.ErrKeyNotFound) {
			fmt.Printf("Account: %s\nService: %s\nStored: no\n", account, authService)
			return 0
		}
		fmt.Fprintf(os.Stderr, "auth get: %v\n", err)
		fmt.Printf("Account: %s\nService: %s\nStored: no\n", account, authService)
		return 0
	}
	// Close the secret immediately — we don't print its value.
	secret.Close()

	fmt.Printf("Account: %s\nService: %s\nStored: yes\n", account, authService)
	return 0
}

// --------------------------------------------------------------------------
// auth remove
// --------------------------------------------------------------------------

func authRemoveCmd(args []string) int {
	fs := flag.NewFlagSet("auth remove", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return 1
	}

	remaining := fs.Args()
	if len(remaining) == 0 {
		fmt.Fprintln(os.Stderr, "auth remove: missing account name")
		return 1
	}
	account := remaining[0]

	if err := auth.DeleteKeychain(authService, account); err != nil {
		if errors.Is(err, auth.ErrKeyNotFound) {
			fmt.Fprintf(os.Stderr, "auth remove: account %q not found in keychain (service: %s)\n",
				account, authService)
			return 1
		}
		fmt.Fprintf(os.Stderr, "auth remove: %v\n", err)
		return 1
	}

	fmt.Printf("Secret removed for account %q (service: %s)\n", account, authService)
	return 0
}

// --------------------------------------------------------------------------
// auth list
// --------------------------------------------------------------------------

func authListCmd(_ []string) int {
	accounts, err := auth.ListKeychain(authService)
	if err != nil {
		fmt.Fprintf(os.Stderr, "auth list: %v\n", err)
		fmt.Fprintln(os.Stderr, "Tip: use 'auth get <name>' to check individual accounts.")
		return 1
	}
	// If somehow the backend does support it in future:
	if len(accounts) == 0 {
		fmt.Printf("No accounts found for service %q\n", authService)
		return 0
	}
	for _, a := range accounts {
		fmt.Println(a)
	}
	return 0
}
