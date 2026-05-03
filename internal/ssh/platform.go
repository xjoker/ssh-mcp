package ssh

import "os"

// sshAuthSock returns the SSH_AUTH_SOCK environment variable value,
// which points to the Unix-domain socket of the SSH agent.
func sshAuthSock() string {
	return os.Getenv("SSH_AUTH_SOCK")
}
