package knownhosts

var acquireKnownHostsFileLock = acquireKnownHostsLock

func acquireKnownHostsLock(path string) (func() error, error) {
	return lockKnownHostsFile(path + ".lock")
}
