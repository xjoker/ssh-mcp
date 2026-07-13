package config

import "sync"

var saveProcessMutex sync.Mutex

func acquireSaveLock(path string) (func() error, error) {
	saveProcessMutex.Lock()
	releaseFile, err := lockSaveFile(path + ".lock")
	if err != nil {
		saveProcessMutex.Unlock()
		return nil, err
	}
	return func() error {
		err := releaseFile()
		saveProcessMutex.Unlock()
		return err
	}, nil
}
