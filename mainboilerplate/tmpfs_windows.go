//go:build windows

package mainboilerplate

import "fmt"

func statFS(path string) (total, free, avail uint64, err error) {
	err = fmt.Errorf("temporary filesystem metrics are not supported on windows")
	return
}
