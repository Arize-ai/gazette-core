//go:build !windows

package mainboilerplate

import "syscall"

func statFS(path string) (total, free, avail uint64, err error) {
	var s syscall.Statfs_t
	if err = syscall.Statfs(path, &s); err != nil {
		return
	}
	var bsize = uint64(s.Bsize)
	total = s.Blocks * bsize
	free = s.Bfree * bsize
	avail = s.Bavail * bsize
	return
}
