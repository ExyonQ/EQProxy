// Command probe reads the container's own resource counters for the
// S-H3-01/S-H3-02 benchmark evidence. It is mounted read-only into each
// container (including the scratch EQProxy image, which has no shell) and
// executed with `docker exec`; it touches nothing but /sys/fs/cgroup and
// /proc/1, so it cannot influence the measured workload.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type counters struct {
	CPUUsageUSec uint64 `json:"cpu_usage_usec,omitempty"`
	CPUUserUSec  uint64 `json:"cpu_user_usec,omitempty"`
	CPUSysUSec   uint64 `json:"cpu_system_usec,omitempty"`
	MemCurrent   uint64 `json:"memory_current,omitempty"`
	MemPeak      uint64 `json:"memory_peak,omitempty"`
	Source       string `json:"source"`
}

func readUint(path string) (uint64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func kv(path string) map[string]uint64 {
	out := map[string]uint64{}
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		v, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		out[fields[0]] = v
	}
	return out
}

func main() {
	c := counters{Source: "cgroup2"}
	stat := kv("/sys/fs/cgroup/cpu.stat")
	c.CPUUsageUSec = stat["usage_usec"]
	c.CPUUserUSec = stat["user_usec"]
	c.CPUSysUSec = stat["system_usec"]
	if v, ok := readUint("/sys/fs/cgroup/memory.current"); ok {
		c.MemCurrent = v
	}
	if v, ok := readUint("/sys/fs/cgroup/memory.peak"); ok {
		c.MemPeak = v
	}
	if c.CPUUsageUSec == 0 {
		c.Source = "proc"
		// Fallback: /proc/1/stat fields 14 (utime) and 15 (stime) in USER_HZ
		// (100 on every platform this bench runs on).
		if data, err := os.ReadFile("/proc/1/stat"); err == nil {
			// The comm field can contain spaces; cut at the last ')'.
			s := string(data)
			if i := strings.LastIndexByte(s, ')'); i >= 0 && i+2 < len(s) {
				fields := strings.Fields(s[i+2:])
				if len(fields) > 13 {
					utime, _ := strconv.ParseUint(fields[11], 10, 64)
					stime, _ := strconv.ParseUint(fields[12], 10, 64)
					c.CPUUsageUSec = (utime + stime) * 10000
				}
			}
		}
	}
	out, _ := json.Marshal(c)
	fmt.Println(string(out))
}
