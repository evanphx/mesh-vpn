package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

var Debug bool = false
var DebugLevel int = -1

const dInfo = 1
const dConn = 2
const dPacket = 5

// Debug function, if the debug flag is set, then display. Do nothing otherwise
// If Docker is in damon mode, also send the debug info on the socket
func Debugf(level int, format string, a ...interface{}) {
	if level <= DebugLevel {
		// Retrieve the stack infos
		_, file, line, ok := runtime.Caller(1)
		if !ok {
			file = "<unknown>"
			line = -1
		} else {
			file = file[strings.LastIndex(file, "/")+1:]
		}

		n := time.Now()

		fmt.Fprintf(os.Stderr, fmt.Sprintf("[debug] %d %s:%d %s\n", n.Unix(), file, line, format), a...)
	}
}
