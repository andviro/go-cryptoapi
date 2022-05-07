package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/mcesar/must"
)

var numberExtractRe = regexp.MustCompile(`.*?((0x[a-fA-F0-9]+)|([0-9]+))L?.*`)

func hexStr(src string) (res string, base int, _ int) {
	src = strings.ToLower(src)
	if strings.HasPrefix(src, "0x") {
		return strings.TrimPrefix(src, "0x"), 16, 64
	}
	return src, 10, 64
}

func main() {
	defer must.HandleFunc(func(err error) {
		if err != nil {
			log.Fatalf("fatal error: %+v", err)
		}
	})
	fp := must.Do(os.Open("/opt/cprocsp/include/cpcsp/CSP_WinError.h"))
	defer fp.Close()
	scanner := bufio.NewScanner(fp)
	var isScanningErrors bool
	found := make(map[int64]string)
	var keys []int64
	for scanner.Scan() {
		s := scanner.Text()
		if !strings.HasPrefix(s, "#define") {
			continue
		}
		data := strings.Fields(s)
		if len(data) != 3 {
			continue
		}
		if strings.HasPrefix(data[1], "ERROR_") && data[1] != "ERROR_SUCCESS" {
			isScanningErrors = true
		}
		if !isScanningErrors {
			continue
		}
		matches := numberExtractRe.FindStringSubmatch(data[2])
		if len(matches) < 2 {
			log.Printf("unsupported definition: %s = %s (%+v)", data[1], data[2], matches)
			continue
		}
		n, err := strconv.ParseInt(hexStr(matches[1]))
		if err != nil {
			log.Printf("invalid definition %s %s: %+v", data[1], data[2], err)
			continue
		}
		prev, ok := found[n]
		if ok {
			log.Printf("found definition for %#x: %s", n, prev)
			continue
		}
		found[n] = data[1]
		keys = append(keys, n)
	}
	must.Do0(scanner.Err())
	buf := must.Do(os.Create("../../csp/error_strings.go"))
	defer buf.Close()
	str := new(strings.Builder)
	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})
	for _, k := range keys {
		str.WriteString(found[k])
	}
	fmt.Fprintf(buf, "package csp\n\n")
	fmt.Fprintf(buf, "// Auto-generated definitions, do not edit\n")
	fmt.Fprintf(buf, "var (\n\terrorStrings = \"%s\"\n", str)
	fmt.Fprintf(buf, "\terrorStringMap = map[int64]string {\n")
	start := 0
	for _, k := range keys {
		n := len(found[k])
		fmt.Fprintf(buf, "\t\t%d: errorStrings[%d:%d],\n", k, start, start+n)
		start += n
	}
	fmt.Fprintf(buf, "\t}\n)\n")
}
