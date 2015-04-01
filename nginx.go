package main

import (
	"io"
	"os"
	"regexp"

	"fmt"

	"github.com/satyrius/gonx"
    "strings"
)

const (
	logFormat = `$remote_addr - - [$time_local] "$request" $status $bytes_sent "$http_referer" "$http_user_agent"`
)

var (
	NginxLogPattern    = regexp.MustCompile(`^access.log(\.\d+)?$`)
	suspiciousPatterns = regexp.MustCompile(`(?i)(php|admin|muieblackcat|wp-|cgi|\.\.|aspx|asp)+`)
	nginxParser        = gonx.NewParser(logFormat)
    urlPattern         = regexp.MustCompile(`(?i)(?P<method>\S+)\s+(?P<uri>\S*)\s+HTTP\/1.\d`)
)

type Nginx struct {
	Request, Referrer string
}

func ReadNginxLog(logFile *os.File) {
	reader := gonx.NewReader(logFile, logFormat)

	// Process records
	for {
		rec, err := reader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}

		request, _ := rec.Field("request")

        if !urlPattern.MatchString(request) {
            interestingRequests[request]++
            continue
        }

		if !suspiciousPatterns.MatchString(request) {
			continue
		}

		referrer, _ := rec.Field("http_referer")

        // ignore my uncle's site
        if strings.Contains(referrer, "mglands") {
            continue
        }

		userAgent, _ := rec.Field("http_user_agent")
		ip, _ := rec.Field("remote_addr")

		if referrer == "-" {
			referrer = ""
		}

		// shitty naming
		nginxAttack := Nginx{
			Request:  request,
			Referrer: referrer,
		}

		var attack *Attack

        // This kind of has a different meaning from just doing "attack, ok := attackers["attacks"][ip]" since in that context
        // ok would tell us whether or not that element exists. In this case, "ok" tells us whether or not the type assertion
        // succeeded. So I guess if you consider trying to cast nil to a type the same as something just not existing,
        // then yeah they're the same thing. Regardless, this works.
		attack, ok := attacks[ip].(*Attack)
		if !ok {
			attack = NewAttack()
			attacks[ip] = attack
		}

		if attack.UserAgent == "" {
			attack.UserAgent = userAgent
		}

		attack.Nginx = append(attack.Nginx, nginxAttack)

        match := urlPattern.FindStringSubmatch(request)
        result := make(map[string]string)
        for i, name := range urlPattern.SubexpNames() {
            result[name] = match[i]
        }

        urls[result["uri"]]++
        methods[result["method"]]++
	}
}
