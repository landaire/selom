package main

import (
	"io"
	"os"
	"regexp"

	"github.com/satyrius/gonx"
    "fmt"
)

const (
	logFormat   = `$remote_addr - - [$time_local] "$request" $status $bytes_sent "$http_referer" "$http_user_agent"`
)

var (
	NginxLogPattern    = regexp.MustCompile(`^access.log(\.\d+)?$`)
	suspiciousPatterns = regexp.MustCompile(`(php|admin|muieblackcat|wp-|cgi|\.\.)`)
	nginxParser        = gonx.NewParser(logFormat)
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
        if !suspiciousPatterns.MatchString(request) {
            continue
        }

        referrer, _ := rec.Field("http_referer")
        userAgent, _ := rec.Field("http_user_agent")
        ip, _ := rec.Field("remote_addr")

		// shitty naming
		nginxAttack := Nginx{
            Request: request,
            Referrer: referrer,
        }

        var attack *Attack

        attack, ok := attackers[ip];
		if !ok {
			attack = NewAttack()
            attackers[ip] = attack
		}

        if attack.UserAgent == "" {
            attack.UserAgent = userAgent
        }

        attack.Nginx = append(attack.Nginx, nginxAttack)
	}
}
