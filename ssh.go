package main
import (
    "os"
    "bufio"
    "regexp"
)

const (
    SshTypePassword = "Password"
    SshType = "Key"
)

var (
    SshLogPattern = regexp.MustCompile(`^auth.log(\.\d+)?$`)
    failIndicator = regexp.MustCompile("(?i)fail")
    invalidUserPattern = regexp.MustCompile(`(?i)invalid user (?P<user>\S+) from (?P<ip>[\d\.]+)`)
)

type Ssh struct {
    User string
    Type string
}

func ReadSshLog(file *os.File) {
    scanner := bufio.NewScanner(file)

    for scanner.Scan() {
        line := scanner.Text()
//        if !failIndicator.MatchString(line) {
//            continue
//        }

        if invalidUserPattern.MatchString(line) {
            match := invalidUserPattern.FindStringSubmatch(line)
            result := make(map[string]string)
            for i, name := range invalidUserPattern.SubexpNames() {
                result[name] = match[i]
            }

            invalidUsers[result["user"]]++
        } else if false {

        }
    }
}
