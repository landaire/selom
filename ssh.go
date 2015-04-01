package main

const (
    SshTypePassword = "Password"
    SshType = "Key"
)

type Ssh struct {
    User string
    Type string
}
