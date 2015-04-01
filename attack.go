package main

type Attack struct {
    Nginx []Nginx `json:"nginx"`
    SSH []Ssh `json:"ssh"`
    UserAgent string `json:"user_agent"`
}

func NewAttack() *Attack {
    return &Attack{}
}
