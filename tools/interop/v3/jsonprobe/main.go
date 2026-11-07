package main

import (
	"encoding/json/v2"
	"fmt"
)

type R struct {
	Epoch int    `json:"epoch"`
	ID    string `json:"id"`
}

func main() {
	for _, s := range []string{`{"epoch":2}`, `{"epoch":2.0}`, `{"epoch":2e0}`, `{"epoch":20e-1}`, `{"epoch":-0}`, `{"epoch":9007199254740993}`, `{"epoch":1e400}`, `{"ID":"x"}`, `{"id":"a","id":"b"}`, `{"id":"\ud800"}`, "{\"id\":\"\xff\"}", `{"epoch":null}`} {
		var r R
		err := json.Unmarshal([]byte(s), &r)
		fmt.Printf("%-28s -> %+v err=%v\n", s, r, err)
	}
}
