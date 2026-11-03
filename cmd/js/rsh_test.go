package main

import "testing"

func TestParseRshArgs(t *testing.T) {
	cases := []struct {
		in          []string
		target, cmd string
		wantErr     bool
	}{
		{[]string{"user@h", "rsync", "--server", "-vlogDtpre.iLsfxC", ".", "/d/"}, "user@h", "rsync --server -vlogDtpre.iLsfxC . /d/", false},
		{[]string{"-l", "bob", "10.0.0.1", "rsync", "--server"}, "bob@10.0.0.1", "rsync --server", false},
		{[]string{"-T", "-o", "StrictHostKeyChecking=no", "-p", "22", "u@h", "echo", "hi"}, "u@h", "echo hi", false},
		{[]string{"-lbob", "h", "ls"}, "bob@h", "ls", false},
		{[]string{"--", "u@h", "ls"}, "u@h", "ls", false},
		{[]string{"u@h"}, "", "", true},
		{nil, "", "", true},
	}
	for _, c := range cases {
		tg, cmd, err := parseRshArgs(c.in)
		if (err != nil) != c.wantErr || tg != c.target || cmd != c.cmd {
			t.Errorf("%v => (%q,%q,%v)", c.in, tg, cmd, err)
		}
	}
}
