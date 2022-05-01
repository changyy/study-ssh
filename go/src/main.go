package main

import (
    //"fmt"
    "log"
    "os"
    "golang.org/x/crypto/ssh"
)

func init() {
    log.SetPrefix("SSH-Client")
    log.SetFlags(log.LstdFlags|log.Lshortfile|log.LUTC)
}

func main() {
    host := "ptt.cc:22"
    termHeight := 24
    termWidth := 80
    termModes := ssh.TerminalModes{
        ssh.ECHO: 0,
        ssh.TTY_OP_ISPEED: 14400,
        ssh.TTY_OP_OSPEED: 14400,
    }

    sshConfig := &ssh.ClientConfig{
        User: "bbs",
    }
    sshConfig.HostKeyCallback = ssh.InsecureIgnoreHostKey()

    client, err := ssh.Dial("tcp", host, sshConfig)
    defer client.Close()
    if err != nil {
        log.Fatalln(err)
    }

    session, err := client.NewSession()
    if err != nil {
        log.Panic(err)
    }
    defer session.Close()

    if err := session.RequestPty("xterm", termHeight, termWidth, termModes); err != nil {
        log.Panic(err)
	}

    session.Stdout = os.Stdout
    session.Stderr = os.Stderr

    if err := session.Shell(); err != nil {
        log.Panic(err)
    }
    session.Wait()
}
