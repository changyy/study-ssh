package main

import (
    "fmt"
    "log"
    "os"
    "io"
    "bufio"
    "golang.org/x/crypto/ssh"
    "golang.org/x/term"
)

func init() {
    log.SetPrefix("SSH-Client")
    log.SetFlags(log.LstdFlags|log.Lshortfile|log.LUTC)
}

func main() {
    state, err := term.MakeRaw(0)
    if err != nil {
        log.Fatalln(err)
    }
    defer func() {
        if err := term.Restore(0, state) ; err != nil {
            fmt.Println("term.Restore error: ", err)
        }
    }()

    quitConnection := make(chan int, 1)
    quitMain := make(chan int, 1)

    go func() {
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
        stdin, err := session.StdinPipe()
        if err != nil {
            log.Fatalln(err)
        }
        defer stdin.Close()

        //session.Stdin = os.Stdin
        go func() {
            in := bufio.NewReader(os.Stdin)
            for {
                r, _, _ := in.ReadRune()
                if _, err := stdin.Write([]byte(string(r))); err != nil {
                    if err == io.EOF {
                        quitConnection <- 1
                        break
                    } else {
                        log.Fatalln(err)
                    }
                }
            }
        }()

        if err := session.Shell(); err != nil {
            log.Panic(err)
        }
        session.Wait()
        <- quitConnection
        quitMain <- 1
    }()

    <- quitMain
}
