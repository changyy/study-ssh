package main

import (
    "bufio"
    "fmt"
    "log"
    "os"
    "os/signal"
    "syscall"
    "golang.org/x/term"
)

func main() {
    // b := make([]byte, 1)
    // for { 
    //     os.Stdin.Read(b)
    //     fmt.Println(b)
    // }
    state, err := term.MakeRaw(0)
    if err != nil {
        log.Fatalln(err)
    }
    defer func() {
        if err := term.Restore(0, state) ; err != nil {
            fmt.Println("term.Restore error: ", err)
        }
    }()

    quitChannel := make(chan os.Signal, 1)
    signal.Notify(quitChannel, syscall.SIGINT, syscall.SIGTERM)

    go func() {
        in := bufio.NewReader(os.Stdin)
        for {
            r, _, err := in.ReadRune()
            if err != nil {
    
            }
            fmt.Print(r, " ")
            // ctrl+c
            if r == 3 {
                quitChannel <- syscall.SIGINT 
                break
            }
        }
    }()

    <-quitChannel
    fmt.Println("Done")
}
