package main

import (
    "crypto/rand"
    "encoding/hex"
    "fmt"
    "io"
    "net"
    "os"
    "strings"
    "time"
    "github.com/gotd/td/mtproxy"
    "github.com/gotd/td/mtproxy/faketls"
)

type tamper struct { io.ReadWriter; offset int; enabled bool }
func (t *tamper) Read(p []byte) (int, error) {
    n, err := t.ReadWriter.Read(p)
    if t.enabled && t.offset <= 11 && t.offset+n > 11 { p[11-t.offset] ^= 1 }
    t.offset += n
    return n, err
}
func main() {
    mode := os.Args[1]
    conn, err := net.DialTimeout("tcp", "127.0.0.1:443", 3*time.Second)
    if err != nil { fmt.Println("connect failed"); os.Exit(2) }
    defer conn.Close()
    conn.SetDeadline(time.Now().Add(5*time.Second))
    key, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
    if mode == "wrong" { key[0] ^= 1 }
    s := mtproxy.Secret{Secret:key, Tag:0xee, CloakHost:"dns.example.com", Type:mtproxy.TLS}
    transport := &tamper{ReadWriter:conn, enabled: mode == "tamper"}
    err = faketls.NewFakeTLS(rand.Reader, transport).Handshake([4]byte{}, 2, s)
    if mode == "correct" && err == nil { fmt.Println("correct: authenticated HMAC"); return }
    if mode == "tamper" && err != nil && strings.Contains(err.Error(), "hmac digest mismatch") { fmt.Println("tamper: rejected"); return }
    if mode == "wrong" && err != nil { fmt.Println("wrong secret: rejected"); return }
    fmt.Printf("unexpected outcome: %v\n", err)
    os.Exit(1)
}
