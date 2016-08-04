package main

/*  Entry Proxy for Onion Gateway

See also:

  * https://github.com/DonnchaC/oniongateway/blob/master/docs/design.rst#32-entry-proxy
  * https://habrahabr.ru/post/142527/
*/

import (
    "log"
    "net"
    "net/url"
    "time"

    "golang.org/x/net/proxy"
)

const BUFFER_SIZE = 1024

func connectToProxy(proxyUrl, targetServer string) (net.Conn, error) {
    parsedUrl, err := url.Parse(proxyUrl)
    if err != nil {
        return nil, err
    }
    dialer, err := proxy.FromURL(parsedUrl, proxy.Direct)
    if err != nil {
        return nil, err
    }
    connection, err := dialer.Dial("tcp", targetServer)
    return connection, err
}

func netCopy(from, to net.Conn, finished chan<- struct{}) {
    defer func() {
        finished<-struct{}{}
    }()
    buffer := make([]byte, BUFFER_SIZE)
    for {
        from.SetReadDeadline(time.Now().Add(time.Duration(10e9)))
        bytesRead, err := from.Read(buffer)
        if err != nil {
            log.Printf("Finished reading: %s", err)
            break
        }
        to.SetWriteDeadline(time.Now().Add(time.Duration(10e9)))
        _, err = to.Write(buffer[:bytesRead])
        if err != nil {
            log.Printf("Finished writting: %s", err)
            break
        }
    }
}

func processRequest(clientConn net.Conn) {
    defer clientConn.Close()
    hostname, prefix, err := readSni(clientConn)
    if err != nil {
        log.Printf("Unable to get target server name from SNI: %s", err)
        return
    }
    proxyUrl := "socks5://127.0.0.1:9150"
    targetServer := hostname + ":4218"
    serverConn, err := connectToProxy(proxyUrl, targetServer)
    if err != nil {
        log.Printf(
            "Unable to connect to %s through %s: %s\n",
            targetServer,
            proxyUrl,
            err,
        )
        return
    }
    defer serverConn.Close()
    // write prefix (already read for SNI) to server
    serverConn.SetWriteDeadline(time.Now().Add(time.Duration(10e9)))
    serverConn.Write(prefix)
    finished := make(chan struct{})
    go netCopy(clientConn, serverConn, finished)
    go netCopy(serverConn, clientConn, finished)
    <-finished
    <-finished
}

func main() {
    listenOn := "127.0.0.1:4218"
    listener, err := net.Listen("tcp", listenOn)
    if err != nil {
        log.Fatal("Unable to listen on %s: %s", listenOn, err)
    }
    for {
        conn, err := listener.Accept()
        if err == nil {
            go processRequest(conn)
        } else {
            log.Printf("Unable to accept request: %s", err)
        }
    }
}
