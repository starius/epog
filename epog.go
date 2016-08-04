package main

import (
    "log"
    "net"
    "net/url"

    "golang.org/x/net/proxy"
)

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

func main() {
    proxyUrl := "socks5://127.0.0.1:9150"
    targetServer := "ip4.me:80"
    _, err := connectToProxy(proxyUrl, targetServer)
    if err != nil {
        log.Printf(
            "Unable to connect to %s through %s: %s\n",
            targetServer,
            proxyUrl,
            err,
        )
        return
    }
}
