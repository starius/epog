package main

import (
    "errors"
    "fmt"
    "net"
)

// based on https://github.com/gpjt/stupid-proxy ( https://git.io/v6m3W )
func readSni(clientConn net.Conn) (
    hostname string,
    prefix []byte,
    err error,
) {
    firstByte := make([]byte, 1)
    _, err = clientConn.Read(firstByte)
    if err != nil {
        err = errors.New(fmt.Sprintf("Couldn't read first byte: %s", err))
        return
    }
    if firstByte[0] != 0x16 {
        err = errors.New("Not TLS")
        return
    }
    versionBytes := make([]byte, 2)
    _, err = clientConn.Read(versionBytes)
    if err != nil {
        err = errors.New(fmt.Sprintf("Couldn't read version bytes: %s", err))
        return
    }
    if versionBytes[0] < 3 || (versionBytes[0] == 3 && versionBytes[1] < 1) {
        err = errors.New("SSL < 3.1 so it's still not TLS")
        return
    }
    restLengthBytes := make([]byte, 2)
    _, err = clientConn.Read(restLengthBytes)
    if err != nil {
        err = errors.New(fmt.Sprintf("Couldn't read restLength bytes: %s", err))
        return
    }
    restLength := (int(restLengthBytes[0]) << 8) + int(restLengthBytes[1])
    rest := make([]byte, restLength)
    _, err = clientConn.Read(rest)
    if err != nil {
        err = errors.New(fmt.Sprintf("Couldn't read rest of bytes: %s", err))
        return
    }
    current := 0
    handshakeType := rest[0]
    current += 1
    if handshakeType != 0x1 {
        err = errors.New("Not a ClientHello")
        return
    }
    // Skip over another length
    current += 3
    // Skip over protocolversion
    current += 2
    // Skip over random number
    current += 4 + 28
    // Skip over session ID
    sessionIDLength := int(rest[current])
    current += 1
    current += sessionIDLength
    cipherSuiteLength := (int(rest[current]) << 8) + int(rest[current+1])
    current += 2
    current += cipherSuiteLength
    compressionMethodLength := int(rest[current])
    current += 1
    current += compressionMethodLength
    if current > restLength {
        err = errors.New("no extensions")
        return
    }
    // Skip over extensionsLength
    // extensionsLength := (int(rest[current]) << 8) + int(rest[current + 1])
    current += 2
    hostname = ""
    for current < restLength && hostname == "" {
        extensionType := (int(rest[current]) << 8) + int(rest[current+1])
        current += 2
        extensionDataLength := (int(rest[current]) << 8) + int(rest[current+1])
        current += 2
        if extensionType == 0 {
            // Skip over number of names as we're assuming there's just one
            current += 2
            nameType := rest[current]
            current += 1
            if nameType != 0 {
                err = errors.New("Not a hostname")
                return
            }
            nameLen := (int(rest[current]) << 8) + int(rest[current+1])
            current += 2
            hostname = string(rest[current : current+nameLen])
        }
        current += extensionDataLength
    }
    if hostname == "" {
        err = errors.New("No hostname")
        return
    }
    // TODO: read directly to prefix ^^
    prefix = make([]byte, 0)
    prefix = append(prefix, firstByte...)
    prefix = append(prefix, versionBytes...)
    prefix = append(prefix, restLengthBytes...)
    prefix = append(prefix, rest...)
    return
}
