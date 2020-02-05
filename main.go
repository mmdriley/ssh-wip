package main

import (
	"crypto/ed25519"
	"fmt"
	"log"
	"net"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

/*
TODO
- Configurable interface and port
- Fixed host key (for now, use -o StrictHostKeyChecking=no,UserKnownHostsFile=/dev/null)
*/

func main() {
	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
		// Remove to disable password auth.
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// Should use constant-time compare (or better, salt+hash) in
			// a production setting.
			if c.User() == "testuser" && string(pass) == "tiger" {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},

		// Remove to disable public key auth.
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			fmt.Println("Allowing connection for %v using key %v", c.User(), ssh.FingerprintSHA256(pubKey))
			return &ssh.Permissions{}, nil
		},
	}

	_, hostPrivateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}

	hostKeySigner, err := ssh.NewSignerFromKey(hostPrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	config.AddHostKey(hostKeySigner)

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	listener, err := net.Listen("tcp", "0.0.0.0:2222")
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}
	nConn, err := listener.Accept()
	if err != nil {
		log.Fatal("failed to accept incoming connection: ", err)
	}

	// Before use, a handshake must be performed on the incoming
	// net.Conn.
	conn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		log.Fatal("failed to handshake: ", err)
	}
	log.Printf("logged in with key %s", conn.Permissions.Extensions["pubkey-fp"])

	// The incoming Request channel must be serviced.
	go ssh.DiscardRequests(reqs)

	// Service the incoming Channel channel.
	for newChannel := range chans {
		// Channels have a type, depending on the application level
		// protocol intended. In the case of a shell, the type is
		// "session" and ServerShell may be used to present a simple
		// terminal interface.
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Fatalf("Could not accept channel: %v", err)
		}

		// Sessions have out-of-band requests such as "shell",
		// "pty-req" and "env".  Here we handle only the
		// "shell" request.
		go func(in <-chan *ssh.Request) {
			for req := range in {
				req.Reply(req.Type == "shell", nil)
			}
		}(requests)

		term := terminal.NewTerminal(channel, "> ")

		go func() {
			defer channel.Close()
			for {
				line, err := term.ReadLine()
				if err != nil {
					break
				}
				fmt.Println(line)
			}
		}()
	}
}
