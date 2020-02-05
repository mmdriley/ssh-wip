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
- Accept more than one connection
*/

// https://tools.ietf.org/html/rfc4254#section-7.2 shows "direct-tcpip" fields
// https://tools.ietf.org/html/rfc4254#section-5.1 shows which are "extra"

type DirectTcpipChannelMsgExtraData struct {
	Host           string
	Port           uint32
	OriginatorIp   string
	OriginatorPort uint32
}

func printDirectTcpipRequest(b []byte) {
	var s DirectTcpipChannelMsgExtraData
	err := ssh.Unmarshal(b, &s)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%+v\n", s)
}

// https://tools.ietf.org/html/rfc4254#section-7.1
type TcpipForwardRequestPayload struct {
	BindAddress string
	BindPort    uint32
}

func printTcpipForwardRequest(b []byte) {
	var s TcpipForwardRequestPayload
	err := ssh.Unmarshal(b, &s)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%+v\n", s)
}

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
			fmt.Printf("Allowing connection for %v using key %v\n", c.User(), ssh.FingerprintSHA256(pubKey))
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
	tcpConn, err := listener.Accept()
	if err != nil {
		log.Fatal("failed to accept incoming connection: ", err)
	}

	// sshConn -- metadata and control
	// channels -- channel of "open channel" requests
	//   https://tools.ietf.org/html/rfc4254#section-5.1
	// requests -- channel of global requests
	//   https://tools.ietf.org/html/rfc4254#section-4
	sshConn, channels, requests, err := ssh.NewServerConn(tcpConn, config)
	if err != nil {
		log.Fatal("failed to handshake: ", err)
	}
	var _ = sshConn

	// For now, rejeact all global requests
	// This is where we will see e.g. tcpip-forward
	go func(in <-chan *ssh.Request) {
		for req := range in {
			t := req.Type
			fmt.Printf("global request: %v\n", t)
			if t == "tcpip-forward" {
				printTcpipForwardRequest(req.Payload)
			}
			req.Reply(false, nil)
		}
	}(requests)

	// Service the channel of incoming channel requests
	for proposedChannel := range channels {
		// Channels have a type, depending on the application level
		// protocol intended. In the case of a shell, the type is
		// "session" and ServerShell may be used to present a simple
		// terminal interface.
		t := proposedChannel.ChannelType()
		fmt.Printf("New proposed channel of type %v\n", t)
		if t == "direct-tcpip" {
			printDirectTcpipRequest(proposedChannel.ExtraData())
		} else if proposedChannel.ChannelType() != "session" {
			proposedChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, channelRequests, err := proposedChannel.Accept()
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
		}(channelRequests)

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
