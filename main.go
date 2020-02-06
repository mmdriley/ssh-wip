package main

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"log"
	"net"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

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

func createServerConfig() *ssh.ServerConfig {
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

	// TODO: persistent host key
	_, hostPrivateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}

	hostKeySigner, err := ssh.NewSignerFromKey(hostPrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	config.AddHostKey(hostKeySigner)

	return config
}

func handleConnection(netconn net.Conn, config *ssh.ServerConfig) {
	// sshConn -- metadata and control
	// channels -- channel of "open channel" requests
	//   https://tools.ietf.org/html/rfc4254#section-5.1
	// requests -- channel of global requests
	//   https://tools.ietf.org/html/rfc4254#section-4
	sshconn, channels, requests, err := ssh.NewServerConn(netconn, config)
	if err != nil {
		log.Fatal("failed to handshake: ", err)
	}
	var _ = sshconn

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
		t := proposedChannel.ChannelType()
		fmt.Printf("New proposed channel of type %v\n", t)

		switch t {
		case "direct-tcpip":
			handleDirectTcpipChannelRequest(sshconn, proposedChannel)
		case "session":
			handleSessionChannelRequest(sshconn, proposedChannel)

		default:
			proposedChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
		}
	}
}

func handleSessionChannelRequest(c ssh.Conn, req ssh.NewChannel) error {
	channel, channelRequests, err := req.Accept()
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

	return nil
}

func copyBothWays(lhs, rhs io.ReadWriteCloser) error {
	errs := make(chan error)

	go func() {
		_, err := io.Copy(rhs, lhs)
		errs <- err
	}()

	go func() {
		_, err := io.Copy(lhs, rhs)
		errs <- err
	}()

	defer lhs.Close()
	defer rhs.Close()

	// TODO: the goal here is to properly handle half-closed connections where
	// one side has closed its sending side but is still willing to receive.
	// However, the net effect is that the connection remains open even after
	// one party is *entirely gone*.
	//
	// Coarse solution is to stop all copies when one hits an error.
	// Coordinate with a channel.
	//
	// Seems like there's a stickier problem here around how to deal with
	// idle connections overall.
	//
	// Is there a way to determine a side is dead (and not just half-closed)
	// without trying to write to it?
	if err := <-errs; err != nil {
		return err
	}
	return <-errs
}

// https://tools.ietf.org/html/rfc4254#section-7.2 shows "direct-tcpip" fields
// https://tools.ietf.org/html/rfc4254#section-5.1 shows which are "extra"

type DirectTcpipChannelMsgExtraData struct {
	Host           string
	Port           uint32
	OriginatorIP   string
	OriginatorPort uint32
}

func handleDirectTcpipChannelRequest(c ssh.Conn, req ssh.NewChannel) error {
	var data DirectTcpipChannelMsgExtraData
	err := ssh.Unmarshal(req.ExtraData(), &data)
	if err != nil {
		return err
	}
	fmt.Printf("%+v\n", data)

	conn, err := net.Dial("tcp", fmt.Sprintf("%v:%v", data.Host, data.Port))
	if err != nil {
		req.Reject(ssh.ConnectionFailed, "")
		return err
	}

	channel, requests, err := req.Accept()
	go ssh.DiscardRequests(requests)
	go func() {
		err := copyBothWays(channel, conn)
		fmt.Printf("copyBothWays returned %v\n", err)
	}()

	return nil
}

func main() {
	config := createServerConfig()

	// TODO: configurable bind address and port
	listener, err := net.Listen("tcp", "0.0.0.0:2222")
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}

	for {
		connection, err := listener.Accept()
		if err != nil {
			log.Fatal("failed to accept incoming connection: ", err)
		}

		go handleConnection(connection, config)
	}
}
