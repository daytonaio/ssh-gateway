package ssh_gateway

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

const SshGatewaySockFile = "/tmp/ssh-gateway-test.sock"
const DestServerSockFile = "/tmp/ssh-gateway-test-dest-server.sock"

func generateRSAKeyPair() (ssh.Signer, ssh.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	return signer, publicKey, nil
}

func generateHostKey() (*ssh.Signer, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, err
	}

	return &signer, nil
}

func setupMockWorkspaceSSH(publickey ssh.PublicKey) {
	// SSH server configuration
	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			// Convert the keys to their string representation
			providedKeyString := string(key.Marshal())
			workspaceKeyString := string(publickey.Marshal())

			// Compare the provided public key with the public key of the workspace
			if providedKeyString == workspaceKeyString {
				return nil, nil
			}

			return nil, fmt.Errorf("unknown public key for %q", conn.User())
		},
	}

	//	use the same hostkey as the gateway
	hostKey, err := generateHostKey()
	if err != nil {
		log.Fatal("Failed to get host key")
	}
	serverConfig.AddHostKey(*hostKey)

	listener, err := net.Listen("unix", DestServerSockFile)
	if err != nil {
		log.Fatalf(err.Error())
	}

	for {
		// Accept a connection
		conn, err := listener.Accept()
		if err != nil {
			log.Fatalf("Failed to accept connection: %v", err)
		}

		// Handle the connection in a new goroutine
		go handleConn(conn, serverConfig)
	}
}

func handleConn(conn net.Conn, config *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		log.Fatalf("Failed to handshake (%s)", err)
	}
	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		go func(newChannel ssh.NewChannel) {
			chType := newChannel.ChannelType()
			if chType != "session" {
				newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unsupported channel type: %s", chType))
				return
			}

			ch, chreqs, err := newChannel.Accept()
			if err != nil {
				log.Fatalf("Could not accept channel (%s)", err)
			}
			go func(in <-chan *ssh.Request) {
				for req := range in {
					fmt.Println(req.Type, req.WantReply, string(req.Payload))
					if req.WantReply {
						err = req.Reply(true, nil)
						if err != nil {
							log.Fatalf("Could not reply to request (%s)", err)
						}
					}
				}
			}(chreqs)

			time.Sleep(1 * time.Second)
			ch.Close()

		}(newChannel)
	}
}

func testSSHNoAuth(t *testing.T) {
	// SSH client configuration
	clientConfig := &ssh.ClientConfig{
		User:            "testuser",
		Auth:            []ssh.AuthMethod{},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// Create SSH client
	client, err := ssh.Dial("unix", SshGatewaySockFile, clientConfig)
	if err != nil {
		t.Fatalf("Failed to dial: %s", err)
	}

	// Create a new session
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("Failed to create session: %s", err)
	}
	defer session.Close()

	err = session.Start("ls")
	if err != nil {
		t.Fatalf("Failed to start: %s", err)
		return
	}

	session.Wait()

	// Close the connection
	client.Close()
}

func TestMain(t *testing.T) {
	privateKey, publicKey, err := generateRSAKeyPair()
	if err != nil {
		log.Fatal("Failed to generate RSA key pair")
	}

	err = os.Remove(SshGatewaySockFile)
	if err != nil {
		panic(err)
	}
	err = os.Remove(DestServerSockFile)
	if err != nil {
		panic(err)
	}

	go func() {
		setupMockWorkspaceSSH(publicKey)
	}()
	go func() {
		hostKey, err := generateHostKey()
		if err != nil {
			log.Fatal("Failed to get host key")
		}
		sshGateway := SshGateway{
			ListenNetwork: "unix",
			ListenAddress: SshGatewaySockFile,
			logger:        logrus.New(),
			HostKey:       *hostKey,
			NoClientAuth:  true,
			ValidatePublicKeyCallback: func(username string, key ssh.PublicKey) (*DestSshServer, error) {
				return &DestSshServer{
					Network: "unix",
					Address: DestServerSockFile,
					Config: &ssh.ClientConfig{
						User: username,
						Auth: []ssh.AuthMethod{
							ssh.PublicKeys(privateKey),
						},
						HostKeyCallback: ssh.InsecureIgnoreHostKey(),
					},
				}, nil
			},
			ValidateNoClientAuthCallback: func(username string) (*DestSshServer, error) {
				return &DestSshServer{
					Network: "unix",
					Address: DestServerSockFile,
					Config: &ssh.ClientConfig{
						User: username,
						Auth: []ssh.AuthMethod{
							ssh.PublicKeys(privateKey),
						},
						HostKeyCallback: ssh.InsecureIgnoreHostKey(),
					},
				}, nil
			},
		}

		sshGateway.Start()
	}()
	time.Sleep(1 * time.Second)

	t.Run("SSH Connection", testSSHNoAuth)
}
