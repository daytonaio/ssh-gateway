package ssh_gateway

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type DestSshServer struct {
	Network string
	Address string
	Config  *ssh.ClientConfig
}

type SshGateway struct {
	destServers map[string](*DestSshServer)

	logger UniversalLogger

	HostKey       ssh.Signer
	ListenNetwork string
	ListenAddress string

	NoClientAuth bool

	ValidateKeyboardInteractiveCallback func(username string, client ssh.KeyboardInteractiveChallenge) (*DestSshServer, error)
	ValidatePasswordCallback            func(username string, password []byte) (*DestSshServer, error)
	ValidatePublicKeyCallback           func(username string, key ssh.PublicKey) (*DestSshServer, error)
	ValidateNoClientAuthCallback        func(username string) (*DestSshServer, error)
}

func (s *SshGateway) Start() error {
	if s.destServers == nil {
		s.destServers = make(map[string](*DestSshServer))
	}

	var log UniversalLogger
	log = NoOpLogger{}
	if s.logger != nil {
		log = s.logger
	}

	config := s.getServerConfig()
	listener, err := net.Listen(s.ListenNetwork, s.ListenAddress)
	if err != nil {
		return err
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Warnf("Failed to accept incoming connection (%s)", err)
			//	todo: handler
			continue
		}

		go func(conn net.Conn) {
			serverConn, chans, reqs, err := ssh.NewServerConn(conn, config)
			if err != nil {
				log.Warnf("Failed to handshake (%s)", err)
				return
			}
			defer delete(s.destServers, string(serverConn.SessionID()))

			destSshServer := s.destServers[string(serverConn.SessionID())]

			workspaceClient, err := ssh.Dial(destSshServer.Network, destSshServer.Address, destSshServer.Config)
			if err != nil {
				log.Warn(err.Error())
				conn.Close()
				return
			}

			go func() {
				for {
					req, closed := <-reqs
					if req == nil {
						time.Sleep(1 * time.Millisecond)
						continue
					}
					ok, payload, err := workspaceClient.SendRequest(req.Type, req.WantReply, req.Payload)
					log.Debug(fmt.Sprintf("Global Request %s %s", req.Type, string(req.Payload)))
					if err != nil {
						log.Warn(err.Error())
						req.Reply(false, []byte(err.Error()))
						return
					}
					if req.WantReply {
						req.Reply(ok, payload)
					}
					if closed {
						return
					}
				}
			}()

			for clientNewChannel := range chans {
				go func(clientNewChannel ssh.NewChannel) {
					log.Debug(fmt.Sprintf("New channel %s %s ", clientNewChannel.ChannelType(), clientNewChannel.ExtraData()))

					workspaceChannel, workspaceRequests, err := workspaceClient.OpenChannel(clientNewChannel.ChannelType(), clientNewChannel.ExtraData())
					if err != nil {
						log.Warnf("could not accept channel (%s)", err)
						clientNewChannel.Reject(ssh.ConnectionFailed, err.Error())
						return
					}

					clientChannel, clientRequests, err := clientNewChannel.Accept()
					if err != nil {
						log.Warnf("could not accept channel (%s)", err)
						return
					}

					go func() {
						_, err := io.Copy(workspaceChannel, clientChannel)
						if err != nil {
							log.Warn(err.Error())
						}
					}()

					go func() {
						for {
							req := <-workspaceRequests
							if req == nil {
								return
							}
							log.Debug(fmt.Sprintf("Workspace request %s %s", req.Type, req.Payload))
							clientChannel.SendRequest(req.Type, req.WantReply, req.Payload)
							if req.WantReply {
								if err != nil {
									req.Reply(false, []byte(err.Error()))
								} else {
									req.Reply(true, nil)
								}
							}
						}
					}()

					go func() {
						for {
							req := <-clientRequests
							if req == nil {
								return
							}
							log.Debug(fmt.Sprintf("Client request %s %s", req.Type, string(req.Payload)))
							ok, err := workspaceChannel.SendRequest(req.Type, req.WantReply, req.Payload)
							if req.WantReply {
								if err != nil {
									req.Reply(false, []byte(err.Error()))
								} else {
									req.Reply(ok, nil)

									//	Workaround for dd hanging when installing JB remote
									if req.Type == "exec" && strings.Contains(string(req.Payload), "dd of") {
										time.Sleep(5 * time.Second)
										clientChannel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})

										workspaceChannel.Close()
									}
								}
							}
						}
					}()

					_, err = io.Copy(clientChannel, workspaceChannel)
					if err != nil {
						log.Warn(err.Error())
					}
					log.Debug("Closing channels")

					//	make sure any pending workspaceRequests are received
					time.Sleep(100 * time.Millisecond)

					clientChannel.Close()
				}(clientNewChannel)
			}
		}(conn)
	}

}

func (s *SshGateway) Stop() {
	panic("implement me")
}

func (s *SshGateway) getServerConfig() *ssh.ServerConfig {
	var keyboardInteractiveCallback func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error)
	if s.ValidateKeyboardInteractiveCallback != nil {
		keyboardInteractiveCallback = func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			destServer, err := s.ValidateKeyboardInteractiveCallback(conn.User(), client)
			if err != nil {
				return nil, err
			}
			s.destServers[string(conn.SessionID())] = destServer
			return nil, nil
		}
	}

	var passwordCallback func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error)
	if s.ValidatePasswordCallback != nil {
		passwordCallback = func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			destServer, err := s.ValidatePasswordCallback(conn.User(), password)
			if err != nil {
				return nil, err
			}
			s.destServers[string(conn.SessionID())] = destServer
			return nil, nil
		}
	}

	var publicKeyCallback func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error)
	if s.ValidatePublicKeyCallback != nil {
		publicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			destServer, err := s.ValidatePublicKeyCallback(conn.User(), key)
			if err != nil {
				return nil, err
			}
			s.destServers[string(conn.SessionID())] = destServer
			return nil, nil
		}
	}

	var noClientAuthCallback func(ssh.ConnMetadata) (*ssh.Permissions, error)
	noClientAuth := false
	if s.ValidateNoClientAuthCallback != nil {
		noClientAuthCallback = func(conn ssh.ConnMetadata) (*ssh.Permissions, error) {
			destServer, err := s.ValidateNoClientAuthCallback(conn.User())
			if err != nil {
				return nil, err
			}
			s.destServers[string(conn.SessionID())] = destServer
			return nil, nil
		}
		noClientAuth = true
	}

	serverConfig := &ssh.ServerConfig{
		KeyboardInteractiveCallback: keyboardInteractiveCallback,
		PasswordCallback:            passwordCallback,
		PublicKeyCallback:           publicKeyCallback,
		NoClientAuthCallback:        noClientAuthCallback,
		NoClientAuth:                noClientAuth,
	}

	serverConfig.AddHostKey(s.HostKey)

	return serverConfig
}
