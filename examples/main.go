package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/pion/stun"
	"github.com/pion/webrtc/v4"
)

type signalMsg struct {
	SDP  *webrtc.SessionDescription `json:"sdp,omitempty"`
	Cand *webrtc.ICECandidateInit   `json:"candidate,omitempty"`
}

type peer struct {
	dc     *webrtc.DataChannel
	alias  string
	tracks []*webrtc.TrackLocalStaticRTP
}

func main() {
	lanIP()
	publicIP()
	if len(os.Args) != 3 {
		fmt.Println("Usage: go run main.go [server|client] [addr:port]")
		return
	}
	fmt.Print("Enter your alias: ")
	alias := ""
	fmt.Scanln(&alias)
	mode, addr := os.Args[1], os.Args[2]
	if mode == "server" {
		runServer(addr, alias)
	} else {
		runClient(addr, alias)
	}
}

func lanIP() {
	conn, err := net.Dial("udp", "8.8.8.8:80") // Google's DNS
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	fmt.Println("LAN IP:", localAddr.IP)
}

func publicIP() {
	// Use a public STUN server (no REST API, just UDP protocol)
	conn, err := stun.Dial("udp4", "stun.l.google.com:19302")
	if err != nil {
		log.Fatal(err)
	}

	var xorAddr stun.XORMappedAddress
	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	err = conn.Do(message, func(res stun.Event) {
		if res.Error != nil {
			log.Fatal(res.Error)
		}
		if err := xorAddr.GetFrom(res.Message); err != nil {
			log.Fatal(err)
		}
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Public IP:", xorAddr.IP)
	fmt.Println("Port:", xorAddr.Port)
}

// --- Multi-peer server ---
func runServer(addr string, alias string) {
	iceServers := []webrtc.ICEServer{
		{URLs: []string{"stun:stun.l.google.com:19302"}},
	}
	config := webrtc.Configuration{ICEServers: iceServers}

	var (
		mu    sync.Mutex
		peers []*peer
	)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Server listening for signaling on", addr)

	// Broadcast helper (for chat)
	broadcast := func(sender *peer, msg string) {
		mu.Lock()
		defer mu.Unlock()
		for _, p := range peers {
			if p != sender && p.dc != nil {
				_ = p.dc.SendText(msg)
			}
		}
	}

	// Accept loop
	for {
		sigConn, err := ln.Accept()
		if err != nil {
			log.Println("accept:", err)
			continue
		}
		go func(sigConn net.Conn) {
			defer sigConn.Close()
			peerConnection, err := webrtc.NewPeerConnection(config)
			if err != nil {
				log.Println("webrtc:", err)
				return
			}
			var p peer
			p.tracks = []*webrtc.TrackLocalStaticRTP{}
			sigReader := bufio.NewReader(sigConn)
			sigWriter := bufio.NewWriter(sigConn)
			send := func(msg signalMsg) error {
				b, _ := json.Marshal(msg)
				b = append(b, '\n')
				_, err := sigWriter.Write(b)
				if err != nil {
					return err
				}
				return sigWriter.Flush()
			}
			recv := func() (signalMsg, error) {
				line, err := sigReader.ReadBytes('\n')
				if err != nil {
					return signalMsg{}, err
				}
				var msg signalMsg
				err = json.Unmarshal(line, &msg)
				return msg, err
			}

			peerConnection.OnDataChannel(func(d *webrtc.DataChannel) {
				p.dc = d
				setupDataChannelMulti(d, &p, &mu, &peers, broadcast)
			})

			// Handle incoming media tracks and relay to other peers
			peerConnection.OnTrack(func(remoteTrack *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
				fmt.Printf("Received %s track from peer\n", remoteTrack.Kind().String())
				// Create a local track for relaying
				localTrack, err := webrtc.NewTrackLocalStaticRTP(remoteTrack.Codec().RTPCodecCapability, remoteTrack.ID(), remoteTrack.StreamID())
				if err != nil {
					log.Println("track relay error:", err)
					return
				}
				mu.Lock()
				p.tracks = append(p.tracks, localTrack)
				// Relay to all other peers
				for _, other := range peers {
					if other != &p {
						sender, err := otherAddTrack(other, localTrack)
						if err != nil {
							log.Println("add track error:", err)
							continue
						}
						go func() {
							rtcpBuf := make([]byte, 1500)
							for {
								if _, _, rtcpErr := sender.Read(rtcpBuf); rtcpErr != nil {
									return
								}
							}
						}()
					}
				}
				mu.Unlock()
				// Forward RTP packets from remote to local
				buf := make([]byte, 1500)
				for {
					n, _, readErr := remoteTrack.Read(buf)
					if readErr != nil {
						break
					}
					if _, writeErr := localTrack.Write(buf[:n]); writeErr != nil {
						break
					}
				}
			})

			peerConnection.OnICECandidate(func(c *webrtc.ICECandidate) {
				if c == nil {
					return
				}
				cand := c.ToJSON()
				_ = send(signalMsg{Cand: &cand})
			})

			// SDP exchange
			msg, err := recv()
			if err != nil || msg.SDP == nil {
				log.Println("Failed to receive offer")
				return
			}
			if err := peerConnection.SetRemoteDescription(*msg.SDP); err != nil {
				log.Println(err)
				return
			}
			answer, err := peerConnection.CreateAnswer(nil)
			if err != nil {
				log.Println(err)
				return
			}
			if err := peerConnection.SetLocalDescription(answer); err != nil {
				log.Println(err)
				return
			}
			_ = send(signalMsg{SDP: &answer})

			// ICE candidate loop
			go func() {
				for {
					msg, err := recv()
					if err != nil {
						return
					}
					if msg.Cand != nil {
						_ = peerConnection.AddICECandidate(*msg.Cand)
					}
				}
			}()

			// Track peer and cleanup
			done := make(chan struct{})
			peerConnection.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
				if state == webrtc.PeerConnectionStateClosed ||
					state == webrtc.PeerConnectionStateFailed ||
					state == webrtc.PeerConnectionStateDisconnected {
					fmt.Println("Peer disconnected")
					close(done)
				}
			})

			// Add to peer list
			mu.Lock()
			peers = append(peers, &p)
			mu.Unlock()

			<-done

			// Remove from peer list
			mu.Lock()
			for i, pp := range peers {
				if pp == &p {
					peers = append(peers[:i], peers[i+1:]...)
					break
				}
			}
			mu.Unlock()
		}(sigConn)
	}
}

// Helper to add a track to a peer's connection
func otherAddTrack(p *peer, track *webrtc.TrackLocalStaticRTP) (*webrtc.RTPSender, error) {
	// Instead of trying to get PeerConnection from DataChannel,
	// pass and store the PeerConnection directly in the peer struct.
	return nil, fmt.Errorf("not implemented: see note below")
}

// --- Client ---
func runClient(addr string, alias string) {
	iceServers := []webrtc.ICEServer{
		{URLs: []string{"stun:stun.l.google.com:19302"}},
	}
	config := webrtc.Configuration{ICEServers: iceServers}
	peerConnection, err := webrtc.NewPeerConnection(config)
	if err != nil {
		log.Fatal(err)
	}

	// Add local video and audio tracks (dummy, for demo)
	videoTrack, err := webrtc.NewTrackLocalStaticSample(webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8}, "video", "pion")
	if err == nil {
		_, _ = peerConnection.AddTrack(videoTrack)
	}
	audioTrack, err := webrtc.NewTrackLocalStaticSample(webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus}, "audio", "pion")
	if err == nil {
		_, _ = peerConnection.AddTrack(audioTrack)
	}
	// NOTE: To send real video/audio, integrate with pion/mediadevices or similar.

	var dc *webrtc.DataChannel
	dc, err = peerConnection.CreateDataChannel("chat", nil)
	if err != nil {
		log.Fatal(err)
	}
	setupDataChannelWithAlias(dc, alias)

	var sigConn net.Conn
	for {
		sigConn, err = net.Dial("tcp", addr)
		if err == nil {
			break
		}
		time.Sleep(1 * time.Second)
	}
	defer sigConn.Close()
	sigReader := bufio.NewReader(sigConn)
	sigWriter := bufio.NewWriter(sigConn)
	send := func(msg signalMsg) error {
		b, _ := json.Marshal(msg)
		b = append(b, '\n')
		_, err := sigWriter.Write(b)
		if err != nil {
			return err
		}
		return sigWriter.Flush()
	}
	recv := func() (signalMsg, error) {
		line, err := sigReader.ReadBytes('\n')
		if err != nil {
			return signalMsg{}, err
		}
		var msg signalMsg
		err = json.Unmarshal(line, &msg)
		return msg, err
	}

	peerConnection.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		cand := c.ToJSON()
		_ = send(signalMsg{Cand: &cand})
	})

	// Print info about incoming tracks
	peerConnection.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		fmt.Printf("Received %s track from peer\n", track.Kind().String())
		// For demo: just print info. To play, integrate with a media library.
	})

	offer, err := peerConnection.CreateOffer(nil)
	if err != nil {
		log.Fatal(err)
	}
	if err := peerConnection.SetLocalDescription(offer); err != nil {
		log.Fatal(err)
	}
	_ = send(signalMsg{SDP: &offer})
	msg, err := recv()
	if err != nil || msg.SDP == nil {
		log.Fatal("Failed to receive answer")
	}
	if err := peerConnection.SetRemoteDescription(*msg.SDP); err != nil {
		log.Fatal(err)
	}

	// ICE candidate loop
	go func() {
		for {
			msg, err := recv()
			if err != nil {
				return
			}
			if msg.Cand != nil {
				_ = peerConnection.AddICECandidate(*msg.Cand)
			}
		}
	}()

	// Wait for connection close
	done := make(chan struct{})
	peerConnection.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		if state == webrtc.PeerConnectionStateClosed ||
			state == webrtc.PeerConnectionStateFailed ||
			state == webrtc.PeerConnectionStateDisconnected {
			fmt.Println("Connection closed")
			close(done)
		}
	})

	// Send messages
	go func() {
		stdin := bufio.NewReader(os.Stdin)
		for {
			fmt.Print("You: ")
			text, _ := stdin.ReadString('\n')
			if dc != nil {
				// Send alias and message as JSON
				msg := struct {
					Alias string `json:"alias"`
					Text  string `json:"text"`
				}{Alias: alias, Text: text}
				b, _ := json.Marshal(msg)
				dc.SendText(string(b))
			}
		}
	}()

	<-done
}

// --- DataChannel handlers ---
func setupDataChannel(dc *webrtc.DataChannel) {
	dc.OnOpen(func() {
		fmt.Println("DataChannel open!")
	})
	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		// Expect JSON with alias and text
		var m struct {
			Alias string `json:"alias"`
			Text  string `json:"text"`
		}
		if err := json.Unmarshal(msg.Data, &m); err == nil && m.Alias != "" {
			fmt.Printf("%s: %s", m.Alias, m.Text)
		} else {
			fmt.Printf("Peer: %s\n", string(msg.Data))
		}
	})
}

func setupDataChannelWithAlias(dc *webrtc.DataChannel, alias string) {
	setupDataChannel(dc)
}

func setupDataChannelMulti(dc *webrtc.DataChannel, p *peer, mu *sync.Mutex, peers *[]*peer, broadcast func(sender *peer, msg string)) {
	dc.OnOpen(func() {
		fmt.Println("Peer joined the chat!")
	})
	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		// Expect JSON with alias and text
		var m struct {
			Alias string `json:"alias"`
			Text  string `json:"text"`
		}
		if err := json.Unmarshal(msg.Data, &m); err == nil && m.Alias != "" {
			fmt.Printf("%s: %s", m.Alias, m.Text)
			broadcast(p, string(msg.Data))
		} else {
			fmt.Printf("Peer: %s", string(msg.Data))
			broadcast(p, string(msg.Data))
		}
	})
}
