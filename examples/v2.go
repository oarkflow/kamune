// Features:
// - Shows LAN and Public IP using STUN and UDP probing
// - Implements multi-peer WebRTC signaling server using TCP
// - Client supports sending/receiving chat messages via DataChannels
// - Audio/Video tracks are exchanged between peers (relay enabled)
// - ICE candidates exchanged via custom TCP-based signaling
// - Peer tracks relayed using TrackLocalStaticRTP for multi-user calls
// - Supports alias-based message formatting and broadcast
// - Logs RTP reception and peer connectivity changes
// - Minimal external dependencies (pion/webrtc and pion/stun)

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

	"github.com/pion/mediadevices"
	"github.com/pion/mediadevices/pkg/codec/opus"
	"github.com/pion/mediadevices/pkg/codec/x264"
	_ "github.com/pion/mediadevices/pkg/driver/camera"
	_ "github.com/pion/mediadevices/pkg/driver/microphone"
	"github.com/pion/stun"
	"github.com/pion/webrtc/v4"
)

type signalMsg struct {
	SDP  *webrtc.SessionDescription `json:"sdp,omitempty"`
	Cand *webrtc.ICECandidateInit   `json:"candidate,omitempty"`
}

type peer struct {
	conn   *webrtc.PeerConnection
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
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	fmt.Println("LAN IP:", localAddr.IP)
}

func publicIP() {
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

func runServer(addr, alias string) {
	iceServers := []webrtc.ICEServer{{URLs: []string{"stun:stun.l.google.com:19302"}}}
	config := webrtc.Configuration{ICEServers: iceServers}
	var mu sync.Mutex
	var peers []*peer

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Server listening for signaling on", addr)

	broadcast := func(sender *peer, msg string) {
		mu.Lock()
		defer mu.Unlock()
		for _, p := range peers {
			if p != sender && p.dc != nil {
				_ = p.dc.SendText(msg)
			}
		}
	}

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
			p.conn = peerConnection
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
			peerConnection.OnTrack(func(remoteTrack *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
				fmt.Printf("Received %s track from peer\n", remoteTrack.Kind().String())
				localTrack, err := webrtc.NewTrackLocalStaticRTP(remoteTrack.Codec().RTPCodecCapability, remoteTrack.ID(), remoteTrack.StreamID())
				if err != nil {
					log.Println("track relay error:", err)
					return
				}
				mu.Lock()
				p.tracks = append(p.tracks, localTrack)
				for _, other := range peers {
					if other != &p {
						sender, err := other.conn.AddTrack(localTrack)
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
				buf := make([]byte, 1500)
				for {
					n, _, err := remoteTrack.Read(buf)
					if err != nil {
						break
					}
					if _, err := localTrack.Write(buf[:n]); err != nil {
						break
					}
				}
			})
			peerConnection.OnICECandidate(func(c *webrtc.ICECandidate) {
				if c != nil {
					ct := c.ToJSON()
					_ = send(signalMsg{Cand: &ct})
				}
			})
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
			done := make(chan struct{})
			peerConnection.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
				if state == webrtc.PeerConnectionStateClosed ||
					state == webrtc.PeerConnectionStateFailed ||
					state == webrtc.PeerConnectionStateDisconnected {
					fmt.Println("Peer disconnected")
					close(done)
				}
			})
			mu.Lock()
			peers = append(peers, &p)
			mu.Unlock()
			<-done
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

func runClient(addr string, alias string) {
	iceServers := []webrtc.ICEServer{{URLs: []string{"stun:stun.l.google.com:19302"}}}
	config := webrtc.Configuration{ICEServers: iceServers}
	peerConnection, err := webrtc.NewPeerConnection(config)
	if err != nil {
		log.Fatal(err)
	}
	if err := setupMedia(peerConnection); err != nil {
		log.Fatal("media setup error:", err)
	}
	dc, err := peerConnection.CreateDataChannel("chat", nil)
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
		if c != nil {
			ct := c.ToJSON()
			_ = send(signalMsg{Cand: &ct})
		}
	})
	peerConnection.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		fmt.Printf("Received %s track from peer\n", track.Kind().String())
	})
	offer, _ := peerConnection.CreateOffer(nil)
	_ = peerConnection.SetLocalDescription(offer)
	_ = send(signalMsg{SDP: &offer})
	msg, err := recv()
	if err != nil || msg.SDP == nil {
		log.Fatal("Failed to receive answer")
	}
	_ = peerConnection.SetRemoteDescription(*msg.SDP)
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
	done := make(chan struct{})
	peerConnection.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		if state == webrtc.PeerConnectionStateClosed ||
			state == webrtc.PeerConnectionStateFailed ||
			state == webrtc.PeerConnectionStateDisconnected {
			fmt.Println("Connection closed")
			close(done)
		}
	})
	go func() {
		stdin := bufio.NewReader(os.Stdin)
		for {
			fmt.Print("You: ")
			text, _ := stdin.ReadString('\n')
			if dc != nil {
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

func setupDataChannel(dc *webrtc.DataChannel) {
	dc.OnOpen(func() {
		fmt.Println("DataChannel open!")
	})
	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
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

func setupMedia(pc *webrtc.PeerConnection) error {
	x264Params, err := x264.NewParams()
	if err != nil {
		return fmt.Errorf("x264 param: %w", err)
	}
	x264Params.Preset = x264.PresetMedium
	x264Params.BitRate = 1_000_000
	opusParams, err := opus.NewParams()
	if err != nil {
		return fmt.Errorf("opus param: %w", err)
	}
	opusParams.BitRate = 128_000

	selector := mediadevices.NewCodecSelector(
		mediadevices.WithVideoEncoders(&x264Params),
		mediadevices.WithAudioEncoders(&opusParams),
	)

	// Relax constraints to allow any available device
	stream, err := mediadevices.GetUserMedia(mediadevices.MediaStreamConstraints{
		Video: func(c *mediadevices.MediaTrackConstraints) {
			// Remove strict width/height/framerate constraints
			// Only set Codec selector
			// c.Width = prop.Int(640)
			// c.Height = prop.Int(480)
			// c.FrameRate = prop.Float(30)
		},
		Audio: func(c *mediadevices.MediaTrackConstraints) {},
		Codec: selector,
	})
	if err != nil {
		// Try again with video disabled (headless or no camera)
		stream, err = mediadevices.GetUserMedia(mediadevices.MediaStreamConstraints{
			Audio: func(c *mediadevices.MediaTrackConstraints) {},
			Codec: selector,
		})
		if err != nil {
			// Try again with audio disabled (no mic)
			stream, err = mediadevices.GetUserMedia(mediadevices.MediaStreamConstraints{
				Video: func(c *mediadevices.MediaTrackConstraints) {},
				Codec: selector,
			})
			if err != nil {
				return fmt.Errorf("get user media: %w", err)
			}
		}
	}

	for _, track := range stream.GetTracks() {
		if _, err := pc.AddTrack(track); err != nil {
			return fmt.Errorf("add track: %w", err)
		}
	}
	return nil
}
