package dnssniffer

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
)

type DnsMsg struct {
	Timestamp       time.Time
	Device          string
	Message         string
	SourceIP        string
	DestinationIP   string
	Query           string
	Answer          []string
	AnswerTTL       []string
	NumberOfAnswers string
	DnsResponseCode int
	DnsOpCode       string
	Hostname        string
}

type DNSQueryRequest func(*DnsMsg)

type DnsSniffer struct {
	Hostname  string
	logger    *logrus.Logger
	callback  DNSQueryRequest
	endSignal chan bool
}

func New(logger *logrus.Logger, callback DNSQueryRequest) *DnsSniffer {
	hostname, _ := os.Hostname()
	ret := &DnsSniffer{
		Hostname:  hostname,
		logger:    logger,
		callback:  callback,
		endSignal: make(chan bool),
	}

	go ret.start()

	return ret
}

func (s *DnsSniffer) start() error {
	s.logger.Infof("Starting...")

	devices, devErr := pcap.FindAllDevs()
	if devErr != nil {
		s.logger.Fatal(devErr)
		return devErr
	}

	for _, device := range devices {
		if len(device.Addresses) > 0 {
			var adds []string
			for _, add := range device.Addresses {
				adds = append(adds, fmt.Sprintf("IP %s/%s", add.IP.String(), net.IP(add.Netmask)))
			}
			s.logger.Infof("[%s] Addresses: [%s]", device.Name, strings.Join(adds, ", "))
			s.logger.Infof("[%s] Starting to read...", device.Name)
			go s.read(device)
		} else {
			s.logger.Debugf("Device with no addresses, ignoring %s", device.Name)
		}
	}

	return nil
}

func (s *DnsSniffer) Stop() {
	s.endSignal <- true
}

func (s *DnsSniffer) read(dev pcap.Interface) {
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	var dns layers.DNS

	var SrcIP string
	var DstIP string

	var payload gopacket.Payload

	handle, err := pcap.OpenLive(dev.Name, 1600, false, pcap.BlockForever)
	if err != nil {
		s.logger.Fatal(err)
	}
	defer handle.Close()

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp, &dns, &payload)

	decodedLayers := make([]gopacket.LayerType, 0, 10)
	for {
		select {
		case <-s.endSignal:
			s.logger.Infof("Stop requested")
			return
		default:
			data, _, err := handle.ReadPacketData()
			if err != nil {
				s.logger.Errorf("Error reading packet data: %s", err.Error())
				continue
			}

			if err = parser.DecodeLayers(data, &decodedLayers); err == nil {
				for _, typ := range decodedLayers {
					switch typ {
					case layers.LayerTypeIPv4:
						SrcIP = ip4.SrcIP.String()
						DstIP = ip4.DstIP.String()
					case layers.LayerTypeIPv6:
						SrcIP = ip6.SrcIP.String()
						DstIP = ip6.DstIP.String()
					case layers.LayerTypeDNS:
						dnsOpCode := int(dns.OpCode)
						dnsANCount := int(dns.ANCount)

						if (dnsANCount == 0 && int(dns.ResponseCode) > 0) || (dnsANCount > 0) {
							for _, dnsQuestion := range dns.Questions {
								d := &DnsMsg{Timestamp: time.Now(),
									Device:          dev.Name,
									Message:         "DNS query detected",
									SourceIP:        SrcIP,
									DestinationIP:   DstIP,
									Query:           string(dnsQuestion.Name),
									DnsOpCode:       strconv.Itoa(dnsOpCode),
									DnsResponseCode: int(dns.ResponseCode),
									NumberOfAnswers: strconv.Itoa(dnsANCount),
									Hostname:        s.Hostname}

								if dnsANCount > 0 {
									for _, dnsAnswer := range dns.Answers {
										d.AnswerTTL = append(d.AnswerTTL, fmt.Sprint(dnsAnswer.TTL))
										if dnsAnswer.IP.String() != "<nil>" {
											d.Answer = append(d.Answer, dnsAnswer.IP.String())
										}
									}
								}

								s.sendMsg(d)
							}
						}

					}
				}
			} else {
				//s.logger.Debugf("Error encountered: %s: %s", err, data)
			}
		}
	}
}

func (s *DnsSniffer) sendMsg(msg *DnsMsg) {
	s.logger.Debugf("[%s:%s] %s: %s", msg.Hostname, msg.Device, msg.Message, msg.Query)
	s.callback(msg)
}
