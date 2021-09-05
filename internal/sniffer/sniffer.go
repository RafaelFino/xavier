package sniffer

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
	DnsQuery        string
	DnsAnswer       []string
	DnsAnswerTTL    []string
	NumberOfAnswers string
	DnsResponseCode int
	DnsOpCode       string
	Hostname        string
}

type DNSQueryRequest func() (msg *DnsMsg)

type DnsSniffer struct {
	Hostname string
	logger *logrus.Logger
	callback DNSQueryRequest
	
}

func New(logger *logrus.Logger, callback DNSQueryRequest) *DnsSniffer {
	hostname, _ := os.Hostname()
	return &DnsSniffer{Hostname: hostname, logger: logger, callback: callback}
}

func (s *DnsSniffer) Start() error {
	s.logger.Infof("Starting...")

	devices, devErr := pcap.FindAllDevs()
	if devErr != nil {
		s.logger.Fatal(devErr)
	}

	for _, device := range devices {
		if len(device.Addresses) > 0 {
			var adds []string
			for _, add := range device.Addresses {
				adds = append(adds, fmt.Sprintf("IP %s/%s", add.IP.String(), net.IP(add.Netmask)))
			}
			s.logger.Infof("[%s] Addresses: [%s]", device.Name, strings.Join(adds, ", "))
			s.logger.Infof("[%s] Starting to read...", device.Name)
			go read(device)
		} else {
			s.logger.Debugf("Device with no addresses, ignoring %s", device.Name)
		}
	}
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
		data, _, err := handle.ReadPacketData()
		if err != nil {
			s.logger.Errorf("Error reading packet data: ", err)
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
								DnsQuery:        string(dnsQuestion.Name),
								DnsOpCode:       strconv.Itoa(dnsOpCode),
								DnsResponseCode: int(dns.ResponseCode),
								NumberOfAnswers: strconv.Itoa(dnsANCount),
								Hostname:        hostname}

							if dnsANCount > 0 {
								for _, dnsAnswer := range dns.Answers {
									d.DnsAnswerTTL = append(d.DnsAnswerTTL, fmt.Sprint(dnsAnswer.TTL))
									if dnsAnswer.IP.String() != "<nil>" {
										d.DnsAnswer = append(d.DnsAnswer, dnsAnswer.IP.String())
									}
								}
							}

							s.sendMsg(d)
						}
					}

				}
			}
		} else {
			s.logger.Errorf("Error encountered: %s: %s", err, data)
		}
	}
}

func (s *DnsSniffer) sendMsg(msg *DnsMsg) {
	s.logger.Debugf("[%s:%s] %s: %s", msg.Hostname, msg.Device, msg.Message, msg.DnsQuery)
	//callback
}
