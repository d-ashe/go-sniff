package sniff

import (
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/google/gopacket"

	"github.com/elastic/go-elasticsearch/v8"
)

func setupPacketSource(ifname, filter string)  gopacket.PacketDataSource {
	logrus.Debug("Initializing new packet data source")
	if ring, errRing := pfring.NewRing(ifname, 65536, pfring.FlagPromisc); errRing != nil {
		logrus.Fatal("Failed to init new ring", errRing)
		panic(errRing)
	} 
	if errFilter := ring.SetBPFFilter(filter); errFilter != nil {  // optional
		logrus.Fatal("Failed to set filter", errFilter)
	} 
	ring.SetSocketMode(pfring.ReadOnly)
	if errEnable := ring.Enable(); errEnable != nil { // Must do this!, or you get no packets!
		logrus.Fatal("Failed to enable ring", errEnable)
		panic(errEnable)
	} 
	packetSource := gopacket.NewPacketSource(ring, layers.LinkTypeEthernet)
	return packetSource
}

func handlePackets(packetSource gopacket.PacketDataSource) {
	var eth layers.Ethernet
    var ip4 layers.IPv4
    var ip6 layers.IPv6
    var tcp layers.TCP
    var udp layers.UDP
    var payload gopacket.Payload
    parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp, &payload)

    decodedLayers := make([]gopacket.LayerType, 0, 10)
    for packet := range packetSource.Packets() {
      fmt.Println("Decoding packet")
      err = parser.DecodeLayers(packet, &decodedLayers)
      for _, typ := range decodedLayers {
        fmt.Println("  Successfully decoded layer type", typ)
        switch typ {
          case layers.LayerTypeEthernet:
            fmt.Println("    Eth ", eth.SrcMAC, eth.DstMAC)
          case layers.LayerTypeIPv4:
            fmt.Println("    IP4 ", ip4.SrcIP, ip4.DstIP)
          case layers.LayerTypeIPv6:
            fmt.Println("    IP6 ", ip6.SrcIP, ip6.DstIP)
          case layers.LayerTypeTCP:
            fmt.Println("    TCP ", tcp.SrcPort, tcp.DstPort)
          case layers.LayerTypeUDP:
            fmt.Println("    UDP ", udp.SrcPort, udp.DstPort)
        }
      }
      if decodedLayers.Truncated {
        fmt.Println("  Packet has been truncated")
      }
      if err != nil {
        fmt.Println("  Error encountered:", err)
      }
    }
}

//Sniff takes ifname and filter string as parameter. 
//Packets are decoded and inserted to ES in handlePacket()
func Sniff(ifname, filter string) {
	packetSource := setupPacketSource(ifname, filter)

	handlePackets(packetSource)

}