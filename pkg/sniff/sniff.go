package sniff

import (
  "fmt"

	"github.com/sirupsen/logrus"
	"github.com/google/gopacket"
  "github.com/google/gopacket/layers"
  "github.com/google/gopacket/pfring"
	"github.com/elastic/go-elasticsearch/v8"
)

func handlePacket(packet gopacket.Packet) {
  fmt.Println(packet)
  logrus.Debug("Packet handled")
}

func iterPackets(packetSource *gopacket.PacketSource) {
  es, err := elasticsearch.NewDefaultClient()
    if err != nil {
      logrus.Fatal("Error creating the client: %s", err)
    }
    res, err := es.Info()
    if err != nil {
      logrus.Fatal("Error getting response: %s", err)
    }
    logrus.Debug(res)
    for packet := range packetSource.Packets() {
      handlePacket(packet)  // Do something with a packet here.
    }
}

//Sniff takes ifname and filter string as parameter. 
//Packets are decoded and inserted to ES in handlePacket()
func Sniff(ifname, filter string) { 
  logrus.Debug("Initializing new ring")
  if ring, err := pfring.NewRing(ifname, 65536, pfring.FlagPromisc); err != nil {
    logrus.Fatal("Failed to init new ring", err)
    panic(err)
  } else if err := ring.SetBPFFilter(filter); err != nil {  // optional
    logrus.Debug("No filter set or failed to set filter.")
  } else if err := ring.Enable(); err != nil { // Must do this!, or you get no packets!
    panic(err)
  } else {
    packetSource := gopacket.NewPacketSource(ring, layers.LinkTypeEthernet)
    logrus.Debug("New packet source initialized.")
    iterPackets(packetSource)
  }
}