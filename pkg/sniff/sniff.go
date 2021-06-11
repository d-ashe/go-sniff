package sniff

import (
  "time"
  "context"
  "sync"
  "bytes"
  "encoding/json"

	"github.com/sirupsen/logrus"
	"github.com/google/gopacket"
  "github.com/google/gopacket/layers"
  "github.com/google/gopacket/pfring"
	"github.com/elastic/go-elasticsearch/v8"
  "github.com/elastic/go-elasticsearch/v8/esutil"
)

type PacketDocument struct {
  SrcMAC   string   `json:"src_mac"`
  DstMAC   string   `json:"dst_mac"`
  SrcIP    string   `json:"src_ip"`
  DstIP    string   `json:"dst_ip"`
  SrcPort  string   `json:"src_port"`
  DstPort  string   `json:"dst_port"`
}

type LinkLayerDoc struct {
  LayerType  string  `json:"layer_type"`
  SrcMAC     string  `json:"src_mac"`
  DstMAC     string  `json:"dst_mac"`
}

func parseLinkLayer(layer gopacket.LinkLayer) *LinkLayerDoc {
  out := new(LinkLayerDoc)
  out.LayerType = layer.LayerType().String()
  lType := layer.LayerType()
  switch {
    case lType == layers.LayerTypeEthernet:
      out.SrcMAC = layer.LinkFlow().Src().String()
      out.DstMAC = layer.LinkFlow().Dst().String()
    case lType == layers.LayerTypeARP:
      logrus.Debug(layer)
  }
  //logrus.Debug(lType)
  return out
}

type NetworkLayerDoc struct {
  LayerType  string  `json:"layer_type"`
  SrcIP      string  `json:"src_ip"`
  DstIP      string  `json:"dst_ip"`
}

func parseNetworkLayer(layer gopacket.NetworkLayer) *NetworkLayerDoc {
  out := new(NetworkLayerDoc)
  out.LayerType = layer.LayerType().String()
  lType := layer.LayerType()
  switch {
    case lType == layers.LayerTypeIPv6:
      out.SrcIP = layer.NetworkFlow().Src().String()
      out.DstIP = layer.NetworkFlow().Dst().String()
    case lType == layers.LayerTypeIPv4:
      out.SrcIP = layer.NetworkFlow().Src().String()
      out.DstIP = layer.NetworkFlow().Dst().String()
  }
  return out
}

type TransportLayerDoc struct {
  LayerType  string   `json:"layer_type"`
  SrcPort    string   `json:"src_port"`
  DstPort    string   `json:"dst_port"`
}

func parseTransportLayer(layer gopacket.TransportLayer) *TransportLayerDoc {
  out := new(TransportLayerDoc)
  out.LayerType = layer.LayerType().String()
  //lType := layer.LayerType()
  
  return out
}

func handleArpPacket(packet gopacket.Packet) {
  arpLayer := packet.Layer(layers.LayerTypeARP)
  arp := arpLayer.(*layers.ARP)
  logrus.Debug(arp)
  logrus.Debug(packet)
}

func handleTCPUDPPacket(packet gopacket.Packet) {
  if link := packet.LinkLayer(); link != nil {
    parseLinkLayer(link)
    //logrus.Debug(link.LayerType())
    //logrus.Debug(link)
  }
  if net := packet.NetworkLayer(); net != nil {
    parseNetworkLayer(net)
    //logrus.Debug(net.LayerType())
    //logrus.Debug(net)
  }
  if trans := packet.TransportLayer(); trans != nil {
    parseTransportLayer(trans)
    //logrus.Debug(trans.LayerType())
    //logrus.Debug(trans)
  }
  if app := packet.ApplicationLayer(); app != nil {
    //logrus.Debug(app.LayerType())
    //logrus.Debug(app)
  }
}

func handlePacket(packet gopacket.Packet) {
  arpLayer := packet.Layer(layers.LayerTypeARP)
  switch {
    case arpLayer != nil:
      handleArpPacket(packet)
  }
}

func insertPackets(packetsIn chan gopacket.Packet, done chan struct{}, wg *sync.WaitGroup) {
  defer wg.Done()
  es, err := elasticsearch.NewDefaultClient()
  if err != nil {
    logrus.Fatal("Error creating the client: %s", err)
    panic(err)
  }
  res, err := es.Info()
  if err != nil {
    logrus.Fatal("Error getting response: %s", err)
    panic(err)
  }
  logrus.Debug(res)
  bi, err := esutil.NewBulkIndexer(esutil.BulkIndexerConfig{
    Index:         "packet",        // The default index name
    Client:        es,               // The Elasticsearch client
    NumWorkers:    20,       // The number of worker goroutines
    FlushBytes:    int(5e+6),  // The flush threshold in bytes
    FlushInterval: 30 * time.Second, // The periodic flush interval
  })
  if err != nil {
    logrus.Fatal("Error creating the indexer: %s", err)
    panic(err)
  }
  for {
		select {
		case <-done:
			return
    case data := <-packetsIn:
      bytesData, err := json.Marshal(data)
		  if err != nil {
		  	logrus.Fatal("Cannot encode article %d: %s", err)
		  }
      err = bi.Add(
		  	context.Background(),
		  	esutil.BulkIndexerItem{
		  		// Action field configures the operation to perform (index, create, delete, update)
		  		Action: "index",
  
		  		// Body is an `io.Reader` with the payload
		  		Body: bytes.NewReader(bytesData),
  
		  		// OnSuccess is called for each successful operation
		  		OnSuccess: func(ctx context.Context, item esutil.BulkIndexerItem, res esutil.BulkIndexerResponseItem) {
		  			logrus.Debug("Bulk insert success")
		  		},
  
		  		// OnFailure is called for each failed operation
		  		OnFailure: func(ctx context.Context, item esutil.BulkIndexerItem, res esutil.BulkIndexerResponseItem, err error) {
		  			if err != nil {
		  				logrus.Fatal("ERROR: %s", err)
		  			} else {
		  				logrus.Fatal("ERROR: %s: %s", res.Error.Type, res.Error.Reason)
		  			}
		  		},
		  	},
		  )
		if err != nil {
			logrus.Fatal("Unexpected error: %s", err)
		}
  }
}
}

func iterPackets(packetSource *gopacket.PacketSource) {
  var wg sync.WaitGroup
	packetsOut := make(chan gopacket.Packet)
	done := make(chan struct{})

  wg.Add(1)
  go func() {
    defer wg.Done()
    for packet := range packetSource.Packets() {
      handlePacket(packet)
      packetsOut <- packet
    }
  }()

  wg.Add(1)
  insertPackets(packetsOut, done, &wg)
  //for packet := range packetSource.Packets() {
    //handlePacket(packet)  // Do something with a packet here.
    //packetsOut = append(packetsOut, &packet)
  //}
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