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
  Link        LinkLayerDoc        `json:"link_layer"`
  Network     NetworkLayerDoc     `json:"network_layer"`
  Transport   TransportLayerDoc   `json:"transport_layer"`
  App         ApplicationLayerDoc `json:"application_layer"`
}

type LinkLayerDoc struct {
  LayerType  string  `json:"layer_type"`
  SrcMAC     string  `json:"src_mac"`
  DstMAC     string  `json:"dst_mac"`
}

func parseLinkLayer(packet gopacket.Packet) LinkLayerDoc {
  out := new(LinkLayerDoc)
  if layer := packet.LinkLayer(); layer != nil {
    out.LayerType = layer.LayerType().String()
    lType := layer.LayerType()
    switch {
      case lType == layers.LayerTypeEthernet:
        out.SrcMAC = layer.LinkFlow().Src().String()
        out.DstMAC = layer.LinkFlow().Dst().String()
      case lType == layers.LayerTypeARP:
        logrus.Debug(layer)
    }
  }
  return *out
}

type NetworkLayerDoc struct {
  LayerType  string  `json:"layer_type"`
  SrcIP      string  `json:"src_ip"`
  DstIP      string  `json:"dst_ip"`
}

func parseNetworkLayer(packet gopacket.Packet) NetworkLayerDoc {
  out := new(NetworkLayerDoc)
  if layer := packet.NetworkLayer(); layer != nil {
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
  }
  return *out
}

type TransportLayerDoc struct {
  LayerType  string   `json:"layer_type"`
  SrcPort    string   `json:"src_port"`
  DstPort    string   `json:"dst_port"`
}

func parseTransportLayer(packet gopacket.Packet) TransportLayerDoc {
  out := new(TransportLayerDoc)
  if layer := packet.TransportLayer(); layer != nil {
  out.LayerType = layer.LayerType().String()
  lType := layer.LayerType()
  switch {
  case lType == layers.LayerTypeTCP:
    out.SrcPort = layer.TransportFlow().Src().String()
    out.DstPort = layer.TransportFlow().Dst().String()
  case lType == layers.LayerTypeUDP:
    out.SrcPort = layer.TransportFlow().Src().String()
    out.DstPort = layer.TransportFlow().Dst().String()
  }
  }
  return *out
}

type ApplicationLayerDoc struct {
  Payload string  `json:"payload"`
}

func parseApplicationLayer(packet gopacket.Packet) ApplicationLayerDoc {
  out := new(ApplicationLayerDoc)
  if app := packet.ApplicationLayer(); app != nil {
    logrus.Debug(string(app.Payload()))
    out.Payload = string(app.Payload())
  }
  return *out
}

func handleArpPacket(packet gopacket.Packet) {
  //arpLayer := packet.Layer(layers.LayerTypeARP)
  //arp := arpLayer.(*layers.ARP)
  //logrus.Debug(arp)
  //logrus.Debug(packet)
  parseLinkLayer(packet)
}

func handleTCPUDPPacket(packet gopacket.Packet) PacketDocument {
  out := new(PacketDocument)
  link := parseLinkLayer(packet)
  net := parseNetworkLayer(packet)
  trans := parseTransportLayer(packet)
  app := parseApplicationLayer(packet)
  
  out.Link = link
  out.Network = net
  out.Transport = trans
  out.App = app
  return *out
}

func handlePacket(packet gopacket.Packet) PacketDocument {
  out := new(PacketDocument)
  arpLayer := packet.Layer(layers.LayerTypeARP)
  switch {
    case arpLayer != nil:
      //handleArpPacket(packet)
    default:
      out := handleTCPUDPPacket(packet)
      return out
  }
  return *out
}

func insertPackets(packetsIn chan PacketDocument, done chan struct{}, wg *sync.WaitGroup) {
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
	packetsOut := make(chan PacketDocument)
	done := make(chan struct{})

  wg.Add(1)
  go func() {
    defer wg.Done()
    for packet := range packetSource.Packets() {
      packetOut := handlePacket(packet)
      packetsOut <- packetOut
    }
  }()

  wg.Add(1)
  insertPackets(packetsOut, done, &wg)
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