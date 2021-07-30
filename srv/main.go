import (
	"os"
	"sync"

	"github.com/confluentinc/confluent-kafka-go/kafka"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func iterPackets(packetSource *gopacket.PacketSource) {
	var wg sync.WaitGroup
	done := make(chan struct{})

	broker := viper.Get("BROKER")
	topic := viper.Get("TOPIC")

	p, err := kafka.NewProducer(&kafka.ConfigMap{"bootstrap.servers": broker})

	if err != nil {
		logrus.Fatal("Failed to create producer: %s\n", err)
		os.Exit(1)
	}

	logrus.Debug("Created Producer %v\n", p)

	wg.Add(1)
	go func() {
		for e := range p.Events() {
			switch ev := e.(type) {
			case *kafka.Message:
				m := ev
				if m.TopicPartition.Error != nil {
					logrus.Fatal("Delivery failed: %v\n", m.TopicPartition.Error)
				} else {
					logrus.Debug("Delivered message to topic %s [%d] at offset %v\n",
						*m.TopicPartition.Topic, m.TopicPartition.Partition, m.TopicPartition.Offset)
				}
				return

			default:
				logrus.Debug("Ignored event: %s\n", ev)
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for packet := range packetSource.Packets() {
			//Check output
			logrus.Debug(packet.Dump())
			p.ProduceChannel() <- &kafka.Message{TopicPartition: kafka.TopicPartition{Topic: &topic, Partition: kafka.PartitionAny}, Value: []byte(packet.Data())}
		}
	}()
}

//Sniff takes ifname and filter string as parameter.
//Packets are decoded and inserted to ES in handlePacket()
func Sniff(ifname, filter string) {
	logrus.Debug("Initializing libpcap")
	if handle, err := pcap.OpenLive(ifname, 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter(filter); err != nil { // optional
		logrus.Debug("No filter set or failed to set filter.")
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		logrus.Debug("New packet source initialized.")
		iterPackets(packetSource)
	}
}
