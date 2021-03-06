package gateway

import (
	"time"

	"github.com/maledog/lora-packet-forwarder-client/gateway/band"
)

// RXPacket contains the PHYPayload received from the gateway.
type RXPacket struct {
	RXInfo     RXInfo `json:"rxInfo"`
	PHYPayload []byte `json:"phyPayload"`
}

// RXPacketBytes contains the PHYPayload as []byte received from the gateway.
// The JSON output is compatible with RXPacket.
type RXPacketBytes struct {
	RXInfo     RXInfo `json:"rxInfo"`
	PHYPayload []byte `json:"phyPayload"`
}

// RXInfo contains the RX information.
type RXInfo struct {
	MAC       Mac           `json:"mac"`            // MAC address of the gateway
	Time      time.Time     `json:"time,omitempty"` // receive time
	Timestamp uint32        `json:"timestamp"`      // gateway internal receive timestamp with microsecond precision, will rollover every ~ 72 minutes
	Frequency int           `json:"frequency"`      // frequency in Hz
	Channel   int           `json:"channel"`        // concentrator IF channel used for RX
	RFChain   int           `json:"rfChain"`        // RF chain used for RX
	CRCStatus int           `json:"crcStatus"`      // 1 = OK, -1 = fail, 0 = no CRC
	CodeRate  string        `json:"codeRate"`       // ECC code rate
	RSSI      int           `json:"rssi"`           // RSSI in dBm
	LoRaSNR   float64       `json:"loRaSNR"`        // LoRa signal-to-noise ratio in dB
	Size      int           `json:"size"`           // packet payload size
	DataRate  band.DataRate `json:"dataRate"`       // RX datarate (either LoRa or FSK)
}

// TXPacket contains the PHYPayload which should be send to the
// gateway.
type TXPacket struct {
	TXInfo     TXInfo `json:"txInfo"`
	PHYPayload []byte `json:"phyPayload"`
}

// TXPacketBytes contains the PHYPayload as []byte which should be send to the
// gateway. The JSON output is compatible with TXPacket.
type TXPacketBytes struct {
	TXInfo     TXInfo `json:"txInfo"`
	PHYPayload []byte `json:"phyPayload"`
}

// TXInfo contains the information used for TX.
type TXInfo struct {
	MAC         Mac           `json:"mac"`         // MAC address of the gateway
	Immediately bool          `json:"immediately"` // send the packet immediately (ignore Time)
	Timestamp   uint32        `json:"timestamp"`   // gateway internal receive timestamp with microsecond precision, will rollover every ~ 72 minutes
	Frequency   int           `json:"frequency"`   // frequency in Hz
	Power       int           `json:"power"`       // TX power to use in dBm
	DataRate    band.DataRate `json:"dataRate"`    // TX datarate (either LoRa or FSK)
	CodeRate    string        `json:"codeRate"`    // ECC code rate
	IPol        *bool         `json:"iPol"`        // when left nil, the gateway-bridge will use the default (true for LoRa modulation)
}

// GatewayStatsPacket contains the information of a gateway.
type GatewayStatsPacket struct {
	MAC                 Mac                    `json:"mac"`
	Time                time.Time              `json:"time,omitempty"`
	Latitude            float64                `json:"latitude"`
	Longitude           float64                `json:"longitude"`
	Altitude            float64                `json:"altitude"`
	RXPacketsReceived   int                    `json:"rxPacketsReceived"`
	RXPacketsReceivedOK int                    `json:"rxPacketsReceivedOK"`
	TXPacketsEmitted    int                    `json:"txPacketsEmitted"`
	CustomData          map[string]interface{} `json:"customData"` // custom fields defined by alternative packet_forwarder versions (e.g. TTN sends platform, contactEmail, and description)
}
