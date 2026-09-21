// Package nfq implements the netfilter NFQUEUE data-plane backend. It speaks
// the netfilter_queue netlink protocol, yielding IP packets to the unified
// pipeline (internal/pipeline) and submitting ACCEPT/DROP verdicts back to the
// kernel. All Linux-specific socket code is in nfq_linux.go (build tag linux);
// this file is pure byte-fiddling so it can be unit tested on any platform.
package nfq

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Netfilter netlink constants (see linux/include/uapi/linux/netfilter/nfnetlink.h
// and netfilter/nfnetlink_queue.h).
const (
	NFNL_SUBSYS_QUEUE = 3

	NFQNL_MSG_PACKET  = 0
	NFQNL_MSG_VERDICT = 1
	NFQNL_MSG_CONFIG  = 2

	// nfqnl_msg_config_cmd.command values.
	NFQNL_CFG_CMD_PF_BIND = 3
	NFQNL_CFG_CMD_BIND    = 1
	NFQNL_CFG_CMD_PF_UNB  = 4
	NFQNL_CFG_CMD_UNBIND  = 2
)

// nfqnl_msg_config_params.copy_mode values.
const (
	NFQNL_COPY_META   = 1
	NFQNL_COPY_PACKET = 2
)

// verdict values (linux/netfilter.h).
const (
	NF_DROP   = 0
	NF_ACCEPT = 1
)

// nfqnl attributes (u16/u16 in netlink attribute TLV).
const (
	NFQA_PACKET_HDR  = 1
	NFQA_VERDICT_HDR = 2
	NFQA_MARK        = 3
	NFQA_PAYLOAD     = 10
)

// PacketID aliases the per-packet kernel id used to correlate a verdict with
// the packet originally delivered to the queue.
type PacketID uint32

// Meta is stored in pipeline.Packet.Meta so the verdict sink can return a
// verdict for the exact packet enqueued by the kernel.
type Meta struct {
	Queue uint16
	ID    PacketID
}

// nfqnlMsgConfigCmd mirrors struct nfqnl_msg_config_cmd (4 bytes on wire).
type nfqnlMsgConfigCmd struct {
	Command uint8
	Pad     uint8
	PF      uint16 // network byte order
}

// nfqnlMsgConfigParams mirrors struct nfqnl_msg_config_params (2 bytes).
type nfqnlMsgConfigParams struct {
	CopyRange uint8
	CopyMode  uint8
}

// nfqnl_msg_packet_hdr is 8 bytes on the wire:
//
//	PacketID    uint32 (network byte order)
//	HWProtocol  uint16 (network byte order)
//	Hook        uint8
//	Pad         uint8

// nfqnl_msg_verdict_hdr is 8 bytes on the wire:
//
//	Verdict  uint32 (network byte order)
//	ID       uint32 (network byte order)

// buildConfigMarshal formats an NFQNL_MSG_CONFIG payload.
// seq is the netlink sequence number; family is the netfilter family
// (AF_UNSPEC for queue operations, AF_INET for a PF bind). resID is the queue
// number carried in nfgenmsg.res_id (network byte order).
func buildConfigMarshal(seq uint32, family uint8, resID uint16, cmd *nfqnlMsgConfigCmd, params *nfqnlMsgConfigParams) []byte {
	native := binary.NativeEndian
	haveParams := params != nil
	plen := 4 + 4
	if haveParams {
		plen += 2
	}
	buf := make([]byte, 16+plen)

	// netlink header (native byte order).
	native.PutUint32(buf[0:], uint32(len(buf)))
	native.PutUint16(buf[4:], nfqnlType(NFQNL_MSG_CONFIG))
	native.PutUint16(buf[6:], NFLG_REQUEST)
	native.PutUint32(buf[8:], seq)
	native.PutUint32(buf[12:], 0) // pid = 0 (kernel)

	// nfgenmsg: res_id is network byte order.
	buf[16] = family
	buf[17] = 0 // version = NFNETLINK_V0
	binary.BigEndian.PutUint16(buf[18:], resID)

	// config cmd: pf is network byte order.
	buf[20] = cmd.Command
	buf[21] = cmd.Pad
	binary.BigEndian.PutUint16(buf[22:], cmd.PF)

	if haveParams {
		buf[24] = params.CopyRange
		buf[25] = params.CopyMode
	}
	return buf
}

// NFLG_REQUEST is NLM_F_REQUEST (netlink request flag).
const NFLG_REQUEST = 1

// nfqnlType computes the netlink message type for a queue subsystem message.
func nfqnlType(low byte) uint16 { return uint16(NFNL_SUBSYS_QUEUE)<<8 | uint16(low) }

// errShort is returned when a netfilter message is malformed / truncated.
var errShort = errors.New("nfq: truncated netfilter message")

// parsePacketMsg extracts the packet metadata + payload from an
// NFQNL_MSG_PACKET netlink message delivered by the kernel.
// Returns the payload and the Meta needed to return a verdict.
func parsePacketMsg(msg []byte) (payload []byte, meta Meta, err error) {
	// Skip the nlmsghdr (16) and nfgenmsg (4).
	if len(msg) < 20 {
		return nil, meta, errShort
	}
	native := binary.NativeEndian
	// nfgenmsg.res_id = queue number (network byte order on the wire).
	meta.Queue = binary.BigEndian.Uint16(msg[18:20])

	off := 20
	// Walk attributes: u16 len, u16 type, then payload.
	for off+4 <= len(msg) {
		alen := int(native.Uint16(msg[off:]))
		atype := native.Uint16(msg[off+2:])
		if alen < 4 || off+alen > len(msg) {
			return nil, meta, errShort
		}
		dataEnd := off + alen
		data := msg[off+4 : dataEnd]
		switch atype {
		case NFQA_PACKET_HDR:
			if len(data) < 8 {
				return nil, meta, errShort
			}
			// packet_id is __be32 on the wire; decode to host order so callers
			// see a clean id, and re-encode big-endian in the verdict later.
			meta.ID = PacketID(binary.BigEndian.Uint32(data[0:4]))
		case NFQA_PAYLOAD:
			payload = data
		}
		// Advance to the next attribute, respecting 4-byte alignment.
		off = (dataEnd + 3) &^ 3
	}
	if meta.ID == 0 {
		return nil, meta, fmt.Errorf("nfq: packet message missing packet id")
	}
	if payload == nil {
		return nil, meta, fmt.Errorf("nfq: packet message missing payload (copy mode not set to COPY_PACKET?)")
	}
	return payload, meta, nil
}

// buildVerdict formats an NFQNL_MSG_VERDICT message for a given packet.
// seq is the netlink sequence; verdict must be NF_ACCEPT or NF_DROP.
func buildVerdict(seq, pid uint32, meta Meta, verdict uint32) []byte {
	native := binary.NativeEndian
	const attrs = 4 + 8 // nlattr(4) + verdict_hdr(8)
	buf := make([]byte, 16+4+attrs)

	// netlink header.
	native.PutUint32(buf[0:], uint32(len(buf)))
	native.PutUint16(buf[4:], nfqnlType(NFQNL_MSG_VERDICT))
	native.PutUint16(buf[6:], NFLG_REQUEST)
	native.PutUint32(buf[8:], seq)
	native.PutUint32(buf[12:], pid)

	// nfgenmsg: family AF_UNSPEC, res_id = queue number (network byte order).
	binary.BigEndian.PutUint16(buf[18:], meta.Queue)

	o := 20
	// nlattr header (type NFQA_VERDICT_HDR).
	native.PutUint16(buf[o:], uint16(attrs))
	native.PutUint16(buf[o+2:], NFQA_VERDICT_HDR)
	o += 4
	// verdict_hdr: verdict + id, both network byte order.
	binary.BigEndian.PutUint32(buf[o:], verdict)
	binary.BigEndian.PutUint32(buf[o+4:], uint32(meta.ID))
	return buf
}

// verdictFor maps a pipeline verdict to an NF_DROP / NF_ACCEPT kernel verdict.
// Unknown/string-empty verdicts are normalized to ACCEPT so misconfigurations
// never silently drop traffic (fail-open default; fail-closed handled by caller
// on transport errors).
func verdictFor(v string) uint32 {
	switch v {
	case "drop", "block", "reject", "ratelimit":
		return NF_DROP
	default:
		return NF_ACCEPT
	}
}
