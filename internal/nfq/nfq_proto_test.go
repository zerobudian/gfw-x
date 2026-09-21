package nfq

import (
	"encoding/binary"
	"testing"
)

// buildFakePacketMsg constructs a wire-format NFQNL_MSG_PACKET message the way
// the kernel delivers it, so parsePacketMsg can be tested on any platform.
func buildFakePacketMsg(t *testing.T, queue uint16, id uint32, payload []byte) []byte {
	t.Helper()
	native := binary.NativeEndian
	var msg []byte

	nl := make([]byte, 16)
	native.PutUint32(nl[0:], 0) // length fixed below
	native.PutUint16(nl[4:], nfqnlType(NFQNL_MSG_PACKET))
	native.PutUint16(nl[6:], 0)
	native.PutUint32(nl[8:], 1)
	native.PutUint32(nl[12:], 0)

	nf := make([]byte, 4)
	nf[0] = 2 // AF_INET
	nf[1] = 0
	binary.BigEndian.PutUint16(nf[2:], queue)

	// NFQA_PACKET_HDR (1): 4-byte nlattr + 8-byte struct.
	ph := make([]byte, 4+8)
	native.PutUint16(ph[0:], 12)
	native.PutUint16(ph[2:], NFQA_PACKET_HDR)
	binary.BigEndian.PutUint32(ph[4:], id)
	binary.BigEndian.PutUint16(ph[8:], 0x0800)
	ph[10] = 0 // hook
	ph[11] = 0

	// NFQA_PAYLOAD (10): aligned nlattr + payload.
	payloadAttrLen := 4 + len(payload)
	pad := (4 - (payloadAttrLen % 4)) % 4
	pa := make([]byte, payloadAttrLen+pad)
	native.PutUint16(pa[0:], uint16(payloadAttrLen))
	native.PutUint16(pa[2:], NFQA_PAYLOAD)
	copy(pa[4:], payload)

	msg = append(msg, nl...)
	msg = append(msg, nf...)
	msg = append(msg, ph...)
	msg = append(msg, pa...)
	native.PutUint32(msg[0:], uint32(len(msg)))
	return msg
}

func TestParsePacketMsg(t *testing.T) {
	payload := []byte{0x45, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00}
	msg := buildFakePacketMsg(t, 100, 0xDEADBEEF, payload)

	got, meta, err := parsePacketMsg(msg)
	if err != nil {
		t.Fatalf("parsePacketMsg: %v", err)
	}
	if meta.Queue != 100 {
		t.Fatalf("queue = %d, want 100", meta.Queue)
	}
	if meta.ID != 0xDEADBEEF {
		t.Fatalf("id = %08x, want deadbeef", uint32(meta.ID))
	}
	if string(got) != string(payload) {
		t.Fatalf("payload = %v, want %v", got, payload)
	}
}

func TestParsePacketMsgTruncated(t *testing.T) {
	msg := buildFakePacketMsg(t, 5, 7, []byte{0x01})
	// Truncate inside the packet header attribute.
	if _, _, err := parsePacketMsg(msg[:24]); err == nil {
		t.Fatal("expected error for truncated message")
	}
	// Missing payload attribute → clear error.
	noPayload := buildFakePacketMsg(t, 5, 7, []byte{0x01})
	native := binary.NativeEndian
	noPayload = noPayload[:len(noPayload)-5] // drop payload attr
	if _, _, err := parsePacketMsg(noPayload); err == nil {
		t.Fatal("expected error for missing payload")
	}
	_ = native
}

func TestVerdictFor(t *testing.T) {
	for _, in := range []string{"drop", "block", "reject", "ratelimit"} {
		if verdictFor(in) != NF_DROP {
			t.Fatalf("verdictFor(%q) = %d, want NF_DROP", in, verdictFor(in))
		}
	}
	for _, in := range []string{"allow", "observe", "", "weird"} {
		if verdictFor(in) != NF_ACCEPT {
			t.Fatalf("verdictFor(%q) = %d, want NF_ACCEPT", in, verdictFor(in))
		}
	}
}

func TestBuildVerdictRoundtrip(t *testing.T) {
	// Echo semantics: the verdict id must reproduce the received bytes so the
	// kernel can match it back to the enqueued packet.
	seq, pid := uint32(42), uint32(0)
	meta := Meta{Queue: 7, ID: 0xAABBCCDD}
	buf := buildVerdict(seq, pid, meta, NF_ACCEPT)

	native := binary.NativeEndian
	if n := native.Uint32(buf[0:]); n != uint32(len(buf)) {
		t.Fatalf("nlmsg len = %d, want %d", n, len(buf))
	}
	if ty := native.Uint16(buf[4:]); ty != nfqnlType(NFQNL_MSG_VERDICT) {
		t.Fatalf("type = %04x, want %04x", ty, nfqnlType(NFQNL_MSG_VERDICT))
	}
	if q := binary.BigEndian.Uint16(buf[18:]); q != 7 {
		t.Fatalf("queue = %d, want 7", q)
	}
	// verdict + id at the attribute body.
	v := binary.BigEndian.Uint32(buf[24:])
	if v != NF_ACCEPT {
		t.Fatalf("verdict = %d, want %d", v, NF_ACCEPT)
	}
	id := binary.BigEndian.Uint32(buf[28:])
	if id != uint32(meta.ID) {
		t.Fatalf("id = %08x, want %08x", id, uint32(meta.ID))
	}
}

func TestBuildConfigMarshal(t *testing.T) {
	buf := buildConfigMarshal(9, 0, 55, &nfqnlMsgConfigCmd{Command: NFQNL_CFG_CMD_BIND}, &nfqnlMsgConfigParams{CopyMode: NFQNL_COPY_PACKET, CopyRange: 0xff})
	native := binary.NativeEndian
	if n := native.Uint32(buf[0:]); n != uint32(len(buf)) {
		t.Fatalf("nlmsg len = %d, want %d", n, len(buf))
	}
	if ty := native.Uint16(buf[4:]); ty != nfqnlType(NFQNL_MSG_CONFIG) {
		t.Fatalf("type = %04x", ty)
	}
	if seq := native.Uint32(buf[8:]); seq != 9 {
		t.Fatalf("seq = %d, want 9", seq)
	}
	if q := binary.BigEndian.Uint16(buf[18:]); q != 55 {
		t.Fatalf("res_id = %d, want 55", q)
	}
	if buf[20] != NFQNL_CFG_CMD_BIND {
		t.Fatalf("command = %d, want BIND", buf[20])
	}
	// struct nfqnl_msg_config_params { copy_range; copy_mode; }
	if buf[24] != 0xff {
		t.Fatalf("copy_range = %d, want 0xff", buf[24])
	}
	if buf[25] != NFQNL_COPY_PACKET {
		t.Fatalf("copy_mode = %d, want COPY_PACKET", buf[25])
	}
}
