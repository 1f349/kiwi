proto_kiwi = Proto("kiwi", "Kiwi")

magic_byte = 0x6e
min_packet_length = 12

Packet_Kind = {
  Hello = 0x39,
  HelloVerify = 0x2d,
  HelloFinish = 0x92,
  Ping = 0xb6,
  Pong = 0x1a,
  Ack = 0x7f,
  WholeData = 0x55,
  SegmentData = 0xde,
  decode = function(self, number)
    for type, code in pairs(self) do
      if not ("decode" == type) and number == code then
        return type
      end
    end
    return "Unknown"
  end
}

packet_kind_field = ProtoField.uint8("kiwi.packet_kind", "Kind", base.HEX)
sequence_field = ProtoField.uint32("kiwi.packet_sequence", "Sequence", base.DEC)
checksum_field = ProtoField.uint32("kiwi.packet_checksum", "Checksum", base.HEX)
packet_length_field = ProtoField.uint16("kiwi.packet_length", "Length", base.DEC)
packet_payload_field = ProtoField.none("kiwi.packet_payload", "Kiwi Payload", base.HEX)
packet_segment_id_field = ProtoField.uint32("kiwi.segment_id", "Segment Id", base.DEC)
packet_segment_page_field = ProtoField.uint16("kiwi.segment_page", "Segment Page", base.DEC)
packet_segment_total_field = ProtoField.uint16("kiwi.segment_total", "Segment Total", base.DEC)
packet_segment_payload_field = ProtoField.none("kiwi.segment_payload", "Segment Payload", base.HEX)

proto_kiwi.fields = {
  packet_kind_field,
  sequence_field,
  checksum_field,
  packet_length_field,
  packet_payload_field,
  packet_segment_id_field,
  packet_segment_page_field,
  packet_segment_total_field,
  packet_segment_payload_field,
}

function is_kiwi_packet(buffer)
  length = buffer:len()
  if length < min_packet_length then
    return false
  end
  return buffer(0, 1):uint() == magic_byte
end

function proto_kiwi.dissector(buffer, pinfo, tree)
  if not is_kiwi_packet(buffer) then
    return
  end

  pinfo.cols.protocol = proto_kiwi.name

  local subtree = tree:add(proto_kiwi, buffer(), "Kiwi Packet")
  subtree:add(packet_kind_field, buffer(1, 1)):append_text(" (" .. Packet_Kind:decode(buffer(1, 1):uint()) .. ")")
  subtree:add(sequence_field, buffer(2, 4))
  subtree:add(checksum_field, buffer(6, 4))
  subtree:add(packet_length_field, buffer(10, 2))
  subtree:add(packet_payload_field, buffer(12, buffer(10, 2):uint())):append_text(" (" .. buffer(10, 2):uint() .. " bytes)")

  if buffer(1, 1):uint() == Packet_Kind.SegmentData then
    subtree:add(packet_segment_id_field, buffer(12, 4))
    subtree:add(packet_segment_page_field, buffer(16, 2))
    subtree:add(packet_segment_total_field, buffer(18, 2))
    subtree:add(packet_segment_payload_field, buffer(20, buffer(10, 2):uint() - 8)):append_text(" (" .. (buffer(10, 2):uint() - 8) .. " bytes)")
  end
end

udp_table = DissectorTable.get("udp.port")
udp_table:add(348, proto_kiwi)
udp_table:add(349, proto_kiwi)

-- heuristic_checker: determine which dissector to use
local function heuristic_checker(buffer, pinfo, tree)
  if is_kiwi_packet(buffer) then
    -- use my dissector
    proto_kiwi.dissector(buffer, pinfo, tree)
    return true
  else
    return false
  end
end

-- register to udp
proto_kiwi:register_heuristic('udp', heuristic_checker)
