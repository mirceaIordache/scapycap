from scapycap.serializer import ScapycapSerializer

# Read in and serialize packets
serializer = ScapycapSerializer("test.pcap", lightweight=True)

# Print flattened packets in order that they have been read
for flat_packet in serializer.dump:
	print(flat_packet)
