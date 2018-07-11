from scapycap.serializer import ScapycapSerializer
import time

# Read in and serialize packets
serializer = ScapycapSerializer("test.pcap")

# Get individual packet timestamps
pkts = serializer.dump.values()
pkt_per_s = {}
for pkt in pkts:
    ts = pkt.time
    pkt_time = time.gmtime(ts)
    pkt_s = pkt_time.tm_sec
    pkt_min = pkt_time.tm_min
    try:
        pkt_per_s[pkt_min*100+pkt_s] += 1
    except KeyError:
        pkt_per_s[pkt_min*100+pkt_s] = 1

# for every time entry (M)MSS in dict you have number of packets captured

for ts in sorted(pkt_per_s.keys()):
    print(ts, ":", pkt_per_s[ts])
