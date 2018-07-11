from __future__ import print_function
from scapy.all import *

from collections import ChainMap

_native_value = (int, float, str, bytes, bool, list, tuple, set, dict, type(None))

class ScapycapSerializer(object):

	dump = None
	_pcap_file = None
	_lightweight = False

	def __init__(self, pcap_file, lightweight=False):

		self._lightweight = lightweight
		self._pcap_file = pcap_file

		if lightweight:
			self.dump = []
		else:
			self.dump = {}

		with PcapReader(self._pcap_file) as pcap_reader:
			for packet in pcap_reader:
				serial = self._serialize(packet)
				if lightweight:
					self.dump.append(serial)
				else:
					self.dump[serial] = packet


	def isLightweight(self):
		return self._lightweight

	@staticmethod
	def _to_dict(pkt):
		"""
		return ChainMap dict. if strict set to True, return dict.
		"""

		d = ScapycapSerializer._Packet2Dict(pkt).to_dict()
		return dict(**d)

	@staticmethod
	def _layer2dict(obj):
		d = {}

		if not getattr(obj, 'fields_desc', None):
			return
		for f in obj.fields_desc:
			value = getattr(obj, f.name)
			if value is type(None):
				value = None

			if not isinstance(value, _native_value):
				value = ScapycapSerializer._layer2dict(value)
			d[f.name] = value
		return {obj.name: d}

	class _Packet2Dict:
		def __init__(self, pkt):
			self.pkt = pkt

		def to_dict(self):
			"""
			Turn every layer to dict, store in ChainMap type.
			:return: ChainMap
			"""
			d = list()
			count = 0

			while True:
				layer = self.pkt.getlayer(count)
				if not layer:
					break
				d.append(ScapycapSerializer._layer2dict(layer))

				count += 1
			return ChainMap(*d)

	@staticmethod
	def _flatten(d, parent_key='', sep='_'):
		items = []
		for k, v in d.items():
			new_key = parent_key + sep + k if parent_key else k
			if isinstance(v, collections.MutableMapping):
				items.extend(ScapycapSerializer._flatten(v, new_key, sep=sep).items())
			else:
				items.append((new_key, v))
		return dict(items)

	def _serialize(self, packet):
		flat_packet = self._flatten(self._to_dict(packet))
		serial = ""
		for key in sorted(flat_packet):
			serial += str(key) + ": " + str(flat_packet[key]) + " | "
		return serial

