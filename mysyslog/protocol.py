# Copyright (c) 2014 Alexander Bredo
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or 
# without modification, are permitted provided that the 
# following conditions are met:
# 
# 1. Redistributions of source code must retain the above 
# copyright notice, this list of conditions and the following 
# disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above 
# copyright notice, this list of conditions and the following 
# disclaimer in the documentation and/or other materials 
# provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND 
# CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR 
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE 
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR 
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT 
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
# POSSIBILITY OF SUCH DAMAGE.


import re, sys, time
from datetime import datetime
from ieee.mac import MACVendor
from bredo.network import Network

'''
TODO:
 - (Generic) Parse content by Tokentypes (MAC, IP, Time, Keywords, ...)
'''

# Only load once. Open,Read,Parse File. .
macvendor = MACVendor()
myipaddr = Network().getMyOwnIP()

# Define EXCEPTIONS:
class InvalidSyslogLine(Exception): 
	pass
		
class InvalidSyslogMessage(Exception): 
	pass
	
# Define PARSERS:
'''
class SyslogMessage():
	def __init__(self, message):
		self.message = message
		
	def stripAllFields(self):
		for k,v in self.__dict__.items():
			if isinstance(v, str):
				setattr(self, k, v.strip())
		
class SyslogDNSMasqDHCP(SyslogMessage):
	def __init__(self, message):
		p = re.compile("([a-zA-Z]+)\((\w+)\) ([\d\.]{7,15}(?: ))?([0-9a-fA-F:]{17}(?: )?)([\w\-_\.]+)?")
		m = p.match(message)
		if m:
			self.stage, self.interface, self.ipaddr, self.macaddr, self.hostname = m.groups()
			if self.macaddr:
				self.vendor = macvendor.lookupVendor(self.macaddr)
			self.stripAllFields()
		else:
			self.message = message
			#raise InvalidSyslogMessage("Sorry, I can't parse the syslog-message you provided.")
'''

# NEU:
class SyslogParser():
	def __init__(self, line):
		self.line = line
		
	def getData(self):
		data = self.readHeader(self.line)
		data.update(self.readMessage(data['service'], data['message']))
		del(data['message'])
		data['destinationIPv4Address'] = myipaddr
		data['type'] = 'ap_connect'
		data['module'] = 'WLANAPACCESS'
		return data
	
	def readHeader(self, line):
		p = re.compile("([a-zA-Z]{3} \d{1,2} \d{1,2}:\d{2}:\d{2}) ([\w\-]+) ([\w\-\/]+)(?:\[[\d]+\])?: (.+)")
		m = p.match(line)

		if m:
			data = dict(zip(('date', 'destinationHostname', 'service', 'message'), m.groups()))
			data['date'] = datetime.strptime(data['date'], '%b %d %H:%M:%S')
			data['date'] = data['date'].replace(year=datetime.today().year) # Because of missing year in Syslog-Message
			data['@timestamp'] = int(time.mktime(data['date'].timetuple()) * 1000)
			del(data['date'])
			return data
		else:
			raise InvalidSyslogLine("Sorry, I can't parse syslog-message: %s" % line)
	
	def readHostap(self, message):
		p = re.compile("(\w+): (?:[a-zA-Z]+) ([0-9a-fA-F:]{17}) ([a-zA-Z]+): (.+)")
		m = p.match(message)
		if m:
			data = dict(zip(('destinationInterface', 'sourceMacAddress', 'category', 'command'), m.groups()))
			if data['sourceMacAddress']:
				data['vendor'] = macvendor.lookupVendor(data['sourceMacAddress'])
			return data
		else:
			raise InvalidSyslogMessage("Sorry, this is possibly an invalid hostap-log-message.")

	def readDHCPD(self, message):
		p = re.compile("(?P<stage>[a-zA-Z]+)( (?:on|for) (?P<ipaddr>[0-9\.]+))?( \([0-9\.]+\))?( (?:from|to) (?P<macaddr>[0-9a-fA-F:]{17}))( \((?P<hostname>[a-zA-Z0-9\-\_]+)\))?( (?:via) (?P<interface>[0-9a-zA-Z]+)?)")
		m = p.match(message)
		if m:
			data = dict(zip(
				('command', 'sourceIPv4Address', 'sourceMacAddress', 'sourceHostname', 'destinationInterface'), 
				(m.group('stage'), m.group('ipaddr'), m.group('macaddr'), m.group('hostname'), m.group('interface'))
			))
			if data['sourceMacAddress']:
				data['vendor'] = macvendor.lookupVendor(data['sourceMacAddress'])
			return data
		else:
			raise InvalidSyslogMessage("Sorry, this is possibly an invalid DHCPD-log-message.")
	
	def readMessage(self, service, message):
		try:
			return SyslogParser.METHODS[service](self, message)
		except KeyError:
			raise Exception("No handler for this type of log-message: %s" % service)
		'''
		TODO: Neue Klasse: MessageAnalyzor
		Alles in einen Topf werfen? Ggf. nur syntaktisch interessantes entnehmen: IP MAC Keywords ...
		IP-MAC Zuordnung herstellen (?)
		Versuchen Fragen zu beantworten: Wer? Was? Wo? Wann? usw. (IT-Forensik Prozess)
		IT-Forensik-Prozess: 
			(1) Wo ist es passiert? WLAN-HOPO
			(2) Wer war beteiligt? IP, MAC, HOSTNAME
			(3) Wann ist etwas passiert? TIMESTAMP
			(4) Was ist geschehen? CONNECT
			(5) Wie wurde vorgegangen? LOG
		'''
	METHODS = {
		'hostapd' : readHostap,
		'dhcpd' : readDHCPD,
	}

if __name__ == "__main__":
	print(SyslogParser("Jul 28 12:06:46 raspberry dhcpd: DHCPDISCOVER from 22:ba:b2:fe:78:52 via wlan0").getData())
	print(SyslogParser("Jul 28 15:40:28 raspberry hostapd: wlan0: STA 22:ba:b5:f1:78:52 WPA: pairwise key handshake completed (RSN)").getData())