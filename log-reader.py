#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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


'''
Idea: Watch/Monitor File Change:  view only appended lines...
TODO:
 - Generic Parser
 - FireEventIfRuleMatch
'''
	
import time, os.path, sys
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
from mysyslog.protocol import SyslogParser

from base.applog import *
from base.appconfig import Configuration
from handler.manager import HandlerManager

class LogReaderConfig(Configuration):
	def setup(self, *args, **kwargs): # Defaults: 
		self.__version = '0.1.0'
		self.__appname = 'log_reader'
		self.syslog_path='/var/log/syslog'
		self.enabled_handlers = {
			'elasticsearch': True, 
			'screen': True,
			'file': False
		}
		self.elasticsearch = {
			'host': '127.0.0.1', 
			'port': 9200, 
			'index': 'honeypot'
		}
		self.filename = 'honeypot_output.txt'
		
config = LogReaderConfig()
handler = HandlerManager(config)

class MyFileHandler(PatternMatchingEventHandler):
	def __init__(self, filename):
		self.filename2monitor = filename
		super(MyFileHandler, self).__init__(patterns=[self.filename2monitor], ignore_directories=True)
		self.setInitialOffset()
		
	def on_modified(self, event):
		log.info("New Event triggered: %s" % event.src_path)
		self.__readFile(event.src_path)
		
	def setInitialOffset(self):
		self.offset = os.path.getsize(self.filename2monitor)
		log.debug("Initial Offset: %d" % self.offset)
	
	def __readFile(self, filename, retry=0):
		if retry > 5:
			log.error("Cant open file. Give up. %s" % e)
			return
		try:
			time.sleep((retry * 2) + 1)
			file = open(filename, 'r')
		except PermissionError as e:
			log.error("ERROR: Can't open file: %s" % e)
			self.__readFile(filename, retry+1)
			
		# Handle Filesize reset (Log rotate)
		if (os.path.getsize(filename) < self.offset):
			self.setInitialOffset()
			return
			
		file.seek(self.offset)
		for line in file:
			try:
				l = line.strip()
				if l:
					syslog = SyslogParser(l)
					handler.handle(syslog.getData(), type='wireless')
			except Exception as e:
				log.error("ERROR: %s (%s)" % (e, l))
				
		self.offset = file.tell()
		log.debug("DEBUG: New Offset: %d" % self.offset)

if __name__ == "__main__":
	log.info("Monitoring %s for changes." % config.syslog_path)
	observer = Observer()
	observer.schedule(
		MyFileHandler(config.syslog_path), 
		path=os.path.dirname(config.syslog_path), 
		recursive=False
	)
	observer.start()
	
	try:
		while True:
			time.sleep(1)
	except KeyboardInterrupt:
		observer.stop()
	observer.join()