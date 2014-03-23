import threading
import logging
import Queue
import serial

import protocol

class DeviceInterface(threading.Thread):
    def __init__(self, pkt_handler=None):
        threading.Thread.__init__(self)
        self.log = logging.getLogger('dev_if')
        self.pkt_handler = pkt_handler
        if self.pkt_handler == None:
            self.pkt_queue = Queue.Queue()
        self.keep_running = False

    def stop(self):
        self.keep_running = False

    def run(self):
        self.keep_running = True
        try:
            while self.keep_running:
                data = self.read()
                if data == '': continue

                pkt = protocol.event_factory(data)
                if self.pkt_handler == None:
                    self.pkt_queue.put(pkt)
                else:
                    self.pkt_handler(pkt)
        except:
            self.log.exception("Exception in read thread")
        finally:
            self.keep_running = False
            self.log.debug("Read thread finished")

        self.close()

    def _write(self, pkt):
        if not self.keep_running:
            return
        self.write(pkt.serialize())

    def write_data(self, conn_handle, data):
        self._write(protocol.HciDataPkt(conn_handle, protocol.L2CapPkt(data)))
        while True:
            pkt = self.wait_for_pkt()

            if pkt.__class__ == protocol.HciNumCompletePackets:
                self.log.debug('data %s, pkt %r', data.__class__.__name__, pkt)
                return pkt
            if pkt == None:
                self.log.info('data %s, timeout waiting for event', data.__class__.__name__)
                return pkt
            self.log.info('data %s, discarding unexpcted event %r', data.__class__.__name__, pkt)

    def write_cmd(self, cmd):
        self._write(cmd)
        while True:
            #if cmd.__class__ == protocol.HciLeCreateConnection:
            #    self.log.debug('cmd %s, no cmd response', cmd.__class__.__name__)
            #    return # TODO: Why do we get no CommandComplete or CommandStatus for this?

            pkt = self.wait_for_pkt()

            if pkt.__class__ == protocol.HciCommandComplete:
                self.log.debug('cmd %s, pkt %r', cmd.__class__.__name__, pkt)
                return pkt
            if pkt.__class__ == protocol.HciCommandStatus:
                self.log.debug('cmd %s, pkt %r', cmd.__class__.__name__, pkt)
                return pkt
            if pkt == None:
                self.log.info('cmd %s, timeout waiting for event', cmd.__class__.__name__)
                return pkt
            self.log.info('cmd %s, discarding unexpcted event %r', cmd.__class__.__name__, pkt)

    def wait_for_pkt(self, timeout = 1):
        try:
            return self.pkt_queue.get(True, timeout)
        except Queue.Empty, ex:
            return None

    def close(self):
        raise NotImplementedError()

    def read(self):
        raise NotImplementedError()

    def write(self, data):
        raise NotImplementedError()

class SerialHci(DeviceInterface):
    def __init__(self, port, baudrate=115200, rtscts=True, pkt_handler=None):
        DeviceInterface.__init__(self, pkt_handler)
        self.serial = serial.Serial(port=port, baudrate=baudrate, rtscts=rtscts, timeout=0.1)
        self.log.debug("Opended port %s, baudrate %s, rtscts %s", port, baudrate, rtscts)
        self.start()

    def close(self):
        self.serial.close()

    def read(self):
        data = self.serial.read(1)
        if data == '':
            return ''

        if data[0] == '\x04':
            data += self.serial.read(2)
            if data[2] != '\x00':
                data += self.serial.read(ord(data[2]))
            data = chr(len(data)) + '\x12' + data
        elif data[0] == '\x02':
            data += self.serial.read(4)
            if data[3] != '\x00':
                data += self.serial.read(ord(data[3]))
            data = chr(len(data)) + '\x11' + data
        else:
            return ''
        self.log.debug('rx <=: %r', data)
        return data

    def write(self, data):
        self.log.debug("tx =>: %r", data)
        self.serial.write(data)

