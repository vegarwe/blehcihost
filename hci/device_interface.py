import threading
import logging
import Queue
import serial

import protocol

class DeviceEventCallback():
    def __init__(self, hcidev, classes=None, filter=None):
        self.hcidev = hcidev
        self.log = hcidev.log
        if isinstance(classes, (list, tuple)):
            self._classes = classes
        elif classes == None:
            self._classes = None
        else:
            self._classes = [classes]
        self._filter = filter
        self.events = Queue.Queue(maxsize=20)

    def _isinstance_of_classes(self, event):
        # if self._classes == None, allow any event
        if self._classes == None:
            return True
        for _class in self._classes:
            if isinstance(event, _class):
                return True
        return False

    def _put_event(self, event):
        if self.events.full():
            dropped_event = self.event.get()
            self.log.warn('Event queue for %s full, dropping oldest event %s',
                    self, dropped_event)
        self.events.put(event)

    def process_event(self, event):
        if self._isinstance_of_classes(event):
            if self._filter and self._filter(event):
                self._put_event(event)
            elif not self._filter:
                self.events.append(event)

    def wait_for_event(self, timeout=1):
        try:
            return self.events.get(timeout=10)
        except Queue.Empty:
            return None

    def append_as_listener(self):
        self.hcidev.pkt_handlers.append(self.process_event)

    def remove_as_listener(self):
        self.hcidev.pkt_handlers.remove(self.process_event)

    def __enter__(self):
        self.append_as_listener()
        return self

    def __exit__(self, type, value, traceback):
        self.remove_as_listener()

class DeviceInterface(object):
    def __init__(self, device_name):
        self.device_name = device_name
        self.log = logging.getLogger(((8 - len(device_name)) * ' ' + device_name))
        self.pkt_handlers = []

    def process_event(self, event):
        self.log.debug('dbg event %r', event)
        # TODO: Deserialized log...
        for fun in self.pkt_handlers:
            fun(event)

    def write_cmd(self, cmd):
        classes = [protocol.HciCommandComplete, protocol.HciCommandStatus]
        _filter = lambda x: x.commmand_op_code == cmd.op_code
        with DeviceEventCallback(self, classes, _filter) as callback:
            self.write(cmd.serialize())
            cmd_resp = callback.wait_for_event()
            self.log.debug('dbg %s %s', cmd, cmd_resp)

    def write_data(self, conn_handle, data):
        pkt = protocol.HciDataPkt(conn_handle, protocol.L2CapPkt(data))
        self.write(pkt.serialize())

    def write_data_wait_for_complete(self, conn_handle, data, timeout=10):
        classes = [protocol.HciNumCompletePackets]
        def _filter(num_complete_event):
            for handle, num_completes in num_completes.handles:
                if handle == conn_handle:
                    return True
            return False
        with DeviceEventCallback(self, classes, _filter) as callback:
            self.write_data(conn_handle, data)
            data_rsp = callback.wait_for_event(timeout)
            if data_rsp == None:
                self.log.info('pkt %s, timeout waiting for hci data' % (pkt.__class__.__name__))
        return data_rsp

class SerialDevice(DeviceInterface, threading.Thread):
    def __init__(self, port, baudrate=115200, rtscts=True):
        threading.Thread.__init__(self)
        DeviceInterface.__init__(self, port)
        self.serial = serial.Serial(port=port, baudrate=baudrate, rtscts=rtscts, timeout=0.1)
        self.log.debug("Opended port %s, baudrate %s, rtscts %s", port, baudrate, rtscts)

        self.keep_running = False
        self.start()

    def stop(self):
        self.keep_running = False

    def run(self):
        self.keep_running = True
        try:
            while self.keep_running:
                data = self.read()
                if data == '': continue

                event = None
                try:
                    event = protocol.event_factory(data)
                except:
                    self.log.exception("Unable to parse data %r", data)
                if event != None: self.process_event(event)
        except:
            self.log.exception("Exception in read thread")
        finally:
            self.keep_running = False
            self.log.debug("Read thread finished")

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

