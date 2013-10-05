import logging
import serial

class SerialHci(object):
    def __init__(self, port, baudrate=115200, rtscts=True):
        self.log    = logging.getLogger('serial')
        self.serial = serial.Serial(port=port, baudrate=baudrate, rtscts=rtscts, timeout=0.1)
        self.log.debug("Opended port %s, baudrate %s, rtscts %s", port, baudrate, rtscts)

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

