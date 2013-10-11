import logging

from lib.serial_driver import SerialHci
from lib.device_interface import DeviceInterface
from lib import hci

class App(object):
    def __init__(self):
        self.log = logging.getLogger('main')

    def main(self, dev):
        data = '\x18\x11\x02\x00 \x13\x00\x0f\x00\x04\x00\x0bXLR2_2_TempLog'
        print repr(hci.HciDataPkt.deserialize(data))
        return

        # Setup
        dev.write_cmd(hci.HciReset())
        dev.write_cmd(hci.HciNrfGetVersionInfo())
        dev.write_cmd(hci.HciReadPublicDeviceAddress())
        dev.write_cmd(hci.HciLeReadBufferSize())

        # Scan and get address from ADV packet
        dev.write_cmd(hci.HciLeSetScanParametersCommand())
        dev.write_cmd(hci.HciLeSetScanEnable('\x01'))
        pkt = dev.wait_for_pkt(20)
        self.log.info('blipp: %r', pkt)
        dev.write_cmd(hci.HciLeSetScanEnable('\x00'))

        if not pkt:
            return

        address = pkt.reports[0].addr
        #address = '\xba\x12\xc5\x9e\xa8\xe5'

        self.log.info('log Connecting to %r' % address)
        dev.write_cmd(hci.HciLeCreateConnection(peer_addr = address))

        pkt = dev.wait_for_pkt(20)
        if not pkt:
            return

        conn_handle = pkt.conn_handle
        self.log.info('log conn %r', pkt)

        dev.write_data(conn_handle, hci.AttReadRequest(handle='\x03\x00'))
        pkt = dev.wait_for_pkt(1)
        self.log.info('blipp: %r', pkt)

if __name__ == '__main__':
    #from optparse import OptionParser

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    #logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.StreamHandler())

    logging.getLogger('dev_if').setLevel(logging.DEBUG)
    logging.getLogger('main').setLevel(logging.DEBUG)
    logging.getLogger('serial').setLevel(logging.DEBUG)

    app = App()
    dev = DeviceInterface(SerialHci('com5'))
    try:
        app.main(dev)
    except:
        logger.exception("Exception in main thread")
    finally:
        dev.stop()


'''
import serial
s = serial.Serial(port = com_port, baudrate=115200, rtscts=True, timeout=1, writeTimeout = 1, interCharTimeout=None)
print repr(s.read(512))
s.write('\x01\x03\x0c\x00')
print repr(s.read(512))
'''

