#!/cygdrive/c/Python27/python.exe

import sys
#sys.path.append('C:\\Users\\vegarwe\\Dropbox\\vegarwe\\devel\\python_stack')
sys.path.append('..')

import logging

from blehcihost import SerialHci
from blehcihost import DeviceInterface
from blehcihost import hci

class App(object):
    def __init__(self):
        self.log = logging.getLogger('main')

    def main(self, dev):
        # Setup
        dev.write_cmd(hci.HciReset())
        dev.write_cmd(hci.HciNrfGetVersionInfo())
        dev.write_cmd(hci.HciReadPublicDeviceAddress())
        dev.write_cmd(hci.HciLeReadBufferSize())

        # Scan and get address from ADV packet
        #dev.write_cmd(hci.HciLeSetScanParametersCommand())
        #dev.write_cmd(hci.HciLeSetScanEnable('\x01'))
        #pkt = dev.wait_for_pkt(20)
        #self.log.info('blipp: %r', pkt)
        #dev.write_cmd(hci.HciLeSetScanEnable('\x00'))

        #if not pkt:
        #    self.log.info('log No adv packet seen')
        #    return

        #address = pkt.reports[0].addr
        address = '\xba\x12\xc5\x9e\xa8\xe5'

        self.log.info('log Connecting to %r' % address)
        dev.write_cmd(hci.HciLeCreateConnection(peer_addr = address))

        pkt = dev.wait_for_pkt(20)
        if not pkt:
            self.log.info('log Not able to connect')
            return

        conn_handle = pkt.conn_handle
        self.log.info('log conn %r', pkt)

        dev.write_cmd(hci.HciReadRemoteVersionInformation(conn_handle=conn_handle))
        pkt = dev.wait_for_pkt(1)
        self.log.info('HciReadRemoteVersionInformation: %r', pkt)

        dev.write_data(conn_handle, hci.AttReadRequest(handle='\x03\x00'))
        pkt = dev.wait_for_pkt(1)
        self.log.info('blipp: %r', pkt)

        dev.write_cmd(hci.HciDisconnect(conn_handle))
        pkt = dev.wait_for_pkt(1)
        self.log.info('disconnect: %r', pkt)

if __name__ == '__main__':
    #from optparse import OptionParser

    #pkt = hci.HciReset()
    #print '%s' % (pkt)
    #pkt = hci.HciLeCreateConnection('\x10\x00', peer_addr='\xba\x12\xc5\x9e\xa8\xe5')
    #print '%s' % (pkt)
    #pkt = hci.AttReadRequest(handle='\x03\x00')
    #print '%s - %r' % (pkt, pkt.serialize())

    #data = '\x18\x11\x02\x00 \x13\x00\x0f\x00\x04\x00\x0bXLR2_2_TempLog'
    #print 'data %r' % data
    #print '%s' % (hci.event_factory(data))

    #raise SystemExit(1)

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

