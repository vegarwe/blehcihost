import logging

from lib.serial_driver import SerialHci
from lib.device_interface import DeviceInterface
from lib import hci

def main(dev):
    logger = logging.getLogger('main')

    # Setup
    dev.write_cmd(hci.HciReset())
    dev.write_cmd(hci.HciNrfGetVersionInfo())
    dev.write_cmd(hci.HciReadPublicDeviceAddress())

    # Scan
    #dev.write_cmd(hci.HciLeSetScanParametersCommand())
    #dev.write_cmd(hci.HciLeSetScanEnable('\x01'))
    #pkt = dev.wait_for_pkt(1)
    #logger.info('blipp: %r', pkt)
    #dev.write_cmd(hci.HciLeSetScanEnable('\x00'))

    # Tear down
    dev.write_cmd(hci.HciReset())

if __name__ == '__main__':
    #from optparse import OptionParser

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    #logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.StreamHandler())

    logging.getLogger('dev_if').setLevel(logging.DEBUG)
    logging.getLogger('main').setLevel(logging.DEBUG)
    #logging.getLogger('serial').setLevel(logging.DEBUG)

    dev = DeviceInterface(SerialHci('com5'))
    try:
        main(dev)
    except:
        self.log.exception("Exception in main thread")
    finally:
        dev.stop()


'''
import serial
s = serial.Serial(port = com_port, baudrate=115200, rtscts=True, timeout=1, writeTimeout = 1, interCharTimeout=None)
print repr(s.read(512))
s.write('\x01\x03\x0c\x00')
print repr(s.read(512))
'''

