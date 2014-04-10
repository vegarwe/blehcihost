#!/cygdrive/c/Python27/python.exe

import sys, os
sys.path.append(os.path.join(os.path.dirname(sys.argv[0]), '..'))

import logging
import struct
import time
from optparse import OptionParser

from hci import protocol, SerialDevice, DeviceEventCallback
from api import gap

LOGFILE_PREFIX = '_interactive'

class Interactive(object):
    _interactive_sessions = []
    def __init__(self, hcidev):
        self.hcidev = hcidev
        self.log    = hcidev.log
        self.hci_reset_ok = False

        self._interactive_sessions.append(self)

    def close(self):
        try:
            self._interactive_sessions.remove(self)
        except:
            pass
        self.log.info('closing %s', self)
        self.hcidev.stop()


    def reset_and_setup(self):
        result = self.hcidev.write_cmd(protocol.HciReset())
        self.log.info('result %s %r', result, result)
        if not result or result.status != '\x00':
            self.log.error('Unable to reset device')
            return
        self.hci_reset_ok = True

        dev_addr = self.hcidev.write_cmd(protocol.HciReadPublicDeviceAddress())
        self.log.info('log Public device address: %r', dev_addr.return_params[::-1])

        #CLOCK_SOURCE_32K = 0x07 # wtf? was 0x02...
        #SLEEP_CLOCK_ACCURACY = 0x07
        #CLOCK_SOURCE_16M = 0x01
        #retval = self.hcidev.write_cmd(HciCommand.HciNrfSetClockParameters(
        #        CLOCK_SOURCE_32K, SLEEP_CLOCK_ACCURACY, CLOCK_SOURCE_16M))
        ##self.log.info('log retval %r %s', retval, retval)

        ver_info = self.hcidev.write_cmd(protocol.HciNrfGetVersionInfo())
        self.log.info('log Firemware: %s' % ver_info.return_params)

    def help(self):
        help_str = 'Functions available:'
        for fname in dir(self):
            if fname.startswith('_'): continue
            if not hasattr(getattr(self, fname), '__call__'): continue
            help_str += '\n  ' + fname
        return help_str

    def read_remote_version(self, conn_handle):
        pass
        #with Blipp(self.hcidev, HciEvent.HciReadRemoteVersionInformationComplete) as blipp:
        #    retval = self.hcidev.write_cmd(HciCommand.HciReadRemoteVersionInformation(conn_handle))
        #    retval = blipp.Wait(5)
        #    self.log.info('log %s', retval)
        #return retval

    def read_local_version_information(self):
        pass
        #retval = self.hcidev.write_cmd(HciCommand.HciReadLocalVersionInformation())
        #if not retval: return

        #Params = [retval.Params[0],
        #          retval.Params[1],
        #          retval.Params[2] + retval.Params[3]*256,
        #          retval.Params[4],
        #          retval.Params[5] + retval.Params[6]*256,
        #          retval.Params[7] + retval.Params[8]*256]
        #self.log.info('log HciVersion 0x%02x, HciRev 0x%04x, LmpVer 0x%02x, Man.name 0x%04x, LmpSubVer 0x%04x',
        #        Params[1], Params[2], Params[3], Params[4], Params[5])

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self.hcidev)

class Slave(Interactive):
    def __init__(self, hcidev):
        Interactive.__init__(self, hcidev)

    def start_advertiser(self, interval=110, whitelist=None):
        pass
        #self.hcidev.write_cmd( HciCommand.HciLeSetAdvertisingParameters(
        #        AdvertisingIntervalMin=interval, AdvertisingIntervalMax=interval,
        #        AdvertisingType = 0x00, OwnAddressType = 0x00))
        #return self.hcidev.write_cmd(HciCommand.HciLeSetAdvertisingEnable(AdvertisingEnable=1))

    def stop_advertiser(self):
        pass
        #return self.hcidev.write_cmd(HciCommand.HciLeSetAdvertisingEnable(AdvertisingEnable=0))

class Master(Interactive):
    def __init__(self, hcidev):
        Interactive.__init__(self, hcidev)
        self.devices = gap.DeviceDb(hcidev)
        self.hcidev.pkt_handlers.append(self.devices.process_event)  # TODO: Need to fix this

    def start_scanner(self, timeout=1, active=False, interval=110, window=100, whitelist=None, filter_devices=False):
        scan_type = '\x01' if active else '\x00'
        seen_devices = {}

        filter_policy = '\x00'
        self.hcidev.write_cmd(protocol.HciLeClearWhiteList())
        #if isinstance(whitelist, (list, tuple)) and len(whitelist) > 0:
        #    filter_policy = '\x01'
        #    for addr in whitelist:
        #        #retval = self.hcidev.write_cmd(
        #        #        protocol.HciLeAddDeviceToWhiteList(addr[0], addr[1]))

        classes = [protocol.HciLeAdvertisingReport]
        def _filter(event):
            device = gap.Device.from_adv_report(self.hcidev, event.reports[0])
            if filter_devices and seen_devices.has_key(device.get_addr()):
                return
            seen_devices[device.get_addr()] = device
            self.log.info('log %s', device)
        with DeviceEventCallback(self.hcidev, classes, _filter) as callback:
            # Start scanning for adv packets
            self.hcidev.write_cmd(protocol.HciLeSetScanParametersCommand(
                    scan_type=scan_type, scan_interval=struct.pack('H', interval),
                    scan_window=struct.pack('H', window),
                    scan_filter_policy=filter_policy
                    ))
            self.hcidev.write_cmd(protocol.HciLeSetScanEnable(scan_enable='\x01'))

            self.log.debug("log Waiting for adv packets")
            time.sleep(timeout)

            self.hcidev.write_cmd(protocol.HciLeSetScanEnable(scan_enable='\x00'))

    def close(self):
        for device in self.devices:
            if device.is_connected():
                device.disconnect()
        Interactive.close(self)

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self.hcidev)

logger = None
def setup_logger(options):
    global logger
    if logger != None: return # Only configure logging once

    logger = logging.getLogger()
    logger.addHandler(logging.StreamHandler())

    if options.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    #from hci import btsnoop
    #btsnoop.init_hci_log(LOGFILE_PREFIX)

def _get_ipython_config():
    import os, sys, IPython

    os.environ['PYTHONSTARTUP'] = ''  # Prevent running this again
    c = IPython.config.loader.Config()
    c.TerminalInteractiveShell.confirm_exit = False
    c.TerminalInteractiveShell.logstart = True
    c.TerminalInteractiveShell.logfile = '%s.ipython.log' % LOGFILE_PREFIX
    return c

def get_device(options):
    if options.type == 'master':
        d = Master(SerialDevice(options.device, baudrate=options.baudrate))
    #else:
    #    d = Slave(HciUart(options.device, baudrate=options.baudrate))

    return d

def start_ipython(options, args):
    import IPython

    d = get_device(options)
    d.reset_and_setup()
    print 'd = %r:\n%s' % (d, d.help())

    IPython.embed(config=_get_ipython_config())
    for i in Interactive._interactive_sessions[:]:
        print 'i', i
        i.log.info('b')
        i.close()
    raise SystemExit(0)

def start_script(options, args):
    if not os.path.isfile(options.script):
        logger.error('Script file "%s" not found', options.script)
        return

    d = get_device(options)
    d.reset_and_setup()

    try:
        execfile(options.script)
    except:
        import traceback
        traceback.print_exc()

    for i in Interactive._interactive_sessions[:]:
        i.close()
    raise SystemExit(0)

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("-d", "--device",       dest="device",   default='com5',                     help="Select master device")
    parser.add_option("-b", "--baudrate",     dest="baudrate", default='1000000',                  help="Baud rate")
    parser.add_option("-t", "--type",         dest="type",     default='master',                   help='Interactive device type')
    parser.add_option("-s", "--script",       dest="script",   default=None,                       help='Stub script to run')
    parser.add_option("-v", "--verbose",      dest="verbose",  default=False, action="store_true", help='Verbose')
    (options, args) = parser.parse_args()

    setup_logger(options)

    if options.script == None:
        start_ipython(options, args)
    else:
        start_script(options, args)

