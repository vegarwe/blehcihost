from hci import protocol, DeviceEventCallback

class Device(object):
    addr_types = {'\x00': 'public', '\x01': 'random'}

    def __init__(self, hcidev, addr, addr_type = 'public' , device_name = None):
        if not addr_type in Device.addr_types.values():
            raise Exception('addr_type needs to be on of %s' % Device.addr_type)
        self.hcidev      = hcidev
        self.log         = hcidev.log
        self.addr        = addr
        self.addr_type   = addr_type
        self.device_name = device_name

    def get_addr(self):
        return "%s(%s)" % (self.addr, self.addr_type)

    def get_binary_addr(self):
        return "%s(%s)" % (self.addr, self.addr_type)

    def connect(self, interval=40, latency=0, scan_interval=80, timeout=1):
        with DeviceEventCallback(self.hcidev, [protocol.HciLeConnectionComplete]) as callback:
            addr = ''.join([chr(int(i, 16)) for i in reversed(self.addr.split(':'))])
            self.hcidev.write_cmd(protocol.HciLeCreateConnection(
                    #ScanInterval    = scan_interval, ScanWindow = scan_interval,
                    #InitiatorFilterPolicy                       = filter_policy,
                    #ConnIntervalMin = interval, ConnIntervalMax = interval,
                    #ConnLatency     = latency,
                    peer_addr_type = '\x01',   peer_addr = addr)
                )

            conn_resp = callback.wait_for_event(timeout)
            if not conn_resp:
                self.log.error('log Unable to connect to %s after %ss',
                        self.get_addr(), timeout)
                self.hcidev.write_cmd(protocol.HciLeCreateConnectionCancel())
                conn_resp = callback.wait_for_event()
                self.log.debug('log %s %r', conn_resp, conn_resp)
                return
            self.log.info('log Connected to %s, conn_handle %s',
                    self.get_addr(), conn_resp.conn_handle)

    def __str__(self):
        if self.device_name:
            return " %s %s" % (self.device_name, self.get_addr())
        return "%s" % (self.get_addr())

    def __repr__(self):
        if self.device_name == None:
            return "%s(%s, '%s', '%s')" % ( self.__class__.__name__,
                    self.hcidev, self.addr, self.addr_type)
        return "%s(%s, '%s', '%s', '%s')" % ( self.__class__.__name__,
                self.hcidev, self.addr, self.addr_type, self.device_name)

    @staticmethod
    def from_adv_report(hcidev, event):
        addr_type = Device.addr_types[event.addr_type]
        addr = ':'.join(['%02x' % ord(i) for i in reversed(event.addr)])
        # TODO: Parse adv data for device name
        return Device(hcidev, addr, addr_type)

    #@staticmethod
    #def from_addr(addr_string):
    #    addr_string = addr_string.lstrip('[')
    #    if addr_string.find('(') >= 0:
    #        addr_string = addr_string[:addr_string.find('(')]
    #    addr_string = addr_string.rstrip(']')
    #    _type, tmp_addr = addr_string.split(',')
    #    if _type == "'01'":
    #        _type = '\x01'
    #    else:
    #        _type = '\x00'
    #    tmp_addr = tmp_addr.strip(" '")
    #    tmp_addr = ''.join([chr(int(i, 16)) for i in reversed(tmp_addr.split(':'))])
    #    return Device(tmp_addr, _type)

