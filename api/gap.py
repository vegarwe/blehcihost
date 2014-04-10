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
        self.conn_handle = None

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
            self.log.info('log Connected to %s', self.get_addr())

    def is_connected(self):
        return self.conn_handle != None

    def disconnect(self):
        with DeviceEventCallback(self.hcidev, protocol.HciDisconnectionComplete) as callback:
            self.hcidev.write_cmd(protocol.HciDisconnect(conn_handle=self.conn_handle))
            cmd_resp = callback.wait_for_event()
            self.log.info('Disconnected %s', self)

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

    def process_event(self, event):
        if isinstance(event, protocol.HciLeConnectionComplete):
            self.conn_handle = event.conn_handle
        if isinstance(event, protocol.HciDisconnectionComplete):
            self.conn_handle = None

    @staticmethod
    def from_adv_report(hcidev, event):
        addr_type = Device.addr_types[event.addr_type]
        addr = ':'.join(['%02x' % ord(i) for i in reversed(event.addr)])
        # TODO: Parse adv data for device name
        return Device(hcidev, addr, addr_type)

    @staticmethod
    def from_connected_event(hcidev, event):
        addr_type = Device.addr_types[event.peer_addr_type]
        addr      = ':'.join(['%02x' % ord(i) for i in reversed(event.peer_addr)])

        device             = Device(hcidev, addr, addr_type)
        device.conn_handle = event.conn_handle
        return device

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

class DeviceDb(object):
    def __init__(self, hcidev, devices=None):
        self.hcidev = hcidev
        self.log    = hcidev.log
        if devices == None:
            self._devices = []
        else:
            self._devices = devices

    def add_device_if_new(self, device):
        for d in self._devices:
            if d.get_addr() == device.get_addr():
                return
        self._devices.append(device)

    #def __repr__(self):
    #    if len(self._devices) > 0:
    #        return "%s([%s])" % (self.__class__.__name__, ''.join(['\n  %r' % i for i in self._devices]))
    #    else:
    #        return "%s(%r)" % (self.__class__.__name__, self._devices)

    def __iter__(self):
        for conn in self._devices[:]:
            yield conn

    def __getitem__(self, idx):
        return self._devices[idx]

    def __len__(self):
        return len(self._devices)

    #def GetDb(self):
    #    return self._devices[:]

    def process_event(self, event):
        if isinstance(event, protocol.HciLeAdvertisingReport):
            self.log.debug('event %r', event)
            device = Device.from_adv_report(self.hcidev, event.reports[0])
            self.add_device_if_new(device)

        if isinstance(event, protocol.HciLeConnectionComplete):
            self.log.debug('event %r', event)
            if event.status == '\x00':
                device = Device.from_connected_event(self.hcidev, event)
                matching_devices = [d for d in self._devices if d.get_addr() == device.get_addr()]
                if matching_devices:
                    matching_devices[0].process_event(event)
                else:
                    self.add_device_if_new(device)

        if isinstance(event, protocol.HciDisconnectionComplete):
            self.log.debug('event %r', event)
            for entry in self._devices:
                for d in self._devices:
                    if d.conn_handle == event.conn_handle:
                        d.process_event(event)

        if isinstance(event, protocol.HciCommandComplete):
            if event.command_op_code == 0x0c03 and event.Status == 0x00:
                self._devices[:] = []

        #if isinstance(event, protocol.HciLeConnectionUpdateComplete):
        #    for entry in self._devices:
        #        if event.ConnectionHandle == entry.conn_handle:
        #            entry.update_conn_params(event)
        #if isinstance(event, protocol.HciEncryptionChange):
        #    for entry in self._devices:
        #        if event.ConnectionHandle == entry.conn_handle:
        #            entry.update_enc_status(event)

