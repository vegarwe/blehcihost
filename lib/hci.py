
class HciPkt(object):
    def __init__(self):
        self.uart_type = ''
        self.op_code   = ''
        self.data      = ''
        self.length    = '\x00'

    def serialize(self):
        return ''.join([self.uart_type, self.op_code, self.length, self.data])

###################### COMMANDS ######################
class HciCommand(HciPkt):
    def __init__(self):
        HciPkt.__init__(self)
        self.uart_type = '\x01'

class HciReset(HciCommand):
    def __init__(self):
        HciCommand.__init__(self)
        self.op_code   = '\x03\x0c'

class HciDisconnect(HciCommand):
    def __init__(self, conn_handle='\x00\x00', reason='\x13'):
        HciCommand.__init__(self)
        self.op_code   = '\x06\x04'
        self.data     += conn_handle
        self.data     += reason
        self.length    = '\x03'

class HciReadRemoteVersionInformation(HciCommand):
    def __init__(self, conn_handle='\x00\x00'):
        HciCommand.__init__(self)
        self.op_code   = '\x1d\x04'
        self.data     += conn_handle
        self.length    = '\x02'

class HciReadPublicDeviceAddress(HciCommand):
    def __init__(self):
        HciCommand.__init__(self)
        self.op_code   = '\x09\x10'
        self.length    = '\x00'

class HciLeReadBufferSize(HciCommand):
    def __init__(self):
        HciCommand.__init__(self)
        self.op_code   = '\x02\x20'
        self.length    = '\x00'

class HciLeSetScanParametersCommand(HciCommand):
    def __init__(self, scan_type='\x00', scan_interval='\x10\x00', scan_window='\x20\x00',
            own_addr_type='\x00', scan_filter_policy='\x00'):
        HciCommand.__init__(self)
        self.op_code   = '\x0b\x20'
        self.data     += scan_type
        self.data     += scan_interval
        self.data     += scan_window
        self.data     += own_addr_type
        self.data     += scan_filter_policy
        self.length    = '\x07'

class HciLeSetScanEnable(HciCommand):
    def __init__(self, scan_enable='\x00', filter_duplicates='\x00'):
        HciCommand.__init__(self)
        self.op_code   = '\x0c\x20'
        self.data     += scan_enable[0]
        self.data     += filter_duplicates[0]
        self.length    = '\x02'

class HciLeCreateConnection(HciCommand):
    pass

class HciNrfGetVersionInfo(HciCommand):
    def __init__(self):
        HciCommand.__init__(self)
        self.op_code   = '\x06\xFC'

# -  HciReset:                            {'OpCode':030C,'Length':0},
# -  HciDisconnect:                       {'OpCode':0604,'Length':3},
# -  HciReadRemoteVersionInformation:     {'OpCode':1D04,'Length':2},
#    HciReadPublicDeviceAddress:          {'OpCode':0910,'Length':0},
#    HciLeReadBufferSize:                 {'OpCode':0220,'Length':0},
#    HciLeReadLocalSupportedFeatures:     {'OpCode':0320,'Length':0},
#    HciLeSetRandomAddress:               {'OpCode':0520,'Length':6},
#    HciLeSetAdvertisingParameters:       {'OpCode':0620,'Length':15},
#    HciLeSetAdvertisingEnable:           {'OpCode':0A20,'Length':1},
#    HciLeSetScanParametersCommand:       {'OpCode':0B20,'Length':7},
#    HciLeSetScanEnable:                  {'OpCode':0C20,'Length':2},
#    HciLeCreateConnection:               {'OpCode':0D20,'Length':25},
#    HciLeCreateConnectionCancel:         {'OpCode':0E20,'Length':0},
#    HciLeReadWhiteListSize:              {'OpCode':0F20,'Length':0},
#    HciLeClearWhiteList:                 {'OpCode':1020,'Length':0},
#    HciLeAddDeviceToWhiteList:           {'OpCode':1120,'Length':7},
#    HciLeConnectionUpdate:               {'OpCode':1320,'Length':14},
#    HciLeSetHostChannelClassification:   {'OpCode':1420,'Length':5},
#    HciLeReadChannelMap:                 {'OpCode':1520,'Length':2},
#    HciLeReadRemoteUsedFeatures:         {'OpCode':1620,'Length':2},
#    HciLeEncrypt:                        {'OpCode':1720,'Length':32},
#    HciLeRand:                           {'OpCode':1820,'Length':0},
#    HciLeStartEncryption:                {'OpCode':1920,'Length':28},
#    HciLeLongTermKeyRequestReply:        {'OpCode':1A20,'Length':18},
#    HciLeLongTermKeyRequestNegativeReply:{'OpCode':1B20,'Length':2},
#    HciNrfSetClockParameters:            {'OpCode':01FC,'Length':3},
#    HciNrfSetTransmitPowerLevel:         {'OpCode':02FC,'Length':1},
#    HciNrfSetBdAddr:                     {'OpCode':03FC,'Length':6},
#    HciNrfGetVersionInfo:                {'OpCode':06FC,'Length':0},

###################### DATA ##########################
class HciData(HciPkt):
    def __init__(self):
        HciPkt.__init__(self)
        self.uart_type = '\x02'

###################### EVENTS ########################
class HciEvent(HciPkt):
    def __init__(self):
        HciPkt.__init__(self)
        self.uart_type = '\x04'
        self.fields = {}

    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, self.fields)

class HciCommandComplete(HciEvent):
    def __init__(self, pkt):
        HciEvent.__init__(self)
        self.fields['EventCode']     = pkt[3]
        self.fields['NumHciCmdPkt']  = pkt[5]
        self.fields['CommandOpcode'] = pkt[6:8]
        self.fields['Status']        = pkt[8]   # TODO: What? status overlaps with params?
        if len(pkt) > 8:
            self.fields['Params']        = pkt[9:]

class HciCommandStatus(HciEvent):
    pass

def event_factory(data):
    if data[3] == '\x0e': return HciCommandComplete(data)

    #0x05:HciDisconnectionComplete,
    #0x08:HciEncryptionChange,
    #0x0C:HciReadRemoteVersionInformationComplete,
    #0x0E:HciCommandComplete,
    #0x0F:HciCommandStatus,
    #0x13:HciNumCompletePackets,
    #0x30:HciEncryptionKeyRefreshComplete,
