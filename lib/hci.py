# TODO: uart_type not a good name. What is it really?
# BLUETOOTH SPECIFICATION Version 4.0 [Vol 2] page 15 of 1114
# BLUETOOTH SPECIFICATION Version 4.0 [Vol 2] page 408 of 1114

class HciPkt(object):
    def __init__(self, uart_type):
        self.uart_type = uart_type

###################### COMMANDS ######################
class HciCommand(HciPkt):
    def __init__(self, op_code, fields=None):
        HciPkt.__init__(self, '\x01')
        self.op_code   = op_code
        if fields == None:
            self.fields = []
        else:
            self.fields = fields

    def serialize(self):
        data = ''
        for field in self.fields:
            data += field[1] # TODO: Verify size of field
        length = chr(len(data))
        return ''.join([self.uart_type, self.op_code, length, data])

class HciReset(HciCommand):
    def __init__(self):
        HciCommand.__init__(self, '\x03\x0c')

class HciDisconnect(HciCommand):
    def __init__(self, conn_handle, reason='\x13'):
        fields = [  ['conn_handle', conn_handle, 2],
                    ['reason'     , reason,      1] ]
        HciCommand.__init__(self, '\x06\x04', fields)

class HciReadRemoteVersionInformation(HciCommand):
    def __init__(self, conn_handle):
        fields = [  ['conn_handle' , conn_handle,  2] ]
        HciCommand.__init__(self, '\x1d\x04', fields)

class HciReadPublicDeviceAddress(HciCommand):
    def __init__(self):
        HciCommand.__init__(self, '\x09\x10')

class HciLeReadBufferSize(HciCommand):
    def __init__(self):
        HciCommand.__init__(self, '\x02\x20')

class HciLeReadLocalSupportedFeatures(HciCommand):
    def __init__(self):
        HciCommand.__init__(self, '\x03\x20')

class HciLeSetRandomAddress(HciCommand):
    def __init__(self, addr):
        fields = [  ['addr' , addr,  6] ]
        HciCommand.__init__(self, '\x05\x20', fields)

class HciLeSetAdvertisingParameters(HciCommand):
    def __init__(self, adv_interval_min='\x00\x08', adv_interval_max='\x00\x08',
            adv_type='\x00', own_addr_type='\x01', direct_addr_type='\x00',
            direct_addr='\x00\x00\x00\x00\x00\x00', adv_channel_map='\x03', adv_filter_policy='\x00'):
        fields = [  ['adv_interval_min' , adv_interval_min,  2],
                    ['adv_interval_max' , adv_interval_max,  2],
                    ['adv_type'         , adv_type,          1],
                    ['own_addr_type'    , own_addr_type,     1],
                    ['direct_addr_type' , direct_addr_type,  1],
                    ['direct_addr'      , direct_addr,       6],
                    ['adv_channel_map'  , adv_channel_map,   1],
                    ['adv_filter_policy', adv_filter_policy, 1] ]
        HciCommand.__init__(self, '\x06\x20', fields)

class HciLeSetAdvertisingEnable(HciCommand):
    def __init__(self, adv_enable='\x00'):
        HciCommand.__init__(self, '\x0a\x20', data)
        #self.length    = '\x01'

class HciLeSetScanParametersCommand(HciCommand):
    def __init__(self, scan_type='\x00', scan_interval='\x10\x00', scan_window='\x20\x00',
            own_addr_type='\x00', scan_filter_policy='\x00'):
        fields = [  ['scan_type'         , scan_type         , 1],
                    ['scan_interval'     , scan_interval     , 2],
                    ['scan_window'       , scan_window       , 2],
                    ['own_addr_type'     , own_addr_type     , 1],
                    ['scan_filter_policy', scan_filter_policy, 1] ]
        HciCommand.__init__(self, '\x0b\x20', fields)

class HciLeSetScanEnable(HciCommand):
    def __init__(self, scan_enable='\x00', filter_duplicates='\x00'):
        fields = [  ['scan_enable'      , scan_enable      , 1],
                    ['filter_duplicates', filter_duplicates, 1] ]
        HciCommand.__init__(self, '\x0c\x20', fields)

class HciLeCreateConnection(HciCommand):
    def __init__(self, scan_interval='\x10\x00', scan_window='\x10\x00', initiator_filter_policy='\x00',
            peer_addr_type='\x01', peer_addr='\x00\x00\x00\x00\x00', own_addr_type='\x00', 
            conn_interval_min='\x50\x00', conn_interval_max='\x50\x00', conn_latency='\x00\x00',
            supervision_timeout='\x50\x02', min_ce_length=None, max_ce_length=None):
        if min_ce_length == None: min_ce_length = conn_interval_min
        if max_ce_length == None: max_ce_length = conn_interval_max
        fields = [  ['scan_interval',           scan_interval,           2],
                    ['scan_window',             scan_window,             2],
                    ['initiator_filter_policy', initiator_filter_policy, 1],
                    ['peer_addr_type',          peer_addr_type,          1],
                    ['peer_addr',               peer_addr,               6],
                    ['own_addr_type',           own_addr_type,           1],
                    ['conn_interval_min',       conn_interval_min,       2],
                    ['conn_interval_max',       conn_interval_max,       2],
                    ['conn_latency',            conn_latency,            1],
                    ['supervision_timeout',     supervision_timeout,     2],
                    ['min_ce_length',           min_ce_length,           2],
                    ['max_ce_length',           max_ce_length,           2] ]
        HciCommand.__init__(self, '\x0d\x20', fields)


class HciLeCreateConnectionCancel(HciCommand):
    def __init__(self):
        HciCommand.__init__(self, '\x0e\x20')

class HciLeReadWhiteListSize(HciCommand):
    def __init__(self):
        HciCommand.__init__(self, '\x0f\x20')

class HciLeClearWhiteList(HciCommand):
    def __init__(self):
        HciCommand.__init__(self, '\x10\x20')

class HciLeAddDeviceToWhiteList(HciCommand):
    def __init__(self, addr_type='\x00', addr='\x00\x00\x00\x00\x00\x00'):
        fields = [  ['addr_type', addr_type, 1],
                    ['addr',      addr,      6] ]
        HciCommand.__init__(self, '\x11\x20', fields)

class HciLeConnectionUpdate(HciCommand):
    def __init__(self, connection_handle='\x00\x00', conn_interval_min='\x50\x00', conn_interval_max='\x50\x00',
            conn_latency='\x00\x00', supervision_timeout='\x50\x02', min_ce_length=None, max_ce_length=None):
        if min_ce_length == None: min_ce_length = conn_interval_min
        if max_ce_length == None: max_ce_length = conn_interval_max
        fields = [  ['connection_handle',    connection_handle,   2],
                    ['conn_interval_min',    conn_interval_min,   2],
                    ['conn_interval_max',    conn_interval_max,   2],
                    ['conn_latency',         conn_latency,        2],
                    ['supervision_timeout',  supervision_timeout, 2],
                    ['min_ce_length',        min_ce_length,       2],
                    ['max_ce_length',        max_ce_length,       2] ]
        HciCommand.__init__(self, '\x13\x20', fields)

class HciNrfGetVersionInfo(HciCommand):
    def __init__(self):
        HciCommand.__init__(self, '\x06\xfc')

# - HciReset:                            {'OpCode':030C,'Length':0},
# - HciDisconnect:                       {'OpCode':0604,'Length':3},
# - HciReadRemoteVersionInformation:     {'OpCode':1D04,'Length':2},
# - HciReadPublicDeviceAddress:          {'OpCode':0910,'Length':0},
# - HciLeReadBufferSize:                 {'OpCode':0220,'Length':0},
# - HciLeReadLocalSupportedFeatures:     {'OpCode':0320,'Length':0},
# - HciLeSetRandomAddress:               {'OpCode':0520,'Length':6},
# - HciLeSetAdvertisingParameters:       {'OpCode':0620,'Length':15},
# - HciLeSetAdvertisingEnable:           {'OpCode':0A20,'Length':1},
# - HciLeSetScanParametersCommand:       {'OpCode':0B20,'Length':7},
# - HciLeSetScanEnable:                  {'OpCode':0C20,'Length':2},
# - HciLeCreateConnection:               {'OpCode':0D20,'Length':25},
# - HciLeCreateConnectionCancel:         {'OpCode':0E20,'Length':0},
# - HciLeReadWhiteListSize:              {'OpCode':0F20,'Length':0},
# - HciLeClearWhiteList:                 {'OpCode':1020,'Length':0},
# - HciLeAddDeviceToWhiteList:           {'OpCode':1120,'Length':7},
# - HciLeConnectionUpdate:               {'OpCode':1320,'Length':14},
#   HciLeSetHostChannelClassification:   {'OpCode':1420,'Length':5},
#   HciLeReadChannelMap:                 {'OpCode':1520,'Length':2},
#   HciLeReadRemoteUsedFeatures:         {'OpCode':1620,'Length':2},
#   HciLeEncrypt:                        {'OpCode':1720,'Length':32},
#   HciLeRand:                           {'OpCode':1820,'Length':0},
#   HciLeStartEncryption:                {'OpCode':1920,'Length':28},
#   HciLeLongTermKeyRequestReply:        {'OpCode':1A20,'Length':18},
#   HciLeLongTermKeyRequestNegativeReply:{'OpCode':1B20,'Length':2},
#   HciNrfSetClockParameters:            {'OpCode':01FC,'Length':3},
#   HciNrfSetTransmitPowerLevel:         {'OpCode':02FC,'Length':1},
#   HciNrfSetBdAddr:                     {'OpCode':03FC,'Length':6},
# - HciNrfGetVersionInfo:                {'OpCode':06FC,'Length':0},

###################### DATA ##########################
# BLUETOOTH SPECIFICATION Version 4.0 [Vol 2] page 429 of 1114
class HciDataPkt(HciPkt):
    def __init__(self, conn_handle, payload_pkt, pb_flag='\x00', bc_flag='\x00'):
        HciPkt.__init__(self, '\x02')
        self.conn_handle = conn_handle
        self.payload_pkt = payload_pkt
        self.pb_flag     = pb_flag
        self.bc_flag     = bc_flag

    def serialize(self):
        payload = self.payload_pkt.serialize()
        length = len(payload)
        # TODO: Handle pb_flag and bc_flag !!!!1111oneoeneone
        # TODO: Handle length field with 16 bits
        return ''.join([self.uart_type, self.conn_handle, chr(length), '\x00', payload])

    @staticmethod
    def deserialize(data):
        return HciDataPkt('\xff\xfe', L2CapPkt.deserialize(data))

    def __repr__(self):
        return '%s(conn_handle=%r, %r)' % (self.__class__.__name__, self.conn_handle, self.payload_pkt)

#   'ERROR_RESPONSE'                :{'Opcode':0x01,'Pkt':AttErrorResponse,'minSize':5, 'maxSize':5},
#   ## Server Configuration
#   'EXCHANGE_MTU_REQUEST'          :{'Opcode':0x02,'Pkt':AttExchangeMtuRequest,'minSize':3, 'maxSize':3},
#   'EXCHANGE_MTU_RESPONSE'         :{'Opcode':0x03,'Pkt':AttExchangeMtuResponse,'minSize':3, 'maxSize':3},
#   ## Discovery
#   'FIND_INFORMATION_REQUEST'      :{'Opcode':0x04,'Pkt':AttFindInformationRequest,'minSize':5, 'maxSize':5},
#   'FIND_INFORMATION_RESPONSE'     :{'Opcode':0x05,'Pkt':AttFindInformationResponse,'minSize':6, 'maxSize':ATT_MTU},
#   'FIND_BY_TYPE_VALUE_REQUEST'    :{'Opcode':0x06,'Pkt':AttFindByTypeValueRequest,'minSize':7, 'maxSize':ATT_MTU},
#   'FIND_BY_TYPE_VALUE_RESPONSE'   :{'Opcode':0x07,'Pkt':AttFindByTypeValueResponse,'minSize':5, 'maxSize':ATT_MTU},
#   ## Read
#   'READ_BY_TYPE_REQUEST'          :{'Opcode':0x08,'Pkt':AttReadByTypeRequest,'minSize':7, 'maxSize':21},
#   'READ_BY_TYPE_RESPONSE'         :{'Opcode':0x09,'Pkt':AttReadByTypeResponse,'minSize':4, 'maxSize':ATT_MTU},
#   'READ_REQUEST'                  :{'Opcode':0x0A,'Pkt':AttReadRequest,'minSize':3, 'maxSize':3},
#   'READ_RESPONSE'                 :{'Opcode':0x0B,'Pkt':AttReadResponse,'minSize':1, 'maxSize':ATT_MTU},
#   'READ_BLOB_REQUEST'             :{'Opcode':0x0C,'Pkt':AttReadBlobRequest,'minSize':5, 'maxSize':5},
#   'READ_BLOB_RESPONSE'            :{'Opcode':0x0D,'Pkt':AttReadBlobResponse,'minSize':1, 'maxSize':ATT_MTU},
#   'READ_MULTIPLE_REQUEST'         :{'Opcode':0x0E,'Pkt':AttReadMultipleRequest,'minSize':5, 'maxSize':ATT_MTU},
#   'READ_MULTIPLE_RESPONSE'        :{'Opcode':0x0F,'Pkt':AttReadMultipleResponse,'minSize':1, 'maxSize':ATT_MTU},
#   'READ_BY_GROUP_TYPE_REQUEST'    :{'Opcode':0x10,'Pkt':AttReadByGroupTypeRequest,'minSize':7, 'maxSize':21},
#   'READ_BY_GROUP_TYPE_RESPONSE'   :{'Opcode':0x11,'Pkt':AttReadByGroupTypeResponse,'minSize':5, 'maxSize':ATT_MTU},
#   ## Write
#   'WRITE_COMMAND'                 :{'Opcode':0x52,'Pkt':AttWriteCommand,'minSize':3, 'maxSize':ATT_MTU},
#   'SIGNED_WRITE_COMMAND'          :{'Opcode':0xD2,'Pkt':AttSignedWriteCommand,'minSize':3, 'maxSize':ATT_MTU},
#   'WRITE_REQUEST'                 :{'Opcode':0x12,'Pkt':AttWriteRequest,'minSize':3, 'maxSize':ATT_MTU},
#   'WRITE_RESPONSE'                :{'Opcode':0x13,'Pkt':AttWriteResponse,'minSize':1, 'maxSize':1},
#   'PREPARE_WRITE_REQUEST'         :{'Opcode':0x16,'Pkt':AttPrepareWriteRequest,'minSize':5, 'maxSize':ATT_MTU},
#   'PREPARE_WRITE_RESPONSE'        :{'Opcode':0x17,'Pkt':AttPrepareWriteResponse,'minSize':5, 'maxSize':ATT_MTU},
#   'EXECUTE_WRITE_REQUEST'         :{'Opcode':0x18,'Pkt':AttExecuteWriteRequest,'minSize':2, 'maxSize':2},
#   'EXECUTE_WRITE_RESPONSE'        :{'Opcode':0x19,'Pkt':AttExecuteWriteResponse,'minSize':1, 'maxSize':1},
#   ## Server Initiated
#   'HANDLE_VALUE_NOTIFICATION'     :{'Opcode':0x1B,'Pkt':AttHandleValueNotification,'minSize':3, 'maxSize':ATT_MTU},
#   'HANDLE_VALUE_INDICATION'       :{'Opcode':0x1D,'Pkt':AttHandleValueIndication,'minSize':3, 'maxSize':ATT_MTU},
#   'HANDLE_VALUE_CONFIRMATION'     :{'Opcode':0x1E,'Pkt':AttHandleValueConfirmation,'minSize':1, 'maxSize':1},

###################### L2CAP #########################
class L2CapPkt(object):
    def __init__(self, payload_pkt):
        self.payload_pkt = payload_pkt
        if   isinstance(payload_pkt, AttPkt):            self.channel_id = '\x04\x00'
        #elif isinstance(payload_pkt, L2CapSignalingPkt): self.channel_id = '\x05\x00'
        #elif isinstance(payload_pkt, SmpPkt):            self.channel_id = '\x06\x00'

    def serialize(self):
        payload = self.payload_pkt.serialize()
        length = len(payload)
        # TODO: Handle length field with 16 bits
        return ''.join([chr(length), '\x00', self.channel_id, payload])

    @staticmethod
    def deserialize(data):
        return L2CapPkt(AttRequest('', ''))

    def __repr__(self):
        return '%s(channel_id=%r, %r)' % (self.__class__.__name__, self.channel_id, self.payload_pkt)

###################### ATT request ###################
class AttPkt(object):
    pass

class AttRequest(AttPkt):
    def __init__(self, op_code, fields):
        self.op_code = op_code
        self.fields  = fields

    def serialize(self):
        data = ''
        for field in self.fields:
            data += field[1] # TODO: Verify size of field
        return ''.join([self.op_code, data])
    
    def __repr__(self):
        return '%s(op_code: %r, %s)' % (
                self.__class__.__name__, self.op_code,
                ', '.join(['%s: %r' % (i[0], i[1]) for i in self.fields]))

class AttReadRequest(AttRequest):
    def __init__(self, handle):
        fields = [  ['handle', handle, 1] ]
        AttRequest.__init__(self, '\x0A', fields)

###################### ATT responses #################
class Attribute:
    def __init__(self, handle, uuid, value=None):
        self.handle = handle
        self.uuid = uuid
        self.value = []
        if value != None:
            for v in value:
                self.value.append(int(v))

    def __repr__(self):
        if self.handle == None:
            handle = 'None'
        else:
            handle = "0x%04x" % self.handle
        if self.uuid == None:
            uuid = 'None'
        else:
            uuid = "0x%04x" % self.uuid
        value = "".join([chr(i) for i in self.value])
        return "%s(handle=%s, uuid=%s, value=%s)" % (self.__class__.__name__, handle, uuid, repr(value))

#    'READ_RESPONSE'                 :{'Opcode':0x0B,'Pkt':AttReadResponse,'minSize':1, 'maxSize':ATT_MTU},
#class AttReadResponse(AttResponse):
#    def create(self, Attributes = None):
#        self.Attributes = Attributes
#    
#    def build(self):
#        self.Content = [self.Opcode] + self.Attributes.value[:ATT_MTU]
#    
#    def parse(self, packet):
#        value = self.Content[1:]
#        self.Attributes = Attribute(None,None,value)
#
#    def __repr__(self):
#        return "%s(Attributes=%s)" % (self.__class__.__name__, repr(self.Attributes))
#
#    def __init__(self, pkt):
#        attribute = Attribute(pkt[3:])
#        fields = [  ['attrs',            [attribute],     1] ]
#        HciEvent.__init__(self, '\x01', fields)


###################### EVENTS ########################
class HciEvent(HciPkt):
    def __init__(self, event_code, fields):
        HciPkt.__init__(self, '\x04')
        self.event_code = event_code
        self.fields = fields

    def __getattr__(self, name):
        for field in self.fields:
            if field[0] == name:
                return field[1]
        raise AttributeError("'%s' object has no attribute '%s'" % (self.__class__.__name__, name))

    def __repr__(self):
        return '%s(event_code: %r, %s)' % (
                self.__class__.__name__, self.event_code,
                ', '.join(['%s: %r' % (i[0], i[1]) for i in self.fields]))

class HciReadRemoteVersionInformationComplete(HciEvent):
    def __init__(self, pkt):
        fields = [  ['status',            pkt[5],     1],
                    ['conn_handle',       pkt[6:8],   2],
                    ['version',           pkt[8],     1],
                    ['manufacturer_name', pkt[9:11],  2],
                    ['sub_version',       pkt[11:13], 2]  ]
        HciEvent.__init__(self, '\x01', fields)

class AdvReport(object):
    def __init__(self, pkt):
        length = ord(pkt[8])
        self.fields = [ ['event_type', pkt[0],          1],
                        ['addr_type',  pkt[1],          1],
                        ['addr',       pkt[2:8],        6],
                        ['length',     pkt[8],          1],
                        ['data',       pkt[9:9+length], length],
                        ['rssi',       pkt[9+length:],  1] ]

    def __getattr__(self, name):
        for field in self.fields:
            if field[0] == name:
                return field[1]
        raise AttributeError("'%s' object has no attribute '%s'" % (self.__class__.__name__, name))

    def __repr__(self):
        tmp = ', '.join(['%s: %r' % (i[0], i[1]) for i in self.fields])
        return '%s(%s)' % (self.__class__.__name__, tmp)

class HciLeAdvertisingReport(HciEvent):
    def __init__(self, pkt):
        reports = []
        num_reports = ord(pkt[6])
        fields = [  ['sub_event_code', pkt[5],  1],
                    ['num_reports',    pkt[6],  1],
                    ['reports',        reports, num_reports] ]
        pos = 0
        for i in range(num_reports):
            length = 10 + ord(pkt[15+pos])
            reports.append(AdvReport(pkt[7+pos:7+pos+length]))
            pos += length
        HciEvent.__init__(self, '\x04', fields)

class HciLeConnectionComplete(HciEvent):
    def __init__(self, pkt):
        reports = []
        num_reports = ord(pkt[6])
        fields = [  ['sub_event_code',        pkt[5],     1],
                    ['status',                pkt[6],     1],
                    ['conn_handle',           pkt[7:9],   2],
                    ['role',                  pkt[9],     1],
                    ['peer_addr_type',        pkt[10],    1],
                    ['peer_addr',             pkt[11:17], 6],
                    ['conn_interval',         pkt[17:19], 2],
                    ['conn_latency',          pkt[19:21], 2],
                    ['supervision_timeout',   pkt[21:23], 2],
                    ['master_clock_accuracy', pkt[23],    1] ]
        HciEvent.__init__(self, '\x05', fields)

class HciLeConnectionUpdateComplete(HciEvent):
    def parse(self, packet):
        self.SubEventCode       = packet[2]
        self.Status             = packet[3]
        self.ConnectionHandle   = packet[4] | (packet[5] << 8)
        self.ConnInterval       = packet[6] | (packet[7] << 8)
        self.ConnLatency        = packet[8] | (packet[9] << 8)
        self.SupervisionTimeout = packet[10] | (packet[11] << 8)
    def __init__(self, pkt):
        fields = [  ['sub_event_code',        pkt[5],     1],
                    ['status',                pkt[6],     1],
                    ['conn_handle',           pkt[7:9],   2],
                    ['conn_interval',         pkt[9:11],  2],
                    ['conn_latency',          pkt[11:13], 2],
                    ['supervision_timeout',   pkt[13:15], 2] ]
        HciEvent.__init__(self, '\x07', fields)

class HciDisconnectionComplete(HciEvent):
    def __init__(self, pkt):
        fields = [  ['status',        pkt[5],   1],
                    ['conn_handle',   pkt[6:8], 2],
                    ['reason',        pkt[8],   1]  ]
        HciEvent.__init__(self, '\x0a', fields)

class HciNumCompletePackets(HciEvent):
    def __init__(self, pkt):
        num_handles = ord(pkt[5])
        handles = []
        fields = [  ['num_handles',      pkt[5],   1],
                    ['handles',         handles,   num_handles] ]
        for i in range(num_handles):
            pos = i*4+5
            handles.append([pkt[pos:pos+1], pkt[pos+2:pos+3]])
        HciEvent.__init__(self, '\x0d', fields)

class HciCommandComplete(HciEvent):
    def __init__(self, pkt):
        fields = [  ['num_hci_cmd_pkt',  pkt[5],   1],
                    ['commmand_op_code', pkt[6:8], 2],
                    ['status',           pkt[8],   1]  ]
        if len(pkt) > 8:
            fields.append(['return_params', pkt[9:], len(pkt[9:])])
        HciEvent.__init__(self, '\x0e', fields)

class HciCommandStatus(HciEvent):
    def __init__(self, pkt):
        fields = [  ['status',           pkt[5],   1],
                    ['num_hci_cmd_pkt',  pkt[6],   1],
                    ['commmand_op_code', pkt[7:9], 2] ]
        HciEvent.__init__(self, '\x0f', fields)

# - class HciReadRemoteVersionInformationComplete(HciEventPkt):  # - HCI_READ_REMOTE_VERSION_INFORMATION_COMPLETE_EVENT  = 0x01
#                                                                #   HCI_ERROR_EVENT                                     = 0x02
#                                                                #   HCI_DATA_BUFFER_OVERFLOW_EVENT                      = 0x03
# - class AdvReport(object):
# - class HciLeAdvertisingReport(HciEventPkt):                   # - HCI_ADVERTISING_PACKET_REPORT_EVENT                 = 0x04
# - class HciLeConnectionComplete(HciEventPkt):                  # - HCI_LL_CONNECTION_CREATED_EVENT                     = 0x05
#   class HciLeReadRemoteUsedFeaturesComplete(HciEventPkt):      #   HCI_READ_REMOTE_USED_FEATURES_COMPLETE_EVENT        = 0x06
# - class HciLeConnectionUpdateComplete(HciEventPkt):            # - HCI_LL_CONNECTION_PAR_UPDATE_COMPLETE_EVENT         = 0x07
#   class HciLeLongTermKeyRequest(HciEventPkt):                  #   HCI_LONG_TERM_KEY_REQUESTED_EVENT                   = 0x08
#                                                                #   HCI_FLUSH_OCCURRED_EVENT                            = 0x09
# - class HciDisconnectionComplete(HciEventPkt):                 # - HCI_LL_CONNECTION_TERMINATION_EVENT                 = 0x0A
#   class HciEncryptionChange(HciEventPkt):                      #   HCI_ENCRYPTION_CHANGE_EVENT                         = 0x0B
#   class HciEncryptionKeyRefreshComplete(HciEventPkt):          #   HCI_ENCRYPTION_KEY_REFRESH_COMPLETE_EVENT           = 0x0C
# - class HciNumCompletePackets(HciEventPkt):                    # - HCI_NUM_COMPLETED_PACKETS_EVENT                     = 0x0D
# - class HciCommandComplete(HciEventPkt):                       # - HCI_COMMAND_COMPLETE_EVENT                          = 0x0E
# - class HciCommandStatus(HciEventPkt):                         # - HCI_COMMAND_STATUS_EVENT                            = 0x0F


def event_factory(data):
    if data[2] == '\x04':
        if data[3] == '\x05': return HciDisconnectionComplete(data)
        #if data[3] == '\x08': return HciEncryptionChange(data)
        if data[3] == '\x0C': return HciReadRemoteVersionInformationComplete(data)
        if data[3] == '\x0E': return HciCommandComplete(data)
        if data[3] == '\x0F': return HciCommandStatus(data)
        if data[3] == '\x13': return HciNumCompletePackets(data)
        #if data[3] == '\x30': return HciEncryptionKeyRefreshComplete(data)

        if data[3] == '\x3e':
            if data[5] == '\x01': return HciLeConnectionComplete(data)
            if data[5] == '\x02': return HciLeAdvertisingReport(data)
            #if data[5] == '\x03': return HciLeConnectionUpdateComplete(data)
            #if data[5] == '\x04': return HciLeReadRemoteUsedFeaturesComplete(data)
            #if data[5] == '\x05': return HciLeLongTermKeyRequest(data)
    if data[2] == '\x02':
        return HciDataPkt.deserialize(data)
        pass
    return 'Not decoded yet'

    # rx <=: '\x18\x11\x02\x00 \x13\x00\x0f\x00\x04\x00\x0bXLR2_2_TempLog'


