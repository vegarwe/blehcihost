# TODO: uart_type not a good name. What is it really?
# BLUETOOTH SPECIFICATION Version 4.0 [Vol 2] page 15 of 1114
# BLUETOOTH SPECIFICATION Version 4.0 [Vol 2] page 408 of 1114

class DynamicObject(object):
    class_descr    =  []

    def __init__(self, *args, **argv):
        self.fields = self._parse_fields(args, argv)

    def _parse_fields(self, args, argv):
        # TODO: Verify size of field
        fields =  []
        for i in range(len(self.class_descr)):
            attr = self.class_descr[i][0]
            if i < len(args):
                fields.append((attr, args[i]))
            elif attr in argv:
                fields.append((attr, argv[attr]))
            else:
                if self.class_descr[i][2] == None:
                    raise TypeError("__init__() takes at least %s arguments (%s given)" %
                            (1+len(self.class_descr), 1 + len(args) + len(argv)))
                fields.append((attr, self.class_descr[i][2]))
        return fields

    def __getattr__(self, name):
        for field in self.fields:
            if field[0] == name:
                return field[1]
        raise AttributeError("'%s' object has no attribute '%s'" % (self.__class__.__name__, name))

class HciCommand(DynamicObject):
    uart_type      = '\x01'
    op_code        = '\x00\x00' # TODO: Find invalid op_code to put here
    class_descr    = []         # TODO: Is it OK to access this static array with self.class_descr in init?

    def serialize(self):
        data = ''
        for field in self.fields:
            data += field[1]
        length = chr(len(data))
        return ''.join([self.uart_type, self.op_code, length, data])

    def __repr__(self):
        if len(self.fields) == 0:
            return '%s(op_code=%r)' % ( self.__class__.__name__, self.op_code)
        else:
            return '%s(op_code=%r, %s)' % (
                    self.__class__.__name__, self.op_code,
                    ', '.join(['%s=%r' % (i[0], i[1]) for i in self.fields]))

class HciDataPkt(object):
    uart_type      = '\x02'

    def __init__(self, conn_handle, payload_pkt, pb_flag='\x00', bc_flag='\x00'):
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
        hci_data = data[2:9]
        # TODO: Not finished yet
        #print 'todo: hci_data %r' % (hci_data)
        return HciDataPkt('\xff\xfe', L2CapPkt.deserialize(data[9:]))

    def __repr__(self):
        return '%s(conn_handle=%r, payload_pkt=%r)' % (self.__class__.__name__, self.conn_handle, self.payload_pkt)

class L2CapPkt(object):
    def __init__(self, payload_pkt):
        self.payload_pkt = payload_pkt
        if   isinstance(payload_pkt, AttPkt):            self.channel_id = '\x04\x00'
        #elif isinstance(payload_pkt, L2CapSignalingPkt): self.channel_id = '\x05\x00'
        #elif isinstance(payload_pkt, SmpPkt):            self.channel_id = '\x06\x00'
        else:                                            self.channel_id = '\x00\x00'

    def serialize(self):
        payload = self.payload_pkt.serialize()
        length = len(payload)
        # TODO: Handle length field with 16 bits
        return ''.join([chr(length), '\x00', self.channel_id, payload])

    @staticmethod
    def deserialize(data):
        if data[0:2] == '\x04\x00':
            return L2CapPkt(AttResponse.deserialize(data[2:]))

    def __repr__(self):
        return '%s(channel_id=%r, payload_pkt=%r)' % (self.__class__.__name__, self.channel_id, self.payload_pkt)

ATT_MTU = 23
class AttPkt(DynamicObject):
    op_code = '\x00' # TODO: Find invalid op_code to put here
    class_descr = [] # TODO: Is it OK to access this static array with self.class_descr in init?

    def serialize(self):
        data = ''
        for field in self.fields:
            data += field[1]
        return ''.join([self.op_code, data])

    def __repr__(self):
        if len(self.fields) == 0:
            return '%s(op_code=%r)' % ( self.__class__.__name__, self.op_code)
        else:
            return '%s(op_code=%r, %s)' % (
                    self.__class__.__name__, self.op_code,
                    ', '.join(['%s=%r' % (i[0], i[1]) for i in self.fields]))

class AttRequest(AttPkt):
    pass

class AttResponse(AttPkt):
    @staticmethod
    def deserialize(data):
        responses = [ 
                AttErrorResponse,
                AttExchangeMtuResponse,
                AttFindInformationResponse,
                AttReadResponse,
                AttWriteResponse,
                AttHandleValueIndication
        ]
        for response in responses:
            if data[0] == response.op_code:
                return response.deserialize(data[1:])

#class Attribute:
#    def __init__(self, handle, uuid, value=None):
#        self.handle = handle
#        self.uuid = uuid
#        self.value = []
#        if value != None:
#            for v in value:
#                self.value.append(int(v))
#

class HciEvent(DynamicObject):
    uart_type      = '\x04'
    event_code     = '\x00' # TODO: Find invalid op_code to put here
    sub_event_code = ''
    class_descr    =  []    # TODO: Is it OK to access this static array with self.class_descr in init?

    def __repr__(self):
        sub = ''
        if self.sub_event_code != '':
            sub = ', sub_event_code=%r' % self.sub_event_code
        return '%s(event_code=%r%s, %s)' % (
                self.__class__.__name__, self.event_code, sub,
                ', '.join(['%s=%r' % (i[0], i[1]) for i in self.fields]))

    @staticmethod
    def deserialize(data):
        #             '\x01' - '\x04' not used by LE controller
        if data[3] == '\x05': return HciDisconnectionComplete.deserialize(data)
        #             '\x06' - '\x07' not used by LE controller
        if data[3] == '\x08': return HciEncryptionChange.deserialize(data)
        #             '\x09' - '\x0a' not used by LE controller
       #if data[3] == '\x0b': return HciReadRemoteSupportedFeatures.deserialize(data)
        if data[3] == '\x0c': return HciReadRemoteVersionInformationComplete.deserialize(data)
        #             '\x0d' not used by LE controller
        if data[3] == '\x0e': return HciCommandComplete.deserialize(data)
        if data[3] == '\x0f': return HciCommandStatus.deserialize(data)
       #if data[3] == '\x10': return HardwareError.deserialize(data) # TODO: Used by LE?
       #if data[3] == '\x11': return FlushOccurred.deserialize(data) # TODO: Used by LE?
        #             '\x12' not used by LE controller
        if data[3] == '\x13': return HciNumCompletePackets.deserialize(data)
        #             '\x14' - '\xyy' TODO: not used by LE controller?
        if data[3] == '\x30': return HciEncryptionKeyRefreshComplete.deserialize(data)
        #             '\x31' - '\x3d' TODO: not used by LE controller?
        if data[3] == '\x3e':
            if data[5] == '\x01': return HciLeConnectionComplete.deserialize(data)
            if data[5] == '\x02': return HciLeAdvertisingReport.deserialize(data)
           #if data[5] == '\x03': return HciLeConnectionUpdateComplete.deserialize(data)
            if data[5] == '\x04': return HciLeReadRemoteUsedFeaturesComplete.deserialize(data)
            if data[5] == '\x05': return HciLeLongTermKeyRequest.deserialize(data)
        #             '\x40' - '\x3d' TODO: not used by LE controller?


def event_factory(data):
    if data[2] == '\x04':
        return HciEvent.deserialize(data)
    if data[2] == '\x02':
        return HciDataPkt.deserialize(data)
    return 'Not decoded yet'


###################### COMMANDS ######################
class HciReset(HciCommand):
    op_code = '\x03\x0c'

class HciDisconnect(HciCommand):
    op_code = '\x06\x04'
    class_descr = [ ['conn_handle',              2, None],
                    ['reason'     ,              1, '\x13'] ]

class HciReadRemoteVersionInformation(HciCommand):
    op_code = '\x1d\x04'
    class_descr = [ ['conn_handle',              2, None] ]

class HciReadPublicDeviceAddress(HciCommand):
    op_code = '\x09\x10'

class HciLeReadBufferSize(HciCommand):
    op_code = '\x02\x20'

class HciLeReadLocalSupportedFeatures(HciCommand):
    op_code = '\x03\x20'

class HciLeSetRandomAddress(HciCommand):
    op_code = '\x05\x20'
    class_descr = [ ['addr',                    6, None] ]

class HciLeSetAdvertisingParameters(HciCommand):
    op_code = '\x06\x20'
    class_descr = [ ['adv_interval_min' ,       2, '\x00\x08'],
                    ['adv_interval_max' ,       2, '\x00\x08'],
                    ['adv_type'         ,       1, '\x00'],
                    ['own_addr_type'    ,       1, '\x01'],
                    ['direct_addr_type' ,       1, '\x00'],
                    ['direct_addr'      ,       6, '\x00\x00\x00\x00\x00\x00'],
                    ['adv_channel_map'  ,       1, '\x03'],
                    ['adv_filter_policy',       1, '\x00'] ]

class HciLeSetAdvertisingEnable(HciCommand):
    op_code = '\x0a\x20'
    class_descr = [ ['adv_enable' , 1, '\x00'] ]

class HciLeSetScanParametersCommand(HciCommand):
    op_code = '\x0b\x20'
    class_descr = [ ['scan_type'         ,      1, '\x00'],
                    ['scan_interval'     ,      2, '\x10\x00'],
                    ['scan_window'       ,      2, '\x20\x00'],
                    ['own_addr_type'     ,      1, '\x00'],
                    ['scan_filter_policy',      1, '\x00'] ]

class HciLeSetScanEnable(HciCommand):
    op_code = '\x0c\x20'
    class_descr = [ ['scan_enable'      ,       1, '\x00'],
                    ['filter_duplicates',       1, '\x00'] ]

class HciLeCreateConnection(HciCommand):
    op_code = '\x0d\x20'
    class_descr = [ ['scan_interval',           2, '\x10\x00'],
                    ['scan_window',             2, '\x10\x00'],
                    ['initiator_filter_policy', 1, '\x00'],
                    ['peer_addr_type',          1, '\x01'],
                    ['peer_addr',               6, '\x00\x00\x00\x00\x00'],
                    ['own_addr_type',           1, '\x00'],
                    ['conn_interval_min',       2, '\x50\x00'],
                    ['conn_interval_max',       2, '\x50\x00'],
                    ['conn_latency',            1, '\x00\x00'],
                    ['supervision_timeout',     2, '\x50\x02'],
                    ['min_ce_length',           2, '\x50\x00'],  # TODO: What is min_ce_length?
                    ['max_ce_length',           2, '\x50\x00'] ] # TODO: What is max_ce_length?


class HciLeCreateConnectionCancel(HciCommand):
    op_code = '\x0e\x20'

class HciLeReadWhiteListSize(HciCommand):
    op_code = '\x0f\x20'

class HciLeClearWhiteList(HciCommand):
    op_code = '\x10\x20'

class HciLeAddDeviceToWhiteList(HciCommand):
    op_code = '\x11\x20'
    class_descr = [ ['addr_type',               1, '\x00'],
                    ['addr',                    6, '\x00\x00\x00\x00\x00\x00'] ]

class HciLeConnectionUpdate(HciCommand):
    op_code = '\x13\x20'
    class_descr = [ ['conn_handle',             2, None],
                    ['conn_interval_min',       2, '\x50\x00'],
                    ['conn_interval_max',       2, '\x50\x00'],
                    ['conn_latency',            2, '\x00\x00'],
                    ['supervision_timeout',     2, '\x50\x02'],
                    ['min_ce_length',           2, '\x50\x00'],
                    ['max_ce_length',           2, '\x50\x00'] ]

class HciLeSetHostChannelClassification(HciCommand):
    op_code = '\x14\x20'
    class_descr = [ ['channel_map', 5, None] ]

class HciLeReadChannelMap(HciCommand):
    op_code = '\x15\x20'
    class_descr = [ ['conn_handle',             2, None] ]

class HciLeReadRemoteUsedFeatures(HciCommand):  
    op_code = '\x16\x20'
    class_descr = [ ['conn_handle',             2, None] ]

class HciLeEncrypt(HciCommand):
    op_code = '\x17\x20'
    class_descr = [ ['key_ltlend',             16, None],
                    ['plain_text_ltlend',      16, None] ]

class HciLeRand(HciCommand):
    op_code = '\x18\x20'

class HciLeStartEncryption(HciCommand):
    op_code = '\x19\x20'
    class_descr = [ ['conn_handle',             2, None],
                    ['rand_number',             8, None],
                    ['ediv',                    2, None],
                    ['long_term_key_ltlend',   16, None] ]

class HciLeLongTermKeyRequestReply(HciCommand):
    op_code = '\x1a\x20'
    class_descr = [ ['conn_handle',             2, None],
                    ['long_term_key_ltlend',   16, None] ]

class HciLeLongTermKeyRequestNegativeReply(HciCommand):
    op_code = '\x1b\x20'
    class_descr = [ ['conn_handle',             2, None] ]

class HciNrfSetClockParameters(HciCommand):
    op_code = '\x01\xfc'
    class_descr = [ ['clk_src_32k',             1, None],
                    ['sleep_clk_acc',           1, None],
                    ['clk_src_16m',             1, None] ]

class HciNrfSetTransmitPowerLevel(HciCommand):
    op_code = '\x02\xfc'
    class_descr = [ ['tx_level',                1, None] ]

class HciNrfSetBdAddr(HciCommand):
    op_code = '\x03\xfc'
    class_descr = [ ['device_addr',             6, None] ]

class HciNrfGetVersionInfo(HciCommand):
    op_code = '\x06\xfc'

# + HciReset:                            {'OpCode':030C,'Length':0},
# - HciDisconnect:                       {'OpCode':0604,'Length':3},
# - HciReadRemoteVersionInformation:     {'OpCode':1D04,'Length':2},
# + HciReadPublicDeviceAddress:          {'OpCode':0910,'Length':0},
# + HciLeReadBufferSize:                 {'OpCode':0220,'Length':0},
# - HciLeReadLocalSupportedFeatures:     {'OpCode':0320,'Length':0},
# - HciLeSetRandomAddress:               {'OpCode':0520,'Length':6},
# - HciLeSetAdvertisingParameters:       {'OpCode':0620,'Length':15},
# - HciLeSetAdvertisingEnable:           {'OpCode':0A20,'Length':1},
# + HciLeSetScanParametersCommand:       {'OpCode':0B20,'Length':7},
# + HciLeSetScanEnable:                  {'OpCode':0C20,'Length':2},
# - HciLeCreateConnection:               {'OpCode':0D20,'Length':25},
# - HciLeCreateConnectionCancel:         {'OpCode':0E20,'Length':0},
# - HciLeReadWhiteListSize:              {'OpCode':0F20,'Length':0},
# - HciLeClearWhiteList:                 {'OpCode':1020,'Length':0},
# - HciLeAddDeviceToWhiteList:           {'OpCode':1120,'Length':7},
# - HciLeConnectionUpdate:               {'OpCode':1320,'Length':14},
# - HciLeSetHostChannelClassification:   {'OpCode':1420,'Length':5},
# - HciLeReadChannelMap:                 {'OpCode':1520,'Length':2},
# - HciLeReadRemoteUsedFeatures:         {'OpCode':1620,'Length':2},
# - HciLeEncrypt:                        {'OpCode':1720,'Length':32},
# - HciLeRand:                           {'OpCode':1820,'Length':0},
# - HciLeStartEncryption:                {'OpCode':1920,'Length':28},
# - HciLeLongTermKeyRequestReply:        {'OpCode':1A20,'Length':18},
# - HciLeLongTermKeyRequestNegativeReply:{'OpCode':1B20,'Length':2},
# - HciNrfSetClockParameters:            {'OpCode':01FC,'Length':3},
# - HciNrfSetTransmitPowerLevel:         {'OpCode':02FC,'Length':1},
# - HciNrfSetBdAddr:                     {'OpCode':03FC,'Length':6},
# + HciNrfGetVersionInfo:                {'OpCode':06FC,'Length':0},

###################### DATA ##########################

###################### L2CAP #########################

###################### ATT ###########################
class AttErrorResponse(AttResponse):
    op_code = '\x01'
    class_descr = [ ['error_op_code',           1, None],
                    ['handle',                  2, None],
                    ['error_code',              1, None] ]

class AttExchangeMtuRequest(AttRequest):
    op_code = '\x02'
    class_descr = [ ['rx_mtu',                  2, '\x23\x00'] ]

class AttExchangeMtuResponse(AttResponse):
    op_code = '\x03'
    class_descr = [ ['rx_mtu',                  2, '\x23\x00'] ]

    @staticmethod
    def deserialize(data):
        return AttExchangeMtuResponse(data)

class AttFindInformationRequest(AttRequest):
    op_code = '\x04'
    class_descr = [ ['start_handle',            2, '\x00\x00'],
                    ['end_handle',              2, '\xff\xff'] ]

class AttFindInformationResponse(AttResponse):
    op_code = '\x05'
    class_descr = [ ['format',                  1, '\x01'],
                    ['attributes',         (1, 9), []] ] # TODO: Find actual max limit here

    @staticmethod
    def deserialize(data):
        format_ = data[0]
        attrs = data[1:]
        if   format_ == '\x01':
            attributes = [(attrs[(4*i):(4*i)+2], attrs[(4*i)+2:(4*i)+4]) for i in xrange(0, len(attrs)/4)]
        elif format_ == '\x02':
            attributes = [(attrs[(18*i):(18*i)+2], attrs[(18*i)+2:(18*i)+18]) for i in xrange(0, len(attrs)/18)]
        # TODO: Else, raise hell
        return AttFindInformationResponse(format_, attributes)

    def parse(self, packet):
        size = len(packet)
        self.Format = self.Content[1]
        self.Attributes = []
        size = size - 2;
        if self.Format == format['TYPE_16']:
            index = 2
            while size >= 4:
                handle = (self.Content[index+1]<<8) | self.Content[index]
                uuid = (self.Content[index+3]<<8) | self.Content[index+2]
                self.Attributes.append(Attribute(handle, uuid, None))
                size = size - 4
                index = index + 4
        elif self.Format == format['TYPE_128']:
            handle = (self.Content[3] << 8) | self.Content[2]
            temp = self.Content[4:]
            temp.reverse()
            uuid = 0
            for value in temp:
                uuid = (uuid << 8) | value
            self.Attributes.append(Attribute(handle, uuid, None))

class AttReadRequest(AttRequest):
    op_code = '\x0a'
    class_descr = [ ['handle',                  2, None] ]

class AttReadResponse(AttResponse):
    op_code = '\x0b'
    class_descr = [ ['value',        (1, ATT_MTU), None] ]

    @staticmethod
    def deserialize(data):
        return AttReadResponse(data)

class AttWriteCommand(AttRequest):
    op_code = '\x52'
    class_descr = [ ['handle',                  2, None],
                    ['value',        (1, ATT_MTU), None] ]

class AttWriteRequest(AttRequest):
    op_code = '\x12'
    class_descr = [ ['handle',                  2, None],
                    ['value',        (1, ATT_MTU), None] ]

class AttWriteResponse(AttResponse):
    op_code = '\x13'

    @staticmethod
    def deserialize(data):
        return AttWriteResponse()

class AttHandleValueIndication(AttResponse):
    op_code = '\x1d'
    class_descr = [ ['handle',                  2, None],
                    ['value',        (1, ATT_MTU), None] ]

    @staticmethod
    def deserialize(data):
        return AttHandleValueIndication(data[0:2], data[2:])

class AttHandleValueConfirmation(AttResponse):
    op_code = '\x1e'

    @staticmethod
    def deserialize(data):
        return AttHandleValueConfirmation()

# - 'ERROR_RESPONSE'                :{'Opcode':0x01,'Pkt':AttErrorResponse,'minSize':5, 'maxSize':5},
#   ## Server Configuration
# + 'EXCHANGE_MTU_REQUEST'          :{'Opcode':0x02,'Pkt':AttExchangeMtuRequest,'minSize':3, 'maxSize':3},
# + 'EXCHANGE_MTU_RESPONSE'         :{'Opcode':0x03,'Pkt':AttExchangeMtuResponse,'minSize':3, 'maxSize':3},
#   ## Discovery
# - 'FIND_INFORMATION_REQUEST'      :{'Opcode':0x04,'Pkt':AttFindInformationRequest,'minSize':5, 'maxSize':5},
# - 'FIND_INFORMATION_RESPONSE'     :{'Opcode':0x05,'Pkt':AttFindInformationResponse,'minSize':6, 'maxSize':ATT_MTU},
#   'FIND_BY_TYPE_VALUE_REQUEST'    :{'Opcode':0x06,'Pkt':AttFindByTypeValueRequest,'minSize':7, 'maxSize':ATT_MTU},
#   'FIND_BY_TYPE_VALUE_RESPONSE'   :{'Opcode':0x07,'Pkt':AttFindByTypeValueResponse,'minSize':5, 'maxSize':ATT_MTU},
#   ## Read
#   'READ_BY_TYPE_REQUEST'          :{'Opcode':0x08,'Pkt':AttReadByTypeRequest,'minSize':7, 'maxSize':21},
#   'READ_BY_TYPE_RESPONSE'         :{'Opcode':0x09,'Pkt':AttReadByTypeResponse,'minSize':4, 'maxSize':ATT_MTU},
# + 'READ_REQUEST'                  :{'Opcode':0x0A,'Pkt':AttReadRequest,'minSize':3, 'maxSize':3},
# + 'READ_RESPONSE'                 :{'Opcode':0x0B,'Pkt':AttReadResponse,'minSize':1, 'maxSize':ATT_MTU},
#   'READ_BLOB_REQUEST'             :{'Opcode':0x0C,'Pkt':AttReadBlobRequest,'minSize':5, 'maxSize':5},
#   'READ_BLOB_RESPONSE'            :{'Opcode':0x0D,'Pkt':AttReadBlobResponse,'minSize':1, 'maxSize':ATT_MTU},
#   'READ_MULTIPLE_REQUEST'         :{'Opcode':0x0E,'Pkt':AttReadMultipleRequest,'minSize':5, 'maxSize':ATT_MTU},
#   'READ_MULTIPLE_RESPONSE'        :{'Opcode':0x0F,'Pkt':AttReadMultipleResponse,'minSize':1, 'maxSize':ATT_MTU},
#   'READ_BY_GROUP_TYPE_REQUEST'    :{'Opcode':0x10,'Pkt':AttReadByGroupTypeRequest,'minSize':7, 'maxSize':21},
#   'READ_BY_GROUP_TYPE_RESPONSE'   :{'Opcode':0x11,'Pkt':AttReadByGroupTypeResponse,'minSize':5, 'maxSize':ATT_MTU},
#   ## Write
# - 'WRITE_COMMAND'                 :{'Opcode':0x52,'Pkt':AttWriteCommand,'minSize':3, 'maxSize':ATT_MTU},
#   'SIGNED_WRITE_COMMAND'          :{'Opcode':0xD2,'Pkt':AttSignedWriteCommand,'minSize':3, 'maxSize':ATT_MTU},
# + 'WRITE_REQUEST'                 :{'Opcode':0x12,'Pkt':AttWriteRequest,'minSize':3, 'maxSize':ATT_MTU},
# + 'WRITE_RESPONSE'                :{'Opcode':0x13,'Pkt':AttWriteResponse,'minSize':1, 'maxSize':1},
#   'PREPARE_WRITE_REQUEST'         :{'Opcode':0x16,'Pkt':AttPrepareWriteRequest,'minSize':5, 'maxSize':ATT_MTU},
#   'PREPARE_WRITE_RESPONSE'        :{'Opcode':0x17,'Pkt':AttPrepareWriteResponse,'minSize':5, 'maxSize':ATT_MTU},
#   'EXECUTE_WRITE_REQUEST'         :{'Opcode':0x18,'Pkt':AttExecuteWriteRequest,'minSize':2, 'maxSize':2},
#   'EXECUTE_WRITE_RESPONSE'        :{'Opcode':0x19,'Pkt':AttExecuteWriteResponse,'minSize':1, 'maxSize':1},
#   ## Server Initiated
#   'HANDLE_VALUE_NOTIFICATION'     :{'Opcode':0x1B,'Pkt':AttHandleValueNotification,'minSize':3, 'maxSize':ATT_MTU},
# + 'HANDLE_VALUE_INDICATION'       :{'Opcode':0x1D,'Pkt':AttHandleValueIndication,'minSize':3, 'maxSize':ATT_MTU},
# + 'HANDLE_VALUE_CONFIRMATION'     :{'Opcode':0x1E,'Pkt':AttHandleValueConfirmation,'minSize':1, 'maxSize':1},


###################### EVENTS ########################
class HciDisconnectionComplete(HciEvent):
    event_code = '\x05'
    class_descr = [ ['status',                  1, None],
                    ['conn_handle',             2, None],
                    ['reason',                  1, None]  ]

    @staticmethod
    def deserialize(data):
        return HciDisconnectionComplete(data[5], data[6:8], data[8])

class HciEncryptionChange(HciEvent):
    event_code = '\x08'
    class_descr = [ ['status',                  1, None],
                    ['conn_handle',             2, None],
                    ['enc_enabled',             1, None] ]

    @staticmethod
    def deserialize(data):
        return HciEncryptionChange(data[5], data[6:8], data[8])

class HciReadRemoteVersionInformationComplete(HciEvent):
    event_code = '\x0c'
    class_descr = [ ['status',                  1, None],
                    ['conn_handle',             2, None],
                    ['version',                 1, None],
                    ['manufacturer_name',       2, None],
                    ['sub_version',             2, None]  ]

    @staticmethod
    def deserialize(data):
        return HciReadRemoteVersionInformationComplete(
                data[5], data[6:8], data[8], data[9:11], data[11:13])

class HciCommandComplete(HciEvent):
    event_code = '\x0e'
    class_descr = [ ['num_hci_cmd_pkt',         1, None],
                    ['command_op_code',         2, None],
                    ['status',                  1, None],
                    ['return_params',      (0, 9), None] ] # TODO: Find actual max limit here

    @staticmethod
    def deserialize(data):
        return_params = ''
        if len(data) > 8:
            return_params = data[9:]
        return HciCommandComplete(data[5], data[6:8], data[8], return_params)

class HciCommandStatus(HciEvent):
    event_code = '\x0f'
    class_descr = [ ['status',                  1, None],
                    ['num_hci_cmd_pkt',         1, None],
                    ['command_op_code',         2, None] ]

    @staticmethod
    def deserialize(data):
        return HciCommandStatus(data[5], data[6], data[7:9])

class HciNumCompletePackets(HciEvent):
    event_code = '\x13'
    class_descr = [ ['num_handles',             1, None],
                    ['handles',            (1, 9), None] ] # TODO: Find actual max limit here

    @staticmethod
    def deserialize(data):
        handles = []
        for i in range(ord(data[5])):
            pos = i*4+5
            handles.append([data[pos:pos+1], data[pos+2:pos+3]])
        return HciNumCompletePackets(data[5], handles)

class HciEncryptionKeyRefreshComplete(HciEvent):
    event_code = '\x30'
    class_descr = [ ['status',                  1, None],
                    ['conn_handle',             2, None] ]

    @staticmethod
    def deserialize(data):
        return HciEncryptionKeyRefreshComplete(data[5], data[6:8])

class AdvReport(DynamicObject):
    class_descr = [ ['event_type',              1, None],
                    ['addr_type',               1, None],
                    ['addr',                    6, None],
                    ['length',                  1, None],
                    ['data',               (1, 9), None], # TODO: Find actual max size
                    ['rssi',                    1, None] ]
    adv_types  = {'\x00': 'ADV_IND',
                  '\x01': 'ADV_DIRECT_IND',
                  '\x02': 'ADV_SCAN_IND',
                  '\x03': 'ADV_NONCONN_IND',
                  '\x04': 'SCAN_RESP'}

    def __str__(self):
        adv_type = '%s' % self.event_type
        if self.adv_types.has_key(self.event_type):
            adv_type = self.adv_types[self.event_type]
        return '%15s [%r %r] Rssi %s %r' % (
                adv_type, self.addr_type, self.addr,
                ord(self.rssi), self.data)

    def __repr__(self):
        tmp = ', '.join(['%s: %r' % (i[0], i[1]) for i in self.fields])
        return '%s(%s)' % (self.__class__.__name__, tmp)

    @staticmethod
    def deserialize(data):
        length = ord(data[8])
        return AdvReport(data[0], data[1], data[2:8], data[8], data[9:9+length], data[9+length:])

class HciLeConnectionComplete(HciEvent):
    event_code = '\x3e'
    sub_event_code = '\x01'
    class_descr = [ ['status',                  1, None],
                    ['conn_handle',             2, None],
                    ['role',                    1, None],
                    ['peer_addr_type',          1, None],
                    ['peer_addr',               6, None],
                    ['conn_interval',           2, None],
                    ['conn_latency',            2, None],
                    ['supervision_timeout',     2, None],
                    ['master_clock_accuracy',   1, None] ]

    @staticmethod
    def deserialize(data):
        return HciLeConnectionComplete(data[6], data[7:9], data[9],
                data[10], data[11:17], data[17:19], data[19:21], data[21:23], data[23])

class HciLeAdvertisingReport(HciEvent):
    event_code = '\x3e'
    sub_event_code = '\x02'
    class_descr = [ ['num_reports',             1, None],
                    ['reports',            (1, 9), None] ] # TODO: Find actual max limit here

    @staticmethod
    def deserialize(data):
        reports = []
        pos = 0
        for i in range(ord(data[6])):
            length = 10 + ord(data[15+pos])
            reports.append(AdvReport.deserialize(data[7+pos:7+pos+length]))
            pos += length
        return HciLeAdvertisingReport(data[6], reports)

class HciLeConnectionUpdateComplete(HciEvent):
    event_code = '\x3e'
    sub_event_code = '\x03'
    class_descr = [ ['status',                  1, None],
                    ['conn_handle',             2, None],
                    ['conn_interval',           2, None],
                    ['conn_latency',            2, None],
                    ['supervision_timeout',     2, None] ]

    @staticmethod
    def deserialize(data):
        return HciLeConnectionUpdateComplete(data[6], data[7:9],
                data[9:11], data[11:13], data[13:15])

class HciLeReadRemoteUsedFeaturesComplete(HciEvent):
    event_code = '\x3e'
    sub_event_code = '\x04'
    class_descr = [ ['status',                  1, None],
                    ['conn_handle',             1, None],
                    ['le_features_ltlend',      1, None] ]

    @staticmethod
    def deserialize(data):
        return HciLeReadRemoteUsedFeaturesComplete(data[6], data[7:9], data[9:])

class HciLeLongTermKeyRequest(HciEvent):
    event_code = '\x3e'
    sub_event_code = '\x05'
    class_descr = [ ['conn_handle',             1, None],
                    ['rand_number_ltend',       8, None],
                    ['ediv',                    2, None] ]

    @staticmethod
    def deserialize(data):
        return HciLeLongTermKeyRequest(data[6:8], data[8:16], data[16:18])

