import hci

def get_peer_db(dev, conn_handle, start_handle = '\x01\x00'):
    peer_db = []
    while True:
        dev.write_data(conn_handle, hci.AttFindInformationRequest(start_handle=start_handle))
        pkt = dev.wait_for_pkt()
        if not isinstance(pkt, hci.HciDataPkt):
            break
        att = pkt.payload_pkt.payload_pkt
        if not isinstance(att, hci.AttFindInformationResponse):
            if isinstance(att, hci.AttErrorResponse):
                pass
            break
        t = att.attributes[-1][0]
        t = ('%04x' % ((ord(t[1]) << 8) + ord(t[0]) + 1)).decode('hex')
        start_handle = t[1] + t[0]
        for attr in att.attributes:
            peer_db.append(attr[0])
    return peer_db

