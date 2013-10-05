import threading
import logging
import Queue

from lib import hci

class DeviceInterface(threading.Thread):
    def __init__(self, driver, pkt_handler=None):
        threading.Thread.__init__(self)
        self.log = logging.getLogger('dev_if')
        self.driver = driver
        self.pkt_handler = pkt_handler
        if self.pkt_handler == None:
            self.pkt_queue = Queue.Queue()
        self.keep_running = False
        self.start()

    def stop(self):
        self.keep_running = False

    def run(self):
        self.keep_running = True
        try:
            while self.keep_running:
                data = self.driver.read()
                if data == '': continue

                pkt = hci.event_factory(data)
                if self.pkt_handler == None:
                    self.pkt_queue.put(pkt)
                else:
                    self.pkt_handler(pkt)
        except:
            self.log.exception("Exception in read thread")
        finally:
            self.keep_running = False
            self.log.debug("Read thread finished")

        self.driver.close()

    def write_cmd(self, cmd):
        if not self.keep_running:
            return
        self.driver.write(cmd.serialize())
        while True:
            #if cmd.__class__ == hci.HciLeSetScanEnable:
            #    self.log.debug('cmd %s, no cmd response', cmd.__class__.__name__)
            #    return # TODO: Why do we get no CommandComplete or CommandStatus for this?
            #if cmd.__class__ == hci.HciLeCreateConnection:
            #    self.log.debug('cmd %s, no cmd response', cmd.__class__.__name__)
            #    return # TODO: Why do we get no CommandComplete or CommandStatus for this?

            pkt = self.wait_for_pkt()

            if pkt.__class__ == hci.HciCommandComplete:
                self.log.debug('cmd %s, pkt %r', cmd.__class__.__name__, pkt)
                return pkt
            if pkt.__class__ == hci.HciCommandStatus:
                self.log.debug('cmd %s, pkt %r', cmd.__class__.__name__, pkt)
                return pkt
            if pkt == None:
                self.log.info('cmd %s, timeout waiting for event', cmd.__class__.__name__)
                return pkt
            self.log.info('cmd %s, discarding unexpcted event %r', cmd.__class__.__name__, pkt)

    def wait_for_pkt(self, timeout = 1):
        try:
            return self.pkt_queue.get(True, timeout)
        except Queue.Empty, ex:
            return None
