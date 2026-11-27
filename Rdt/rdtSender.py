# Name: Gavin Burns (301634542), <partner> (<their number>)
"""The sending half of the protocol: Go-Back-N and Selective Repeat.

Stop-and-wait is Go-Back-N with a window of one, so build task 1 in a way that
task 2 can widen rather than replace.

Everything below the GIVEN line is written for you, including the argument
parser and the reading of the input file. Implement the class above it.
"""

import argparse
import socket
import sys
import threading
import time

import config
import segment
from segment import RDTSegment, RdtBuffer


UDP_READ_SIZE = 65_535
SOCKET_POLL_SECONDS = 0.005
MAX_RETRIES = 20

class Sender:
    """One direction of a connection, from the application into the channel.

    Two threads. The application thread calls send() and close(); the network
    thread you start in start() owns the socket, receives acknowledgements and
    runs the retransmission timers. They share the window, so decide which lock
    protects which variable and write it down here -- you will be asked.
    """

    def __init__(self, sock, channelAddr, protocol):
        """Set up the window and the timers.

        The window is a segment.RdtBuffer. Size it with config.WINDOW for now.
        In task 5 you replace that with segment.checkWindow(protocol), which
        returns the same number but refuses to run when the configured window is
        too wide for the sequence space; leave it as config.WINDOW until you
        have written windowLimit, because checkWindow asks windowLimit for the
        answer and cannot work before it exists.

        The buffer owns base, next and the segments themselves, so this class
        never touches slots directly: it calls putNext to admit a segment, get
        to fetch one for retransmission, markAcked when an ACK arrives, and
        setLimit when flow control or congestion control narrows the window.

        Beside it you need the receiver's advertised window and your timer
        deadlines, and one threading.Lock of your own to protect them. That lock
        is yours and is not the buffer's: RdtBuffer has its own Condition
        guarding slots, base and next, and never needs yours. Two primitives,
        two jobs -- a Condition where a thread has to wait for the buffer to
        change, a plain Lock where it only has to read and write your own
        fields without another thread doing so at the same time.

        The indices the buffer keeps never wrap; reduce them into the sequence
        space only when a segment is built, so exactly one place in your code
        has to think about wrapping.

        Timers are deadlines, not threads. Keep the time by which an ACK must
        arrive, and None when no timer is running: one deadline for the whole
        window under Go-Back-N, one per segment under Selective Repeat --
        RDTSegment already has a `deadline` attribute for exactly that.
        Cancelling a timer is then an assignment. The value is config.RTO_INIT
        and it does not change; measuring the path is the bonus.
        """
        self.sock = sock
        self.channelAddr = channelAddr
        self.protocol = protocol
        self.buffer = RdtBuffer(config.WINDOW)
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        # self.lock guard
        self.sent_next = 0
        self.deadline = None

        self.failed = None
        self.timeouts = 0
        self.fin_seq = None
        self.fin_acked = threading.Event()

    def start(self):
        """Start the network thread.

        That thread is one loop and nothing else. Give the socket a short
        timeout -- a few milliseconds -- so it wakes whether or not a datagram
        arrived, and each time round:

            * if a datagram arrived, validate it and act on it: an ACK marks
              its segment, may advance base, and clears that segment's
              deadline. Task 3 also reads rcvWin off it and calls setLimit.
            * then compare time.monotonic() against the deadlines you kept and
              retransmit whatever has expired, emitting traceTimeout first.

        Do the socket call outside the buffer's Condition, never inside it.
        """
        self.sock.settimeout(SOCKET_POLL_SECONDS)
        self.network_thread = threading.Thread(target=self._network_loop)
        self.network_thread.start()

    def send(self, payload):
        """Hand one segment's worth of data to the protocol.

        Blocks while the window is full, and returns True once the segment has
        been accepted for transmission, or False if the transfer has failed.

        One exception to blocking: if the receiver has advertised a window of
        zero and nothing is outstanding, no acknowledgement will ever arrive to
        reopen it, because there is nothing left to acknowledge. After
        config.PERSIST seconds, transmit anyway.
        """

        if self.failed: return False

        with self.buffer.cv:
            index = self.buffer.next
        seg = RDTSegment(seqNum=segment.mask(index), payload=payload)
        while not self.buffer.putNext(seg, timeout=config.PERSIST):
            if self.failed: return False
            with self.buffer.cv:
                stalled = self.buffer.limit == 0 and self.buffer.next == self.buffer.base
            if stalled:
                self.buffer.putNext(seg, force=True)
                break

        with self.lock:
            with self.buffer.cv:
                base = self.buffer.base
                win = self.buffer.limit
            self.sock.sendto(seg.pack(), self.channelAddr)
            self.sent_next = index + 1
            segment.traceSend(seg, base, self.sent_next, win)
            if self.deadline is None:
                self.deadline = time.monotonic() + config.RTO_INIT
        return True

    def _network_loop(self):
        while not self.stop_event.is_set():
            try:
                data, _ = self.sock.recvfrom(UDP_READ_SIZE)
            except socket.timeout:
                data = None
            except ConnectionResetError:
                data = None
            except OSError:
                if self.sock.fileno() == -1:
                    return
                raise

            ack = None
            if data is not None:
                reason = RDTSegment.validate(data)
                if reason is None:
                    ack = RDTSegment.unpack(data)
                elif reason == "checksum":
                    segment.traceCorrupt(int.from_bytes(data[:4], "big"))
                else:
                    segment.traceDrop(int.from_bytes(data[:4], "big"), reason)

            with self.lock:
                if (just_ack := ack is not None and ack.isAck):
                    self.buffer.setLimit(min(config.WINDOW, ack.rcvWin))
                    self.timeouts = 0
                with self.buffer.cv:
                    base = self.buffer.base
                    win = self.buffer.limit
                if ack is not None:
                    segment.traceRecv(ack, base, self.sent_next, win)
                    if just_ack and not ack.isFin:
                        # Map the wire ACK to an index in the transmitted window.
                        distance = segment.mask(ack.ackNum - segment.mask(base))
                        last = base + distance
                        if segment.mask(ack.ackNum) == ack.ackNum and last < self.sent_next:
                            for index in range(base, last + 1):
                                self.buffer.markAcked(index)
                            base = last + 1
                            self.deadline = None
                            if base < self.sent_next:
                                self.deadline = time.monotonic() + config.RTO_INIT
                    elif just_ack and ack.ackNum == self.fin_seq:
                        self.fin_acked.set()

                if self.deadline is None or time.monotonic() < self.deadline:
                    continue

                self.timeouts += 1
                if self.timeouts > MAX_RETRIES:
                    self.failed = "receiver stopped responding"
                    self.deadline = None
                    continue
                
                segment.traceTimeout(segment.mask(base), base, self.sent_next)
                for index in range(base, self.sent_next):
                    seg = self.buffer.get(index)
                    self.sock.sendto(seg.pack(), self.channelAddr)
                    segment.traceSend(seg, base, self.sent_next, win)
                self.deadline = time.monotonic() + config.RTO_INIT

    def close(self):
        """Wait for every segment to be acknowledged, then take the connection
        down: send a FIN, retransmit it if it is lost, and return True once it
        has been acknowledged. Return False if the connection could not be
        closed. Must return within a bounded time in either case.
        """

        # wait for every segment to be acked
        while True:
            with self.buffer.cv:
                if self.buffer.next == self.buffer.base:
                    break
                self.buffer.cv.wait(timeout=0.05)
            if self.failed:
                return self._finish(False)

        with self.buffer.cv:
            index = self.buffer.next
        fin = RDTSegment(seqNum=segment.mask(index), flags=segment.FLAG_FIN)
        with self.lock:
            self.fin_seq = fin.seqNum

        for _ in range(MAX_RETRIES):
            with self.buffer.cv:
                win = self.buffer.limit
            self.sock.sendto(fin.pack(), self.channelAddr)
            segment.traceSend(fin, index, index, win)
            if self.fin_acked.wait(timeout=config.RTO_INIT):
                return self._finish(True)
            segment.traceTimeout(fin.seqNum, index, index)

        self.failed = "FIN was never acknowledged"
        return self._finish(False)

    def _finish(self, ok):
        self.stop_event.set()
        self.network_thread.join(timeout=1.0)
        return ok


# ============================================================================
# GIVEN - do not modify anything below this line.
#
# Argument parsing, socket setup and the reading of the input file. The grading
# script invokes exactly these options, and none of this is what the project is
# teaching, so it is handed to you rather than assigned.
# ============================================================================

def parseArgs(argv):
    ap = argparse.ArgumentParser(description="CMPT 371 Project 3 - RDT sender")
    ap.add_argument("--channel", type=int, required=True,
                    help="the port channel.py printed for the sender side")
    ap.add_argument("--in", dest="inPath", required=True, help="file to send")
    ap.add_argument("--protocol", default="gbn", choices=("gbn", "sr"))
    ap.add_argument("--trace", default=None, help="write the event log here")
    return ap.parse_args(argv)


def openSocket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((config.HOST, 0))
    # A generous receive buffer: a burst of acknowledgements that arrives while
    # this program is busy elsewhere is otherwise dropped by the operating
    # system, and looks exactly like loss the channel never injected.
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    return sock


def main(argv=None):
    args = parseArgs(argv if argv is not None else sys.argv[1:])
    if (not isinstance(segment.SEED, int) or isinstance(segment.SEED, bool)
            or segment.SEED <= 0):
        sys.exit("set SEED at the top of segment.py to your Canvas group number")
    segment.traceOpen(args.trace)

    data = open(args.inPath, "rb").read()
    sock = openSocket()
    sender = Sender(sock, (config.HOST, args.channel), args.protocol)
    sender.start()
    for i in range(0, len(data), config.MSS):
        if not sender.send(data[i:i + config.MSS]):
            break
    try:
        ok = sender.close()
    except NotImplementedError:
        # Graceful teardown is task 4. Until it is written, give the last window
        # time to be acknowledged and then exit cleanly, so that the tasks
        # before it are still graded on the bytes that arrived rather than on
        # how the connection ended. This costs two seconds and nothing else.
        time.sleep(2.0)
        ok = True
    sock.close()
    if not ok:
        print("transfer failed: %s" % (getattr(sender, "failed", None) or "unknown"),
              file=sys.stderr)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
