import time

# https://github.com/prekageo/rtmp-python
RTMP_ADDRESS = 'rtmp://192.168.1.1:9911/live/program_616_1080P'

HANDSHAKE_LENGTH = 1536
RTMP_HEAD = RTMP_ADDRESS[::-1][:RTMP_ADDRESS[::-1].index('/')][::-1]
RTMP_APP = RTMP_ADDRESS.split('/')[-2]
RTMP_STREAM = RTMP_ADDRESS.split('/')[-1]
TARGET_IP = RTMP_ADDRESS.split('//')[1].split(':')[0]
TARGET_PORT = int(RTMP_ADDRESS.split('//')[1].split(':')[1].split('/')[0])

class Packet(object):
    """
    A handshake packet.
    @ivar first: The first 4 bytes of the packet, represented as an unsigned
        long.
    @type first: 32bit unsigned int.
    @ivar second: The second 4 bytes of the packet, represented as an unsigned
        long.
    @type second: 32bit unsigned int.
    @ivar payload: A blob of data which makes up the rest of the packet. This
        must be C{HANDSHAKE_LENGTH} - 8 bytes in length.
    @type payload: C{str}
    @ivar timestamp: Timestamp that this packet was created (in milliseconds).
    @type timestamp: C{int}
    """

    first = None
    second = None
    payload = None
    timestamp = None

    def __init__(self, **kwargs):
        timestamp = kwargs.get('timestamp', None)

        if timestamp is None:
            kwargs['timestamp'] = int(time.time())

        self.__dict__.update(kwargs)

    def encode(self, buffer):
        """
        Encodes this packet to a stream.
        """
        buffer.write_ulong(self.first or 0)
        buffer.write_ulong(self.second or 0)

        buffer.write(self.payload)

    def decode(self, buffer):
        """
        Decodes this packet from a stream.
        """
        self.first = buffer.read_ulong()
        self.second = buffer.read_ulong()

        self.payload = buffer.read(HANDSHAKE_LENGTH - 8)

def header_decode(stream):
    """
    Reads a header from the incoming stream.
    A header can be of varying lengths and the properties that get updated
    depend on the length.
    @param stream: The byte stream to read the header from.
    @type stream: C{pyamf.util.BufferedByteStream}
    @return: The read header from the stream.
    @rtype: L{Header}
    """
    # read the size and channelId
    channelId = stream.read_uchar()
    bits = channelId >> 6
    channelId &= 0x3f

    if channelId == 0:
        channelId = stream.read_uchar() + 64

    if channelId == 1:
        channelId = stream.read_uchar() + 64 + (stream.read_uchar() << 8)

    header = Header(channelId)

    if bits == 3:
        return header

    header.timestamp = stream.read_24bit_uint()

    if bits < 2:
        header.bodyLength = stream.read_24bit_uint()
        header.datatype = stream.read_uchar()

    if bits < 1:
        # streamId is little endian
        stream.endian = '<'
        header.streamId = stream.read_ulong()
        stream.endian = '!'

        header.full = True

    if header.timestamp == 0xffffff:
        header.timestamp = stream.read_ulong()

    return header

def header_encode(stream, header, previous=None):
    """
    Encodes a RTMP header to C{stream}.
    We expect the stream to already be in network endian mode.
    The channel id can be encoded in up to 3 bytes. The first byte is special as
    it contains the size of the rest of the header as described in
    L{getHeaderSize}.
    0 >= channelId > 64: channelId
    64 >= channelId > 320: 0, channelId - 64
    320 >= channelId > 0xffff + 64: 1, channelId - 64 (written as 2 byte int)
    @param stream: The stream to write the encoded header.
    @type stream: L{util.BufferedByteStream}
    @param header: The L{Header} to encode.
    @param previous: The previous header (if any).
    """
    if previous is None:
        size = 0
    else:
        size = min_bytes_required(header, previous)

    channelId = header.channelId

    if channelId < 64:
        stream.write_uchar(size | channelId)
    elif channelId < 320:
        stream.write_uchar(size)
        stream.write_uchar(channelId - 64)
    else:
        channelId -= 64

        stream.write_uchar(size + 1)
        stream.write_uchar(channelId & 0xff)
        stream.write_uchar(channelId >> 0x08)

    if size == 0xc0:
        return

    if size <= 0x80:
        if header.timestamp >= 0xffffff:
            stream.write_24bit_uint(0xffffff)
        else:
            stream.write_24bit_uint(header.timestamp)

    if size <= 0x40:
        stream.write_24bit_uint(header.bodyLength)
        stream.write_uchar(header.datatype)

    if size == 0:
        stream.endian = '<'
        stream.write_ulong(header.streamId)
        stream.endian = '!'

    if size <= 0x80:
        if header.timestamp >= 0xffffff:
            stream.write_ulong(header.timestamp)

class Header(object):
    """
    An RTMP Header. Holds contextual information for an RTMP Channel.
    """

    __slots__ = ('streamId', 'datatype', 'timestamp', 'bodyLength',
        'channelId', 'full')

    def __init__(self, channelId, timestamp=-1, datatype=-1,
                 bodyLength=-1, streamId=-1, full=False):
        self.channelId = channelId
        self.timestamp = timestamp
        self.datatype = datatype
        self.bodyLength = bodyLength
        self.streamId = streamId
        self.full = full

    def __repr__(self):
        attrs = []

        for k in self.__slots__:
            v = getattr(self, k, None)

            if v == -1:
                v = None

            attrs.append('%s=%r' % (k, v))

        return '<%s.%s %s at 0x%x>' % (
            self.__class__.__module__,
            self.__class__.__name__,
            ' '.join(attrs),
            id(self))

def min_bytes_required(old, new):
    """
    Returns the number of bytes needed to de/encode the header based on the
    differences between the two.
    Both headers must be from the same channel.
    @type old: L{Header}
    @type new: L{Header}
    """
    if old is new:
        return 0xc0

    if old.channelId != new.channelId:
        class HeaderError(Exception):
            pass
        raise HeaderError('channelId mismatch on diff old=%r, new=%r' % (
            old, new))

    if old.streamId != new.streamId:
        return 0 # full header

    if old.datatype == new.datatype and old.bodyLength == new.bodyLength:
        if old.timestamp == new.timestamp:
            return 0xc0

        return 0x80

    return 0x40

import pyamf.amf0
import pyamf.util.pure
import socket
import logging

class FileDataTypeMixIn(pyamf.util.pure.DataTypeMixIn):
    """
    Provides a wrapper for a file object that enables reading and writing of raw
    data types for the file.
    """

    def __init__(self, fileobject):
        self.fileobject = fileobject
        pyamf.util.pure.DataTypeMixIn.__init__(self)

    def read(self, length):
        return self.fileobject.read(length)

    def write(self, data):
        if isinstance(data, str):
            data = data.encode('utf8')
        self.fileobject.write(data)

    def flush(self):
        self.fileobject.flush()

    def at_eof(self):
        return False
    def seek(self, offset, whence=0):
        return

class DataTypes:
    """ Represents an enumeration of the RTMP message datatypes. """
    NONE = -1
    SET_CHUNK_SIZE = 1
    USER_CONTROL = 4
    WINDOW_ACK_SIZE = 5
    SET_PEER_BANDWIDTH = 6
    SHARED_OBJECT = 19
    COMMAND = 20

class SOEventTypes:
    """ Represents an enumeration of the shared object event types. """
    USE = 1
    RELEASE = 2
    CHANGE = 4
    MESSAGE = 6
    CLEAR = 8
    DELETE = 9
    USE_SUCCESS = 11

class UserControlTypes:
    """ Represents an enumeration of the user control event types. """
    STREAM_BEGIN = 0
    STREAM_EOF = 1
    STREAM_DRY = 2
    SET_BUFFER_LENGTH = 3
    STREAM_IS_RECORDED = 4
    PING_REQUEST = 6
    PING_RESPONSE = 7

class RtmpReader:
    """ This class reads RTMP messages from a stream. """

    chunk_size = 128

    def __init__(self, stream):
        """
        Initialize the RTMP reader and set it to read from the specified stream.
        """
        self.stream = stream

    def __iter__(self):
        return self

    def __next__(self):
        """ Read one RTMP message from the stream and return it. """
        if self.stream.at_eof():
            raise StopIteration

        # Read the message into body_stream. The message may span a number of
        # chunks (each one with its own header).
        message_body = []
        msg_body_len = 0
        header = header_decode(self.stream)
        # FIXME: this should be really implemented inside header_decode
        if header.datatype == DataTypes.NONE:
            header = self.prv_header
        self.prv_header = header
        while True:
            read_bytes = min(header.bodyLength - msg_body_len, self.chunk_size)
            message_body.append(self.stream.read(read_bytes))
            msg_body_len += read_bytes
            if msg_body_len >= header.bodyLength:
                break
            next_header = header_decode(self.stream)
            # WORKAROUND: even though the RTMP specification states that the
            # extended timestamp field DOES NOT follow type 3 chunks, it seems
            # that Flash player 10.1.85.3 and Flash Media Server 3.0.2.217 send
            # and expect this field here.
            if header.timestamp >= 0x00ffffff:
                self.stream.read_ulong()
            assert next_header.streamId == -1, (header, next_header)
            assert next_header.datatype == -1, (header, next_header)
            assert next_header.timestamp == -1, (header, next_header)
            assert next_header.bodyLength == -1, (header, next_header)
        assert header.bodyLength == msg_body_len, (header, msg_body_len)
        # merge message_body from bytes to bytes
        body_stream = pyamf.util.BufferedByteStream(b''.join(message_body))

        # Decode the message based on the datatype present in the header
        ret = {'msg':header.datatype}
        if ret['msg'] == DataTypes.USER_CONTROL:
            ret['event_type'] = body_stream.read_ushort()
            ret['event_data'] = body_stream.read()
        elif ret['msg'] == DataTypes.WINDOW_ACK_SIZE:
            ret['window_ack_size'] = body_stream.read_ulong()
        elif ret['msg'] == DataTypes.SET_PEER_BANDWIDTH:
            ret['window_ack_size'] = body_stream.read_ulong()
            ret['limit_type'] = body_stream.read_uchar()
        elif ret['msg'] == DataTypes.SHARED_OBJECT:
            decoder = pyamf.amf0.Decoder(body_stream)
            obj_name = decoder.readString()
            curr_version = body_stream.read_ulong()
            flags = body_stream.read(8)

            # A shared object message may contain a number of events.
            events = []
            while not body_stream.at_eof():
                event = self.read_shared_object_event(body_stream, decoder)
                events.append(event)

            ret['obj_name'] = obj_name
            ret['curr_version'] = curr_version
            ret['flags'] = flags
            ret['events'] = events
        elif ret['msg'] == DataTypes.COMMAND:
            decoder = pyamf.amf0.Decoder(body_stream)
            commands = []
            while not body_stream.at_eof():
                commands.append(decoder.readElement())
            ret['command'] = commands
        #elif ret['msg'] == DataTypes.NONE:
        #    print 'WARNING: message with no datatype received.', header
        #    return self.next()
        elif ret['msg'] == DataTypes.SET_CHUNK_SIZE:
            ret['chunk_size'] = body_stream.read_ulong()
        elif ret['msg'] == 18:
            decoder = pyamf.amf0.Decoder(body_stream)
            commands = []
            while not body_stream.at_eof():
                commands.append(decoder.readElement())
            ret['command'] = commands
        elif ret['msg'] == 8:
            ret['event_type'] = body_stream.read_ushort()
            ret['event_data'] = body_stream.read()
        elif ret['msg'] == 9:
            ret['event_type'] = body_stream.read_ushort()
            ret['event_data'] = body_stream.read()
        else:
            assert False, (header, ret)

        logging.debug('recv %r', ret)
        return ret

    def read_shared_object_event(self, body_stream, decoder):
        """
        Helper method that reads one shared object event found inside a shared
        object RTMP message.
        """
        so_body_type = body_stream.read_uchar()
        so_body_size = body_stream.read_ulong()

        event = {'type':so_body_type}
        if event['type'] == SOEventTypes.USE:
            assert so_body_size == 0, so_body_size
            event['data'] = ''
        elif event['type'] == SOEventTypes.RELEASE:
            assert so_body_size == 0, so_body_size
            event['data'] = ''
        elif event['type'] == SOEventTypes.CHANGE:
            start_pos = body_stream.tell()
            changes = {}
            while body_stream.tell() < start_pos + so_body_size:
                attrib_name = decoder.readString()
                attrib_value = decoder.readElement()
                assert attrib_name not in changes, (attrib_name,list(changes.keys()))
                changes[attrib_name] = attrib_value
            assert body_stream.tell() == start_pos + so_body_size,\
                (body_stream.tell(),start_pos,so_body_size)
            event['data'] = changes
        elif event['type'] == SOEventTypes.MESSAGE:
            start_pos = body_stream.tell()
            msg_params = []
            while body_stream.tell() < start_pos + so_body_size:
                msg_params.append(decoder.readElement())
            assert body_stream.tell() == start_pos + so_body_size,\
                (body_stream.tell(),start_pos,so_body_size)
            event['data'] = msg_params
        elif event['type'] == SOEventTypes.CLEAR:
            assert so_body_size == 0, so_body_size
            event['data'] = ''
        elif event['type'] == SOEventTypes.DELETE:
            event['data'] = decoder.readString()
        elif event['type'] == SOEventTypes.USE_SUCCESS:
            assert so_body_size == 0, so_body_size
            event['data'] = ''
        else:
            assert False, event['type']

        return event

class RtmpWriter:
    """ This class writes RTMP messages into a stream. """

    chunk_size = 128

    def __init__(self, stream):
        """
        Initialize the RTMP writer and set it to write into the specified
        stream.
        """
        self.stream = stream

    def flush(self):
        """ Flush the underlying stream. """
        self.stream.flush()

    def write(self, message):
        logging.debug('send %r', message)
        """ Encode and write the specified message into the stream. """
        datatype = message['msg']
        body_stream = pyamf.util.BufferedByteStream()
        encoder = pyamf.amf0.Encoder(body_stream)

        if datatype == DataTypes.USER_CONTROL:
            body_stream.write_ushort(message['event_type'])
            body_stream.write(message['event_data'])
        elif datatype == DataTypes.WINDOW_ACK_SIZE:
            body_stream.write_ulong(message['window_ack_size'])
        elif datatype == DataTypes.SET_PEER_BANDWIDTH:
            body_stream.write_ulong(message['window_ack_size'])
            body_stream.write_uchar(message['limit_type'])
        elif datatype == DataTypes.COMMAND:
            for command in message['command']:
                encoder.writeElement(command)
        elif datatype == DataTypes.SHARED_OBJECT:
            encoder.serialiseString(message['obj_name'])
            body_stream.write_ulong(message['curr_version'])
            body_stream.write(message['flags'])

            for event in message['events']:
                self.write_shared_object_event(event, body_stream)
        else:
            assert False, message

        self.send_msg(datatype, body_stream.getvalue())

    def write_shared_object_event(self, event, body_stream):
        """
        Helper method that writes one shared object inside a shared object RTMP
        message.
        """

        inner_stream = pyamf.util.BufferedByteStream()
        encoder = pyamf.amf0.Encoder(inner_stream)

        event_type = event['type']
        if event_type == SOEventTypes.USE:
            assert event['data'] == '', event['data']
        elif event_type == SOEventTypes.CHANGE:
            for attrib_name in event['data']:
                attrib_value = event['data'][attrib_name]
                encoder.serialiseString(attrib_name)
                encoder.writeElement(attrib_value)
        elif event['type'] == SOEventTypes.CLEAR:
            assert event['data'] == '', event['data']
        elif event['type'] == SOEventTypes.USE_SUCCESS:
            assert event['data'] == '', event['data']
        else:
            assert False, event

        body_stream.write_uchar(event_type)
        body_stream.write_ulong(len(inner_stream))
        body_stream.write(inner_stream.getvalue())

    def send_msg(self, datatype, body):
        """
        Helper method that send the specified message into the stream. Takes
        care to prepend the necessary headers and split the message into
        appropriately sized chunks.
        """

        # Values that just work. :-)
        if datatype >= 1 and datatype <= 7:
            channel_id = 2
            stream_id = 0
        else:
            channel_id = 3
            stream_id = 0
        timestamp = 0

        header = Header(
            channelId=channel_id,
            streamId=stream_id,
            datatype=datatype,
            bodyLength=len(body),
            timestamp=timestamp)
        header_encode(self.stream, header)

        for i in range(0,len(body),self.chunk_size):
            chunk = body[i:i+self.chunk_size]
            self.stream.write(chunk)
            if i+self.chunk_size < len(body):
                header_encode(self.stream, header, header)

class FlashSharedObject:
    """
    This class represents a Flash Remote Shared Object. Its data are located
    inside the self.data dictionary.
    """

    def __init__(self, name):
        """
        Initialize a new Flash Remote SO with a given name and empty data.
        """
        self.name = name
        self.data = {}
        self.use_success = False

    def use(self, reader, writer):
        """
        Initialize usage of the SO by contacting the Flash Media Server. Any
        remote changes to the SO should be now propagated to the client.
        """
        self.use_success = False

        msg = {
            'msg': DataTypes.SHARED_OBJECT,
            'curr_version': 0,
            'flags': '\x00\x00\x00\x00\x00\x00\x00\x00',
            'events': [
                {
                    'data': '',
                    'type': SOEventTypes.USE
                }
            ],
            'obj_name': self.name
        }
        writer.write(msg)
        writer.flush()

    def handle_message(self, message):
        """
        Handle an incoming RTMP message. Check if it is of any relevance for the
        specific SO and process it, otherwise ignore it.
        """
        if message['msg'] == DataTypes.SHARED_OBJECT and \
            message['obj_name'] == self.name:
            events = message['events']

            if not self.use_success:
                assert events[0]['type'] == SOEventTypes.USE_SUCCESS, events[0]
                assert events[1]['type'] == SOEventTypes.CLEAR, events[1]
                events = events[2:]
                self.use_success = True

            self.handle_events(events)
            return True
        else:
            return False

    def handle_events(self, events):
        """ Handle SO events that target the specific SO. """
        for event in events:
            event_type = event['type']
            if event_type == SOEventTypes.CHANGE:
                for key in event['data']:
                    self.data[key] = event['data'][key]
                    self.on_change(key)
            elif event_type == SOEventTypes.DELETE:
                key = event['data']
                assert key in self.data, (key,list(self.data.keys()))
                del self.data[key]
                self.on_delete(key)
            elif event_type == SOEventTypes.MESSAGE:
                self.on_message(event['data'])
            else:
                assert False, event

    def on_change(self, key):
        pass

    def on_delete(self, key):
        pass

    def on_message(self, data):
        pass

class RtmpClient:
    """ Represents an RTMP client. """

    def __init__(self, ip, port, tc_url, page_url, swf_url, app):
        """ Initialize a new RTMP client. """
        self.ip = ip
        self.port = port
        self.tc_url = tc_url
        self.page_url = page_url
        self.swf_url = swf_url
        self.app = app
        self.shared_objects = []

    def handshake(self):
        """ Perform the handshake sequence with the server. """
        self.stream.write_uchar(3)
        c1 = Packet()
        c1.first = 0
        c1.second = 0
        c1.payload = 'x'*1528
        c1.encode(self.stream)
        self.stream.flush()

        self.stream.read_uchar()
        s1 = Packet()
        s1.decode(self.stream)

        c2 = Packet()
        c2.first = s1.first
        c2.second = s1.second
        c2.payload = s1.payload
        c2.encode(self.stream)
        self.stream.flush()

        s2 = Packet()
        s2.decode(self.stream)

    def connect_rtmp(self, connect_params):
        """ Initiate a NetConnection with a Flash Media Server. """
        msg = {
            'msg': DataTypes.COMMAND,
            'command':
            [
                'connect',
                1,
                {
                    'app': self.app,
                    'flashVer': 'WIN 10,0,32,18',
                    'fpad': False,
                    'tcUrl': self.tc_url,
                    'capabilities': 15,
                    'videoCodecs': 252,
                    'audioCodecs': 3575,
                    'videoFunction': 1,
                    'objectEncoding': 0
                }
            ]
        }
        msg['command'].extend(connect_params)
        self.writer.write(msg)
        self.writer.flush()

        while True:
            msg = next(self.reader)
            if self.handle_message_pre_connect(msg):
                break

    def call(self, proc_name, parameters = {}, trans_id = 0, proc_params = []):
        """ Runs remote procedure calls (RPC) at the receiving end. """
        msg = {
            'msg': DataTypes.COMMAND,
            'command':
            [
                proc_name,
                trans_id,
                parameters
            ]
        }
        for i in proc_params:
            msg['command'].append(i)
        self.writer.write(msg)
        self.writer.flush()

    def handle_message_pre_connect(self, msg):
        """ Handle messages arriving before the connection is established. """
        if msg['msg'] == DataTypes.COMMAND:
            assert msg['command'][0] == '_result', msg
            assert msg['command'][1] == 1, msg
            assert msg['command'][3]['code'] == \
                'NetConnection.Connect.Success', msg
            return True
        elif msg['msg'] == DataTypes.WINDOW_ACK_SIZE:
            pass
            # assert msg['window_ack_size'] == 2500000, msg
        elif msg['msg'] == DataTypes.SET_PEER_BANDWIDTH:
            pass
            # assert msg['window_ack_size'] == 2500000, msg
            assert msg['limit_type'] == 2, msg
        elif msg['msg'] == DataTypes.USER_CONTROL:
            assert msg['event_type'] == UserControlTypes.STREAM_BEGIN, msg
            assert msg['event_data'] == '\x00\x00\x00\x00', msg
        elif msg['msg'] == DataTypes.SET_CHUNK_SIZE:
            assert msg['chunk_size'] > 0 and msg['chunk_size'] <= 65536, msg
            self.reader.chunk_size = msg['chunk_size']
        else:
            assert False, msg

        return False

    def connect(self, connect_params):
        """ Connect to the server with the given connect parameters. """
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.ip, self.port))
        self.file = self.socket.makefile(mode='rwb')
        self.stream = FileDataTypeMixIn(self.file)

        self.handshake()

        self.reader = RtmpReader(self.stream)
        self.writer = RtmpWriter(self.stream)

        self.connect_rtmp(connect_params)

    def shared_object_use(self, so):
        """ Use a shared object and add it to the managed list of SOs. """
        if so in self.shared_objects:
            return
        so.use(self.reader, self.writer)
        self.shared_objects.append(so)

    def handle_messages(self):
        """ Start the message handling loop. """
        while True:
            msg = next(self.reader)

            handled = self.handle_simple_message(msg)

            if handled:
                continue

            for so in self.shared_objects:
                if so.handle_message(msg):
                    handled = True
                    break
            if not handled:
                assert False, msg

    def handle_simple_message(self, msg):
        """ Handle simple messages, e.g. ping requests. """
        if msg['msg'] == DataTypes.USER_CONTROL and msg['event_type'] == \
                UserControlTypes.PING_REQUEST:
            resp = {
                'msg':DataTypes.USER_CONTROL,
                'event_type':UserControlTypes.PING_RESPONSE,
                'event_data':msg['event_data'],
            }
            self.writer.write(resp)
            self.writer.flush()
            return True

        return False

class SO(FlashSharedObject):
    """ Represents a sample shared object. """

    def on_change(self, key):
        """ Handle change events for the specific shared object. """
        print('%s.sparam = "%s"' % (self.name, self.data['sparam']))


def main():
    """
    Start the client, connect to 127.0.0.1:80 and use 2 remote flash shared
    objects.
    """

    client = RtmpClient(TARGET_IP, TARGET_PORT, RTMP_HEAD, '', '', RTMP_APP)
    client.connect([])
    # Window acknowledgement size: 5000000
    client.writer.write({'msg': DataTypes.WINDOW_ACK_SIZE, 'window_ack_size': 5000000})
    client.writer.flush()
    # Event type: Set Buffer Length (3)
    client.writer.write({'msg': DataTypes.USER_CONTROL, 'event_type': 3, 'event_data': '\x00\x00\x00\x00\x00\x00\x00\x00'})
    client.writer.flush()
    
    # createStream
    client.call('createStream', None, 2)

    # FCSubscribe with arg '7tch_480P'
    client.call('FCSubscribe', None, 3, proc_params=[RTMP_STREAM])


    # get _result
    msg = next(client.reader)
    assert msg['msg'] == DataTypes.COMMAND, msg
    assert msg['command'][0] == '_result', msg
    assert msg['command'][1] == 2, msg
    stream_id = msg['command'][3]
    # play 7tch_480P
    client.call('play', None, 5, proc_params=[RTMP_STREAM, -1000])
    # Set Buffer Length 1,100ms
    client.writer.write({'msg': DataTypes.USER_CONTROL, 'event_type': 3, 'event_data': '\x00\x00\x00\x00\x00\x00\x00\x00'})
    
    # get streambegin1
    msg = next(client.reader)
    assert msg['msg'] == DataTypes.USER_CONTROL, msg
    assert msg['event_type'] == UserControlTypes.STREAM_BEGIN, msg
    assert msg['event_data'] == b'\x00\x00\x00\x01', msg
    # get onstatus
    msg = next(client.reader)
    assert msg['msg'] == DataTypes.COMMAND, msg
    assert msg['command'][0] == 'onStatus', msg
    assert msg['command'][1] == 0, msg
    assert msg['command'][3]['code'] == 'NetStream.Play.Start', msg
    # get RtmpSampleAccess
    msg = next(client.reader)
    assert msg['msg'] == 18, msg
    # get onMetaData
    msg = next(client.reader)
    # print(msg)
    # client.handle_messages()
    print(1)
    while True:
        msg = next(client.reader)
        #print(msg)
        #if msg['msg'] == 20:
        #    break
    

import threading
if __name__ == '__main__':
    # multi thread
    thread_count = 30
    count = 0
    while True:
        count += 1
        if count > thread_count:
            break
        t = threading.Thread(target=main)
        t.start()
