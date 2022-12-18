import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
import select
import util.simsocket as simsocket
import struct
import socket
import util.bt_utils as bt_utils
import hashlib
import argparse
import pickle

"""
This is CS305 project skeleton code.
Please refer to the example files - example/dumpreceiver.py and example/dumpsender.py - to learn how to play with this skeleton.
"""

BUF_SIZE = 1400
CHUNK_DATA_SIZE = 512 * 1024
HEADER_LEN = struct.calcsize("HBBHHII")
MAX_PAYLOAD = 1024

config = None
expect_sending_chunk_hash = ""

expect_output_file = None
expect_received_chunk = dict()
expect_downloading_chunk_hash = ""

# Packet Format
# |2byte magic|1byte team |1byte type|
# |2byte  header len  |2byte pkt len |
# |      4byte  seq                  |
# |      4byte  ack                  |


def process_download(sock, chunkfile, outputfile):
    '''
    if DOWNLOAD is used, the peer will keep getting files until it is done
    '''
    global expect_output_file
    global expect_received_chunk
    global expect_downloading_chunk_hash

    expect_output_file = outputfile
    # 1. read chunk hash to be downloaded from chunk file
    download_hash = bytes()
    with open(chunkfile, "r") as cf:
        index, data_hash_str = cf.readline().strip().split(" ")
        expect_received_chunk[data_hash_str] = bytes()
        expect_downloading_chunk_hash = data_hash_str

        # hex_str to bytes
        data_hash = bytes.fromhex(data_hash_str)
        download_hash = download_hash + data_hash

    # 2. make a WHOHAS pkt
    whohas_header = struct.pack("HBBHHII", socket.htons(52305), 35, 0, socket.htons(HEADER_LEN),
                                socket.htons(HEADER_LEN + len(download_hash)), socket.htonl(0), socket.htonl(0))
    whohas_pkt = whohas_header + download_hash

    # 3. flooding WHOHAS pkt to all peers in peer list
    peer_list = config.peers
    for peer in peer_list:
        if int(peer[0]) != config.identity:
            sock.sendto(whohas_pkt, (peer[1], int(peer[2])))


def process_inbound_udp(sock):
    # Receive pkt
    global config, expect_sending_chunk_hash

    pkt, from_addr = sock.recvfrom(BUF_SIZE)
    Magic, Team, Type, headerLen, pktLen, Seq, Ack = struct.unpack("HBBHHII", pkt[:HEADER_LEN])
    data = pkt[HEADER_LEN:]
    print("SKELETON CODE CALLED, FILL this!")
    #   Type corresponding:
    #   0:WHOHAS  1:IHAVE  2:GET  3:DATA  4:ACK  5:DENIED
    if Type == 0:
        # received an WHOHAS pkt
        # see what chunk I have
        request_chunk_hash = data[:20]
        # bytes to hex_str
        request_chunk_hash_str = bytes.hex(request_chunk_hash)
        if request_chunk_hash_str in config.haschunks:
            # send back IHAVE pkt
            ihave_header = struct.pack("HBBHHII", socket.htons(52305), 35, 1, socket.htons(HEADER_LEN),
                                       socket.htons(HEADER_LEN + len(request_chunk_hash)), socket.htonl(0),
                                       socket.htonl(0))
            ihave_pkt = ihave_header + request_chunk_hash
            sock.sendto(ihave_pkt, from_addr)

    elif Type == 1:
        # reveived an IHAVE pkt
        # see what chunk the sender has
        get_chunk_hash = data[:20]
        # send back GET pkt
        get_header = struct.pack("HBBHHII", socket.htons(52305), 35, 2, socket.htons(HEADER_LEN),
                                 socket.htons(HEADER_LEN + len(get_chunk_hash)), socket.htonl(0), socket.htonl(0))
        get_pkt = get_header + get_chunk_hash
        sock.sendto(get_pkt, from_addr)

    elif Type == 2:
        # received a GET pkt
        chunk_data = config.haschunks[expect_sending_chunk_hash][:MAX_PAYLOAD]
        # send back data
        data_header = struct.pack("HBBHHII", socket.htons(52305), 35, 3, socket.htons(HEADER_LEN),
                                  socket.htons(HEADER_LEN), socket.htonl(1), 0)
        sock.sendto(data_header + chunk_data, from_addr)

    elif Type == 3:
        # received an DATA pkt
        expect_received_chunk[expect_downloading_chunk_hash] += data

        # send back ACK pkt
        ack_pkt = struct.pack("HBBHHII", socket.htons(52305), 35, 4, socket.htons(HEADER_LEN), socket.htons(HEADER_LEN),
                              0, Seq)
        sock.sendto(ack_pkt, from_addr)

        # see if finished
        if len(expect_received_chunk[expect_downloading_chunk_hash]) == CHUNK_DATA_SIZE:
            # finished downloading chunk data
            # dump the received chunk to file in dict form using pickle
            with open(expect_output_file, "wb") as wf:
                pickle.dump(expect_received_chunk, wf)

            # add to this peer's haschunk
            config.haschunks[expect_downloading_chunk_hash] \
                = expect_received_chunk[expect_downloading_chunk_hash]

            # you need to print "GOT" when finished downloading all chunks in a DOWNLOAD file
            print(f"GOT {expect_output_file}")

    elif Type == 4:
        # received an ACK pkt
        ack_num = socket.ntohl(Ack)
        if ack_num * MAX_PAYLOAD >= CHUNK_DATA_SIZE:
            # finished
            pass
        else:
            left = ack_num * MAX_PAYLOAD
            right = min((ack_num + 1) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
            # [left: right] is the next part of chunk
            next_data = config.haschunks[expect_sending_chunk_hash][left: right]
            # send next data
            data_header = struct.pack("HBBHHII", socket.htons(52305), 35, 3, socket.htons(HEADER_LEN),
                                      socket.htons(HEADER_LEN + len(next_data)), socket.htonl(ack_num + 1), 0)
            sock.sendto(data_header + next_data, from_addr)


def process_user_input(sock):
    command, chunkf, outf = input().split(' ')
    if command == 'DOWNLOAD':
        process_download(sock, chunkf, outf)
    else:
        pass


def peer_run(config):
    addr = (config.ip, config.port)
    sock = simsocket.SimSocket(config.identity, addr, verbose=config.verbose)

    try:
        while True:
            ready = select.select([sock, sys.stdin], [], [], 0.1)
            read_ready = ready[0]
            if len(read_ready) > 0:
                if sock in read_ready:
                    process_inbound_udp(sock)
                if sys.stdin in read_ready:
                    process_user_input(sock)
            else:
                # No pkt nor input arrives during this period 
                pass
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


if __name__ == '__main__':
    """
    -p: Peer list file, it will be in the form "*.map" like nodes.map.
    -c: Chunkfile, a dictionary dumped by pickle. It will be loaded automatically in bt_utils. The loaded dictionary has the form: {chunkhash: chunkdata}
    -m: The max number of peer that you can send chunk to concurrently. If more peers ask you for chunks, you should reply "DENIED"
    -i: ID, it is the index in nodes.map
    -v: verbose level for printing logs to stdout, 0 for no verbose, 1 for WARNING level, 2 for INFO, 3 for DEBUG.
    -t: pre-defined timeout. If it is not set, you should estimate timeout via RTT. If it is set, you should not change this time out.
        The timeout will be set when running test scripts. PLEASE do not change timeout if it set.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', type=str, help='<peerfile>     The list of all peers', default='nodes.map')
    parser.add_argument('-c', type=str, help='<chunkfile>    Pickle dumped dictionary {chunkhash: chunkdata}')
    parser.add_argument('-m', type=int, help='<maxconn>      Max # of concurrent sending')
    parser.add_argument('-i', type=int, help='<identity>     Which peer # am I?')
    parser.add_argument('-v', type=int, help='verbose level', default=0)
    parser.add_argument('-t', type=int, help="pre-defined timeout", default=0)
    args = parser.parse_args()

    config = bt_utils.BtConfig(args)
    peer_run(config)
