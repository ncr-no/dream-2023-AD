#!/usr/bin/env python3
from ctf_gameserver import checkerlib
import pwn
import string
from gmpy2 import *
import random
import logging

class TemplateChecker(checkerlib.BaseChecker):
    # pwn.context.log_level = 'debug'
    PORT = 10058
    p = mpz("008cc0e9d5af02471e2ac849c203fd4f7926a01d6d38237ea7746b876c01984d8335705e429cd68ea00d7f68f4afe048c48c4d8438f6ebb9b0d961ae2bfd1311319ebeabbd9aa03965ec43b652cbdfbda67ea2aadf5f11cc86cda4a69fdb30cb6cd354cf0ab94939e61aac4be4233b483c7e09e835c338fd149209d6c893d9f4c7", 16)
    q = mpz("008937dd8af446507ec33f3a97af6c7477f8b14b9d", 16)
    q_str_b10 = '783377575687639477584301733381424367862656617373'
    g = mpz("46466077b24e86560b15390992c7beaa9b7e7ddeaece76f929f6d41e2b3ab2937744745330eac965a746e125f52a70cc7dcdb067d372bf9643405ca49300e9865c47fd29f756c6c7b34497173878b911de43cacd96257956befa02bcd6a5060093099c9d253b50839b0db14080461e53f9ef697ff4fc65b18a4d41c03c64fa57", 16)
    help_menu = ['help', 'register', 'login', 'exit', 'users', 'pubkey']

    def _generate_random_string(self, size):
        return ''.join(random.choice(string.ascii_uppercase) for x in range(size))
    def _generate_key_pair(self):
        sec = random.randint(2, int(self.q_str_b10))
        sec = mpz(str(sec), 10)
        pub = powmod(self.g, sec, self.p)
        return {'pub': pub.digits(16), 'sec': sec.digits(16)}
    def _connect_to_server(self):
        try:
            t = pwn.remote(self.ip, self.PORT, timeout=32)
            return t
        except pwn.pwnlib.exception.PwnlibException:
            logging.error(f'_connect_to_server: connection fails')
            return None
    def _register_user(self, profile):
        name = 'DSA' + self._generate_random_string(20)
        key = self._generate_key_pair()
        
        t = self._connect_to_server()
        if t == None:
            logging.error(f'_register_user: server is unreachable')
            return None

        t.sendlineafter(b'$ ', b'register')
        t.sendlineafter(b'username: ', name.encode())
        t.sendlineafter(b'key: ', key['pub'].encode())
        t.sendlineafter(b'profile: ', profile.encode())
        t.sendlineafter(b'$ ', b'exit')
        t.close()
        # key pair is returned
        return {'name': name, 'key': key, 'profile': profile}
    def _login_user(self, user):
        t = self._connect_to_server()
        if t == None:
            logging.error(f'_login_user: server is unreachable')
            return False, 'no connection'
        t.sendlineafter(b'$ ', b'login')
        username = user['name']
        t.sendlineafter(b'username: ', username.encode())
        t.recvuntil(b'challenge: ')
        chall = t.recvline().strip()
        mchall = mpz(chall, 16)
        x_sec = user['key']['sec']
        x = mpz(x_sec, 16)
        # k = random.randint(2, q_str_b10)
        # tame the randomness
        k = random.randint(128, 8192)
        k_inv = powmod(k, -1, self.q)
        r = powmod(self.g, k, self.p)
        r = t_mod(r, self.q)
        tmp = mul(x, r)
        tmp = add(mchall, tmp)
        s = mul(k_inv, tmp)
        s = t_mod(s, self.q)
        r_s = hex(int(r))[2:] + ',' + hex(int(s))[2:]
        t.sendlineafter(b'R,S: ', r_s.encode())
        recv_profile = t.recvline().strip()
        t.close()
        logging.info(f'_login_user: verdict for user `{username}`: `{recv_profile.decode()}`')
        if b'invalid signature' == recv_profile:
            logging.info(f'_login_user: invalid signature for user `{username}`')
            return False, 'invalid signature'
        elif b'profile is' in recv_profile:
            profile = recv_profile.split(b' ')[-1].decode()
            logging.info(f'_login_user: received profile for user `{username}`: `{profile}`')
            return True, profile
        else:
            logging.error(f'_login_user: no profile found for user `{username}`: ')
            return False, 'no profile found'

    def place_flag(self, tick):
        try:
            flag = checkerlib.get_flag(tick)
            user = self._register_user(flag)
            if user == None:
                logging.error(f'place_flag: creating user fail')
                return checkerlib.CheckResult.DOWN, "failed to place flag, could not create user"
            logging.info(f'place_flag: `{user["name"]}` at `{tick}` with `{user["profile"]}`')
            checkerlib.store_state('flag_' + str(tick), user)
            return checkerlib.CheckResult.OK, ""
        except ValueError:
            return checkerlib.CheckResult.FAULTY, "place flag failure"

    def check_service(self):
        try:
            t = self._connect_to_server()
            if t == None:
                logging.error(f'check_service: server is unreachable')
                return checkerlib.CheckResult.DOWN, "server is unreachable"
            # check help
            t.sendlineafter(b'$ ', b'help')
            recv_help_menu = t.recvuntil(b'of a user').decode()
            for x in self.help_menu:
                if x not in recv_help_menu:
                    logging.error(f'check_service: command `{x}` is gone')
                    return checkerlib.CheckResult.FAULTY, f"check_service failure, command {x}"
            # check users
            t.sendlineafter(b'$ ', b'users')
            last_user = None
            recvdata = t.recv().decode().split('\n')
            for uu in recvdata:
                if uu.startswith('|DSA') == True:
                    last_user = uu[1:-1]
                    break
            if last_user == None:
                logging.error(f'check_service: no user starting with DSA has been found')
                return checkerlib.CheckResult.FAULTY, "check_service no user starting with DSA has been found"
            # check pubkey on the `last_user`
            t.sendline(b'pubkey')
            t.sendlineafter(b'username: ', last_user.encode())
            pubkey = t.recvline().strip().decode()
            t.sendlineafter(b'$ ', b'exit')
            t.close()
            if pubkey == 'user not exist':
                logging.error(f'check_service: user `{last_user}` does not own a public key')
                return checkerlib.CheckResult.FAULTY, f"check_service {last_user} does not own a public key"
            elif 'public key' in pubkey:
                pubkey = pubkey.split(' ')[-1].strip()
                if pubkey == '':
                    logging.error(f'check_service: user `{last_user}` does not own a public key')
                    return checkerlib.CheckResult.FAULTY
                logging.info(f'check_service: user `{last_user}` owns public key `{pubkey}`')
                return checkerlib.CheckResult.OK, ""
        except ValueError:
            return checkerlib.CheckResult.FAULTY, "check_service failure"

    def check_flag(self, tick):
        try:
            user = checkerlib.load_state('flag_' + str(tick))
            if not user:
                logging.error(f'check_flag: user at `{tick}` not found from state')
                return checkerlib.CheckResult.FLAG_NOT_FOUND, f"user at {tick} not found from state"
            verdict, msg = self._login_user(user)
            if verdict == False and msg == 'no connection':
                logging.error(f'check_flag: server is unreachable')
                return checkerlib.CheckResult.DOWN, "check_flag: server is unreachable"

            username = user['name']
            profile = user['profile']
            if verdict == True:
                if msg != profile:
                    logging.error(f'check_flag: user `{username}` got wrong flag\ncorrect: `{profile}`\nincorrect: `{msg}`')
                    return checkerlib.CheckResult.FLAG_NOT_FOUND, "check_flag: got wrong flag"
                else:
                    return checkerlib.CheckResult.OK, ""
            else:
                logging.info(f'check_flag: user `{username}` `{msg}`')
                return checkerlib.CheckResult.FLAG_NOT_FOUND, f"check_flag failure: user {username} {msg}"
        except ValueError:
            return checkerlib.CheckResult.FAULTY, "check_flag failure"

if __name__ == '__main__':
    checkerlib.run_check(TemplateChecker)
