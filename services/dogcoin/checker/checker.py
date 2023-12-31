#!/usr/bin/env python3
import time
import random
import string

import pwn

from ctf_gameserver import checkerlib

pwn.context.update(log_level="critical")

class TreasuryChecker(checkerlib.BaseChecker):
    PORT = 10056
    DEBUG = False

    MENU_STRINGS = {
            'welcome' : b"\n\nWelcome to the greatest coin of all times!!\n"
                        b"You got so many coins that you can't\n"
                        b"store them all in one vault, but also don't\n"
                        b"worry about keeping track of them all\n"
                        b"Let us worry about handling those while\n"
                        b"you focus on getting, moreee!\n"
                        b"\nChoose an action:\n"
                        b"-> add coin location\n"
                        b"-> view coin locations\n"
                        b"-> update coin location\n"
                        b"-> print logs\n"
                        b"-> quit\n"
                        b"  > ",
            'add_entry' : b"Name for the coin: ",
            'add_desc' : b'Description: ',
            'add_end' : b"Great! We'll safely store this information for you! :)\n\n",
            'menu' : b"Choose an action:\n"
                        b"-> add coin location\n"
                        b"-> view coin locations\n"
                        b"-> update coin location\n"
                        b"-> print logs\n"
                        b"-> quit\n"
                        b"  > ",
            'goodbye' : b"Bye!:)\n",
            'print_entry' : b"Logs are only for admins!\n"
                            b"Password: ",
            'print_end' : b"Nice try! :)\n\n",
            'update_entry' : b"TODO: not implemented yet.\n"
                             b"Push feature in next release.\n\n",
            'view_entry' : b'Location name: ',
            'view_desc' : b'\n-----------\nDescription: ',

            }

    def _generate_random_string(self, size):
        return ''.join(random.choice(string.ascii_letters) for x in range(size))

    def _get_key(self, flag):
        keys = checkerlib.load_state("keys")
        if not keys:
            keys = {}
        if flag in keys:
            return keys[flag]
        key = self._generate_random_string(60)
        while key in keys.values():
            key = self._generate_random_string(60)
        keys[flag] = key
        checkerlib.store_state("keys", keys)
        return key

    def _revoke_key(self, flag, key):
        keys = checkerlib.load_state("keys")
        if not keys:
            return
        if (flag in keys) and (key == keys[flag]):
            keys.pop(flag)
            checkerlib.store_state("keys", keys)


    def _add_treasure(self, key, value):
        try:
            if self.DEBUG:
                r = pwn.process("./coined")
            else:
                r = pwn.remote(self.ip, self.PORT)
        except pwn.pwnlib.exception.PwnlibException:
            return checkerlib.CheckResult.DOWN, "Failed to connect, Service down"
            #raise ConnectionRefusedError("Cannot connect to target")
        for i in range(12):
            # ascii art
            r.recvline()
        welcome_message = r.recvuntil(b"quit\n  > ")
        if welcome_message != self.MENU_STRINGS['welcome']:
            r.close()
            pwn.log.info("add_treasure: wrong welcome message")
            return 1
        pwn.log.info("add_treasure: checked welcome")
        r.sendline(b"add")

        resp = r.recvuntil(b"coin: ")
        if resp != self.MENU_STRINGS['add_entry']:
            r.close()
            pwn.log.info("add_treasure: wrong add_entry message")
            return 1
        r.sendline(bytes(key, "ascii"))
        pwn.log.info("add_treasure: checked add_entry")

        resp = r.recvuntil(b"Description: ")
        if resp != self.MENU_STRINGS['add_desc']:
            r.close()
            pwn.log.info("add_treasure: wrong add_desc message")
            return 1
        r.sendline(bytes(value,"ascii"))
        pwn.log.info("add_treasure: checked add_desc")

        first = r.recv(numb=1)
        if first == b'T':
            r.close()
            pwn.log.info("add_treasure: key already in use")
            return 2
        elif first == b'W':
            r.close()
            pwn.log.info("add_treasure: save failed")
            return 3

        pwn.log.info("add_treasure: checked T")

        resp = r.recvuntil(b"for you! :)\n\n")
        if first + resp != self.MENU_STRINGS['add_end']:
            r.close()
            pwn.log.info("add_treasure: wrong add_end message")
            return 1
        pwn.log.info("add_treasure: checked add_end")

        resp = r.recvuntil(b"quit\n  > ")
        if resp != self.MENU_STRINGS['menu']:
            r.close()
            pwn.log.info("add_treasure: wrong menu message")
            return 1
        r.sendline(b"quit")
        pwn.log.info("add_treasure: checked menu")

        resp = r.recvuntil(b"Bye!:)\n")
        if resp != self.MENU_STRINGS['goodbye']:
            r.close()
            pwn.log.info("add_treasure: wrong goodbye message")
            return 1
        pwn.log.info("add_treasure: checked goodbye")
        r.close()
        return 0

    def _view_treasure(self, key):
        try:
            if self.DEBUG:
                r = pwn.process("./treasury")
            else:
                r = pwn.remote(self.ip, self.PORT)
        except pwn.pwnlib.exception.PwnlibException:
            raise ConnectionRefusedError("Cannot connect to target")
        for i in range(12):
            # ascii art
            r.recvline()
        welcome_message = r.recvuntil(b"quit\n  > ")
        if welcome_message != self.MENU_STRINGS['welcome']:
            r.close()
            pwn.log.info("view_treasure: wrong welcome message")
            return None
        r.sendline(b"view")

        resp = r.recvuntil(b"Location name: ")
        if resp != self.MENU_STRINGS['view_entry']:
            r.close()
            pwn.log.info("view_treasure: wrong view_entry message")
            return None
        r.sendline(bytes(key, "ascii"))

        first = r.recv(numb=1)
        if first == b'N':
            r.close()
            pwn.log.info("view_treasure: no treasure found with this key")
            return None

        resp = r.recvuntil(bytes(key, "ascii"))
        if resp != key.encode():
            r.close()
            pwn.log.info("view_treasure: wrong key displayed")
            return None
        resp = r.recvuntil(b"Description: ")
        if resp != self.MENU_STRINGS['view_desc']:
            r.close()
            pwn.log.info("view_treasure: wrong view_desc message")
            return None
        desc = r.recvuntil(b"\n", drop=True)
        resp = r.recvuntil(b"\n")
        if resp != b'\n':
            r.close()
            pwn.log.info("view_treasure: missing newline")
            return None
        resp = r.recvuntil(b"quit\n  > ")
        if resp != self.MENU_STRINGS['menu']:
            r.close()
            pwn.log.info("view_treasure: wrong menu message")
            return None
        r.sendline(b"quit")
        resp = r.recvuntil(b"Bye!:)\n")
        if resp != self.MENU_STRINGS['goodbye']:
            r.close()
            pwn.log.info("view_treasure: wrong goodbye message")
            return None
        r.close()
        return desc

    def _update_location(self):
        try:
            if self.DEBUG:
                r = pwn.process("./coined")
            else:
                r = pwn.remote(self.ip, self.PORT)
        except pwn.pwnlib.exception.PwnlibException:
            raise ConnectionRefusedError("Cannot connect to target")
        for i in range(12):
            # ascii art
            r.recvline()
        welcome_message = r.recvuntil(b"quit\n  > ")
        if welcome_message != self.MENU_STRINGS['welcome']:
            r.close()
            pwn.log.info("view_treasure: wrong welcome message")
            return False
        r.sendline(b"update")
        resp = r.recvuntil(b"in next release.\n\n")
        if resp != self.MENU_STRINGS['update_entry']:
            r.close()
            pwn.log.info("view_treasure: wrong update_entry message")
            return False
        resp = r.recvuntil(b"quit\n  > ")
        if resp != self.MENU_STRINGS['menu']:
            r.close()
            pwn.log.info("view_treasure: wrong menu message")
            return False
        r.sendline(b"quit")

        resp = r.recvuntil(b"Bye!:)\n")
        if resp != self.MENU_STRINGS['goodbye']:
            r.close()
            pwn.log.info("view_treasure: wrong goodbye message")
            return False
        r.close()
        return True

    def _print_logs(self):
        try:
            if self.DEBUG:
                r = pwn.process("./treasury")
            else:
                r = pwn.remote(self.ip, self.PORT)
        except pwn.pwnlib.exception.PwnlibException:
            raise ConnectionRefusedError("Cannot connect to target")
        for i in range(12):
            # ascii art
            r.recvline()
        welcome_message = r.recvuntil(b"quit\n  > ")
        if welcome_message != self.MENU_STRINGS['welcome']:
            r.close()
            pwn.log.info("print_logs: wrong welcome message")
            return False
        r.sendline(b"print")
        resp = r.recvuntil(b"Password: ")
        if resp != self.MENU_STRINGS['print_entry']:
            r.close()
            pwn.log.info("print_logs: wrong print_entry message")
            return False
        pw = self._generate_random_string(8)
        r.sendline(bytes(pw,"ascii"))
        resp = r.recvuntil(b"Nice try! :)\n\n")
        if resp != self.MENU_STRINGS['print_end']:
            r.close()
            pwn.log.info("print_logs: wrong print_end message")
            return False

        resp = r.recvuntil(b"quit\n  > ")
        if resp != self.MENU_STRINGS['menu']:
            r.close()
            pwn.log.info("print_logs: wrong menu message")
            return False
        r.sendline(b"quit")
        resp = r.recvuntil(b"Bye!:)\n")
        if resp != self.MENU_STRINGS['goodbye']:
            r.close()
            pwn.log.info("print_logs: wrong goodbye message")
            return False
        r.close()
        return True

    def place_flag(self, tick):
        start = time.time()

        flag = checkerlib.get_flag(tick)
        key = self._get_key(flag)

        ret = self._add_treasure(key, flag)
        if ret == 0:
            pwn.log.info(f"Placed flag {flag}")
            pwn.log.info(f"Overall duration for place_flag: {int(time.time() - start)}s")
            #checkerlib.set_flagid(key) # the key can not be public, can be used to retrieve flags from the service
            return checkerlib.CheckResult.OK, ""
        if ret == 1:
            pwn.log.info("place_flag: add_treasure failed")
            pwn.log.info(f"Overall duration for place_flag: {int(time.time() - start)}s")
            return checkerlib.CheckResult.DOWN, "failed to place flag"
        if ret == 3:
            return checkerlib.CheckResult.FAULTY, "failed to add coin"

        while ret == 2:
            self._revoke_key(flag, key)
            key = self._get_key(flag)
            ret = self._add_treasure(key, flag)
            if ret == 0:
                pwn.log.info(f"Overall duration for place_flag: {int(time.time() - start)}s")
                return checkerlib.CheckResult.OK, ""
            if ret == 1:
                pwn.log.info("place_flag: add_treasure failed")
                pwn.log.info(f"Overall duration for place_flag: {int(time.time() - start)}s")
                return checkerlib.CheckResult.DOWN, "failed to add coin"

    def check_service(self):
        start = time.time()

        # add a location
        new_loc = self._generate_random_string(59)
        new_desc = self._generate_random_string(80)
        pwn.log.info(f"Trying to add location {new_loc}")
        ret = self._add_treasure(new_loc, new_desc)
        if ret == 1:
            pwn.log.info("check_service: add_treasure failed")
            pwn.log.info(f"Overall duration for check_service: {int(time.time() - start)}s")
            return checkerlib.CheckResult.DOWN, "failed to add coin"
        elif ret == 3:
            return checkerlib.CheckResult.FAULTY, "failed to add coin"


        while ret == 2:
            new_loc = self._generate_random_string(59)
            ret = self._add_treasure(new_loc, new_desc)
            if ret == 0:
                break
            if ret == 1:
                pwn.log.info("check_service: add_treasure failed")
                pwn.log.info(f"Overall duration for check_service: {int(time.time() - start)}s")
                return checkerlib.CheckResult.DOWN, "failed to add coin"
        pwn.log.info("check_service: add_treasure OK")

        # check the location
        pwn.log.info(f"Trying to access location {new_loc}")
        remote_value = self._view_treasure(new_loc)
        if remote_value is None:
            pwn.log.info("check_service: view_treasure failed")
            pwn.log.info(f"Overall duration for check_service: {int(time.time() - start)}s")
            return checkerlib.CheckResult.DOWN, "failed to view coin"
        if remote_value.decode() != new_desc:
            pwn.log.info("check_service: view_treasure return wrong value")
            pwn.log.info(f"Overall duration for check_service: {int(time.time() - start)}s")
            return checkerlib.CheckResult.FAULTY, "wrong value returned while viewing coin"
        pwn.log.info("check_service: view_treasure OK")

        # try to update the location
        res = self._update_location()
        if not res:
            pwn.log.info("check_service: update_location failed")
            pwn.log.info(f"Overall duration for check_service: {int(time.time() - start)}s")
            return checkerlib.CheckResult.FAULTY, "update coin failed"

        # "try" to access logs sometimes
        if random.choice([1,2]) == 2:
            pwn.log.info("Trying to access logs")
            res = self._print_logs()
            if not res:
                pwn.log.info("check_service: print_logs failed")
                pwn.log.info(f"Overall duration for check_service: {int(time.time() - start)}s")
                return checkerlib.CheckResult.FAULTY, "print_logs failed"
        else:
            pwn.log.info("Not trying to access logs")
        pwn.log.info("check_service: update_location OK")

        pwn.log.info(f"Overall duration for check_service: {int(time.time() - start)}s")
        return checkerlib.CheckResult.OK, ""

    def check_flag(self, tick):
        flag = checkerlib.get_flag(tick)
        key = self._get_key(flag)

        pwn.log.info(f"Checking flag {flag} at location {key}")

        stored_val = self._view_treasure(key)

        if not stored_val:
            pwn.log.info("check_flag: view_treasure failed")
            return checkerlib.CheckResult.FLAG_NOT_FOUND, "flag not found"
        if stored_val.decode() != flag:
            pwn.log.info("check_service: wrong flag")
            return checkerlib.CheckResult.FLAG_NOT_FOUND, "wrong flag found"

        return checkerlib.CheckResult.OK, ""


if __name__ == '__main__':
    checkerlib.run_check(TreasuryChecker)
