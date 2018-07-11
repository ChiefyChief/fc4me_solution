#!/usr/bin/python
from __future__ import print_function

import base64
import hashlib
import re
import requests

from unicorn import *
from unicorn.x86_const import *
from capstone import *


class Emulator:
    """ This class was borrowed from https://gist.github.com/mrschyte/1cf5ff55ff5bc3c5ac46ff588e58267d"""

    def __init__(self, base_address, memory_size, machine_code):
        # Initialize emulator in X86-32bit mode
        self.mu = Uc(UC_ARCH_X86, UC_MODE_32)
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)

        self.base_address = base_address
        self.memory_size = memory_size
        self.machine_code = machine_code

        # map the required memory for this emulation
        self.mu.mem_map(self.base_address, self.memory_size)

        # write machine code to be emulated to memory
        self.mu.mem_write(self.base_address, self.machine_code)

        # tracing all instructions with customized callback
        self.mu.hook_add(UC_HOOK_CODE, self.hook_code)

    def hook_code(self, uc, address, size, user_data):
        for i in self.md.disasm(bytes(self.mu.mem_read(address, size)), address):
            print(">>> 0x%x\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

    def before(self):
        # initialize machine registers
        self.mu.reg_write(UC_X86_REG_ESP, self.base_address + self.memory_size - (self.memory_size // 4))

    def after(self):
        print(">>> EDI = %x" %(self.mu.reg_read(UC_X86_REG_EDI)))
        with open("memory.dmp", "wb") as fp:
            fp.write(self.mu.mem_read(self.base_address, self.memory_size))

    def run(self):
        print("Emulating program.")
        self.before()

        try:
            # emulate code in infinite time & unlimited instructions
            self.mu.emu_start(self.base_address, self.base_address + len(self.machine_code))
        except UcError as e:
            print("ERROR: %s" % e)

        # now print out some registers
        print("Emulation done.")
        self.after()


def get_security_string():
    url = "http://fc4.me"

    req = requests.get(url)
    if req.status_code != 200:
        print("[!] Retrieved a {} from {}... exiting".format(req.status_code, url))
        exit(-1)
    
    # Attempting to parse out the srvstr from the main page.
    try:
        srvstr = re.findall("var srvstr='(.*?)'",req.text)[0]
    except IndexError:
        print("[!] Failed to find the srvstr... exiting")
        exit(-1)
    
    # This emulates the hexMD5 function from http://fc4.me/fc4.js
    return hashlib.md5("\x74\x72\x79\x68\x61\x72\x64\x65\x72" + srvstr).hexdigest()


def get_registration_code(solution):
    url = "http://fc4.me/fc4me.php"

    # Posting the data we found from get_security_string
    post_data = { "email": solution["email_address"],
                  "securitystring": solution["security_string"]
    }

    res = requests.post(url, data=post_data)
    if res.status_code != 200:
        print("[!] Retrieved a {} from {}... exiting".format(res.status_code, url))
        exit(-1)
    
    # Attempting to parse out the base64 string
    try:
        encoded_string = re.findall("<blockquote>(.*?)</blockquote>", res.text)[0]
    except IndexError:
        print("[!] Failed to find encoded blob... exiting")
        exit(-1)
    
    # Removes breaks in the html string and decodes the base64 
    base64_string = re.sub("<br/>", "", encoded_string)
    decoded_string = base64.b64decode(base64_string)

    # Attempting to parse out registration code
    try:
        solution["registration_code"] = re.findall("Registration Code: (\d+) ", decoded_string)[0]
    except IndexError:
        print("[!] Failed to find registration code... exiting")
        exit(-1)

    # Attempting to parse out registration key
    try:
        solution["registration_key"] = b"{}".format(re.findall("Now decode your CTP Secret Key and you are done! : (.*)", decoded_string)[0])
    except IndexError:
        print("[!] Failed to find registration key... exiting")
        exit(-1)
    
    return solution


def main(solution):
    solution["security_string"] = get_security_string()
    solution = get_registration_code(solution)

    # memory address where emulation starts
    # Todo: Extract out the final piece
    em = Emulator(0x00000, 1024 * 1024 * 2 , solution["registration_key"])
    em.run()
    
    print("-" * 100)
    print("\tEmail Address: {}".format(solution["email_address"]))
    print("\tSecurity String: {}".format(solution["security_string"]))
    print("\tRegistration Code: {}".format(solution["registration_code"]))
    print("-" * 100)


if __name__ == "__main__":
    # Mapping Python 2 and Python 3 inputs together
    try:
        input = raw_input
    except NameError:
        pass

    main({ "email_address" : "bhelms@gamil.com" })

