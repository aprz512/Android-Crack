from unicorn import *
from androidemu.emulator import Emulator
from androidemu.java.helpers.native_method import native_method
from androidemu.utils import memory_helpers

from androidemu.java.java_classloader import JavaClassDef
from androidemu.java.java_method_def import java_method_def

import logging
import sys

# 使用 lv3 中提供的项目代码运行

base_address = 0xcbc66000

# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %((address - base_address), size))
    

logging.basicConfig(stream=sys.stdout,
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)7s %(name)34s | %(message)s")
logger = logging.getLogger(__name__)


@native_method
def __aeabi_memclr(mu, addr, size):
    print('__aeabi_memclr(%x,%d)' % (addr, size))
    mu.mem_write(addr, bytes(size))

@native_method
def __aeabi_memcpy(mu, dist, source, size):
    print ('__aeabi_memcpy(%x,%x,%d)' % (dist, source, size))
    data = mu.mem_read(source, size)
    mu.mem_write(dist, bytes(data))

@native_method
def sprintf(mu, buffer, format1, a1, a2):
    format1 = memory_helpers.read_utf8(mu, format1)
    result = format1 % (memory_helpers.read_utf8(mu, a1), a2)
    mu.mem_write(buffer, bytes((result + '\x00').encode('utf-8')))

@native_method
def check_port(mu):
    print("check port invoked...")
    pass

@native_method
def read_status(mu):
    print("read status invoked...")
    pass


class com_sec_udemo_MainActivity(metaclass=JavaClassDef, jvm_name="com/sec/udemo/MainActivity"):
    def __init__(self):
        pass
    
    @java_method_def(name='getSaltFromJava', 
                     signature='(Ljava/lang/String;)Ljava/lang/String;', 
                     native=False,
                     args_list=['jstring'])
    def getSaltFromJava(self, mu, str):
        return str.value.value + "salt.."
    
    @java_method_def(name='sign_lv4', 
                     signature='(Ljava/lang/String;)Ljava/lang/String;', 
                     native=True,
                     args_list=['jstring'])
    def sign_lv4(self, mu, str):
        pass

emulator = Emulator()
# emulator.mu.hook_add(UC_HOOK_CODE, hook_code, 0) 

emulator.modules.add_symbol_hook('__aeabi_memclr', emulator.hooker.write_function(__aeabi_memclr) + 1)
emulator.modules.add_symbol_hook('__aeabi_memcpy', emulator.hooker.write_function(__aeabi_memcpy) + 1)
emulator.modules.add_symbol_hook('sprintf', emulator.hooker.write_function(sprintf) + 1)
# emulator.modules.add_symbol_hook('_Z19CheckPort23946ByTcpv', emulator.hooker.write_function(check_port) + 1)
# emulator.modules.add_symbol_hook('_Z10readStatusv', emulator.hooker.write_function(read_status) + 1)


emulator.java_classloader.add_class(com_sec_udemo_MainActivity)

emulator.load_library('lib/libc.so', do_init=False)
libmod = emulator.load_library('lib/libnative-lib.so', do_init=False)

try:
    obj = com_sec_udemo_MainActivity()
    emulator.mu.mem_write(base_address + 0xAA02, b'\xAF\xF3\x00\x80')
    emulator.mu.mem_write(base_address + 0xAA06, b'\xAF\xF3\x00\x80')
    s = emulator.call_symbol(libmod, 'JNI_OnLoad', emulator.java_vm.address_ptr, 0)
    result = obj.sign_lv4(emulator, '123')
    print(result)

except UcError as e:
    print (e)
