import socket
import struct
import ctypes
import select
from signal import SIGTRAP


class RSCSyscall(object):
    def __init__(self, handler):
        self.handler = handler

    def enter(self):
        pass

    def call_syscall(self, lp, rp, syscall):
        my_args = []

        if syscall.name == 'poll':
            i = 0
            size = syscall.arguments[i+1].value
            poll_type = globals()[self.args[i].split(' ')[1]]
            type_size = ctypes.sizeof(globals()[self.args[i].split(' ')[1]])
            size = size * type_size
            local_structs = []
            remote_structs = []
            for k in range(syscall.arguments[i+1].value):
                fd_struct = globals()[self.args[i].split(' ')[1]].from_buffer(bytearray(lp.readBytes(syscall.arguments[i].value + (k * type_size), size)))
                if fd_struct.fd in self.handler.fds:
                    remote_structs.append(fd_struct)
                else:
                    local_structs.append(fd_struct)
            if len(local_structs) > 0:
                r_size = (len(remote_structs) * type_size) + type_size
                l_size = (len(local_structs) * type_size) + type_size
                r_addr = rp.allocate(r_size)
                tmp_buff = ctypes.create_string_buffer(r_size)
                for k in range(len(remote_structs)):
                    ctypes.memmove(ctypes.addressof(tmp_buff) + (k * type_size), ctypes.addressof(remote_structs[k]), type_size)
                r_socket_fd = poll_type()
                r_socket_fd.fd = rp.remote_socket_fd
                r_socket_fd.events = 0x1
                ctypes.memmove(ctypes.addressof(tmp_buff) + ((k+1) * type_size), ctypes.addressof(r_socket_fd), type_size)
                rp.write(r_addr, tmp_buff.raw, r_size)
                rp.async_call('poll', [r_addr, len(remote_structs) + 1, syscall.arguments[2].value])

                l_addr = local_alloc_memory(lp, 0x2000)
                tmp_buff = ctypes.create_string_buffer(l_size)
                for k in range(len(local_structs)):
                    ctypes.memmove(ctypes.addressof(tmp_buff) + (k * type_size), ctypes.addressof(local_structs[k]), type_size)
                l_socket_fd = poll_type()
                l_socket_fd.fd = rp.s.fileno()
                l_socket_fd.events = 0x1
                ctypes.memmove(ctypes.addressof(tmp_buff) + ((k+1) * type_size), ctypes.addressof(l_socket_fd), type_size)
                lp.writeBytes(l_addr, tmp_buff.raw)
                res_l = local_call_syscall(lp, SYSCALL_POLL, [l_addr, len(local_structs)+1, syscall.arguments[2].value])
                rlist, wlist, elist = select.select([rp.s.fileno()], [], [], 0.001)
                copy_l = False
                copy_r = False
                if len(rlist) > 0:
                    copy_r = True
                else:
                    rp.s.send('0')
                    copy_l = True

                res_r = rp.read_res_return()

                structs_counter = 0

                for k in range(len(remote_structs)):
                    pollfd.from_buffer(bytearray(rp.read(r_addr + (k * type_size), type_size)))
                    if pollfd.fd != rp.remote_socket_fd:
                        lp.writeBytes(syscall.arguments[0].value + (structs_counter * type_size), rp.read(r_addr + (k * type_size), type_size))
                        structs_counter += 1
                    else:
                        copy_r = True

                for k in range(len(local_structs)):
                    pollfd.from_buffer(bytearray(lp.readBytes(l_addr + (k * type_size), type_size)))
                    if pollfd.fd != rp.s.fileno():
                        lp.writeBytes(syscall.arguments[0].value+ (structs_counter * type_size), lp.readBytes(l_addr + (k * type_size), type_size))
                        structs_counter += 1
                    else:
                        copy_l = True


                if copy_r:
                    #self.s.send('0')
                    return res_r
                else:
                    return res_l
                #print 123;
                #import time
                #time.sleep(10)
                #import time
                #time.sleep(10)
                #rp.s.send('1')


        for i in range(len(self.args)):
            type = self.args[i].split(' ')[0]
            if type in ['S', 'FD']:
                my_args.append(syscall.arguments[i].value)
            elif (type == 'C+1'):
                size = syscall.arguments[i+1].value
                addr = rp.allocate(size)
                rp.write(addr, lp.readBytes(syscall.arguments[i].value, size), size)
                my_args.append(addr)
            elif (type == 'C*1'):
                size = syscall.arguments[i+1].value
                type_size = ctypes.sizeof(globals()[self.args[i].split(' ')[1]])
                size = size * type_size
                addr = rp.allocate(size*type_size)
                rp.write(addr, lp.readBytes(syscall.arguments[i].value, size), size)
                my_args.append(addr)
            elif (type == '<'):
                #print self.args[i].split(' ')[1]
                if syscall.arguments[i].value == 0:
                    my_args.append(0)
                else:
                    size = ctypes.sizeof(globals()[self.args[i].split(' ')[1]])
                    addr = rp.allocate(size)
                    my_args.append(addr)
                    rp.write(addr, lp.readBytes(syscall.arguments[i].value, size), size)
            elif (type == '<+1'):
                size = syscall.arguments[i+1].value
                addr = rp.allocate(size)
                my_args.append(addr)
            elif (type == '<+1R'):
                if syscall.arguments[i].value == 0:
                    my_args.append(0)
                else:
                    len_size = ctypes.sizeof(globals()[self.args[i+1].split(' ')[1]])
                    size = struct.unpack('<I', lp.readBytes(syscall.arguments[i+1].value, len_size))[0]
                    buff = lp.readBytes(syscall.arguments[i].value, size)
                    addr = rp.allocate(size)
                    rp.write(addr, buff, size)
                    my_args.append(addr)
            elif (type == 'FDS'):
                if syscall.arguments[i].value != 0:
                    size = ctypes.sizeof(globals()[self.args[i].split(' ')[1]])
                    addr = rp.allocate(size)
                    rp.write(addr, lp.readBytes(syscall.arguments[i].value, size), size)
                    my_args.append(addr)
                else:
                    my_args.append(0)
            else:
                if syscall.arguments[i].value != 0:
                    if type == '<>':
                        type = self.args[i].split(' ')[1]
                        #print type
                    size = ctypes.sizeof(globals()[type])
                    addr = rp.allocate(size)
                    if (PointerStruct in globals()[type].__bases__ ):
                        msg = globals()[type]()
                        msg_raw = msg.map_memory_write(lp, rp, syscall.arguments[i].value)
                        rp.write(addr, msg_raw, size)
                    else:
                        rp.write(addr, lp.readBytes(syscall.arguments[i].value, size), size)
                    my_args.append(addr)
                else:
                    my_args.append(0)

        sys_res = rp.call(self.name, my_args)
        if sys_res >= 0:
            for i in range(len(self.args)):
                type = self.args[i].split(' ')[0]
                if (type == '<+1'):
                    lp.writeBytes(syscall.arguments[i].value, rp.read(my_args[i], my_args[i+1]))
                elif (type == '<+1R'):
                    if (syscall.arguments[i].value != 0):
                        len_size = ctypes.sizeof(globals()[self.args[i+1].split(' ')[1]])
                        lp.writeBytes(syscall.arguments[i].value, rp.read(my_args[i], struct.unpack('<I', rp.read(my_args[i+1], len_size))[0]))
                elif (type == 'C*1'):
                    size = syscall.arguments[i+1].value
                    type_size = ctypes.sizeof(globals()[self.args[i].split(' ')[1]])
                    size = size * type_size
                    lp.writeBytes(syscall.arguments[i].value, rp.read(my_args[i], size))
                elif (type == '<' or type == '<>'):
                    #if (syscall.arguments[i].value != 0):
                    if type == '<>':
                        type = self.args[i].split(' ')[1]
                        #print type
                    size = ctypes.sizeof(globals()[self.args[i].split(' ')[1]])
                    if (PointerStruct in globals()[self.args[i].split(' ')[1]].__bases__ ):
                        msg = globals()[self.args[i].split(' ')[1]]()
                        msg.map_memory_read(lp, rp, my_args[i], syscall.arguments[i].value)
                        #tst_msg = msghdr.from_buffer(bytearray(lp.readBytes(syscall.arguments[i].value, 56)))
                        #print 123
                    else:
                        #pass
                        lp.writeBytes(syscall.arguments[i].value, rp.read(my_args[i], size))
        return sys_res

    def parse_line(self, line):
        self.args = []
        args_line = line[line.find('(')+1:line.find(')')]
        raw_args = args_line.split(',')
        self.isArgFd = False
        self.isReturnFd = False
        for raw_arg in raw_args:
            if raw_arg[1:].split(' ')[0] == 'FD':
                self.isArgFd = True
            self.args.append(raw_arg[1:])
        self.name = line[line.rfind(' ', 0, line.find('('))+1: line.find('(')]
        if line.split(' ')[0] == 'FD':
            self.isReturnFd = True



ALLOCATE_MEMORY = 4
READ_MEMORY = 1
WRITE_MEMORY = 2
RUN_CMD = 3


class RemoteProcess(object):
    def __init__(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect(('127.0.0.1', 5001))
        self.remote_socket_fd = struct.unpack('<I', self.s.recv(4))[0]

    def allocate(self, size):
        self.s.send(chr(ALLOCATE_MEMORY))
        self.s.send(struct.pack('<I', size))
        addr = self.s.recv(4)
        addr = struct.unpack('<I', addr)
        return addr[0]

    def read(self, addr, count):
        self.s.send(chr(READ_MEMORY))
        self.s.send(struct.pack('<I', addr))
        self.s.send(struct.pack('<I', count))
        return self.s.recv(count)

    def write(self, addr, buff):
        count = len(buff)
        self.s.send(chr(WRITE_MEMORY))
        self.s.send(struct.pack('<I', addr))
        self.s.send(struct.pack('<I', count))
        self.s.send(buff)

    def async_call(self, name, args):
        self.s.send(chr(RUN_CMD))
        self.s.send(name.ljust(30, chr(0)))
        self.s.send(struct.pack('<I', len(args)))
        for arg in args:
            self.s.send(struct.pack('<I', arg))

    def read_res_return(self):
        res = struct.unpack('<i',self.s.recv(4))[0]
        errno = struct.unpack('<i',self.s.recv(4))[0]
        if res < 0:
            return errno * -1
        return res

    def call(self, name, args):
        self.s.send(chr(RUN_CMD))
        self.s.send(name.ljust(30, chr(0)))
        self.s.send(struct.pack('<I', len(args)))
        for arg in args:
            self.s.send(struct.pack('<I', arg))
        res = struct.unpack('<i',self.s.recv(4))[0]
        errno = struct.unpack('<i',self.s.recv(4))[0]
        if res < 0:
            return errno * -1
        return res

class LocalProcess(object):
    pass


def local_call_syscall(process, syscall_number, args):

    #syscall_opcode = "\xCD\x80"
    syscall_opcode = "\x0F\x05"
    push_opcode = "\x50"

    eip = process.getreg("rip")
    old_regs = process.getregs()
    old_instrs = process.readBytes(eip, len(syscall_opcode))
    process.writeBytes(eip, syscall_opcode)
    process.setreg("rax", syscall_number)

    arg_regs = ['rdi', 'rsi', 'rdx', 'r10', 'r8', 'r9']
    for i in range(len(args)):
        process.setreg(arg_regs[i], args[i])

    process.singleStep()
    process.waitSignals(SIGTRAP)

    res = process.getreg("rax")

    process.setregs(old_regs)
    process.setInstrPointer(eip)
    process.writeBytes(eip, old_instrs)

    return res


SYSCALL_DUP = 32
SYSCALL_POLL = 7
SYSCALL_MMAP = 9


def local_alloc_memory(lp, size):
    return local_call_syscall(lp, SYSCALL_MMAP, [0, 0x1000, 3, 0x22, -1, 0])

from linux_structs import SyscallArgStack, SyscallArgPointerNumber
import linux_structs
from ptrace.debugger import PtraceProcess

class LocalProcessWrapper(PtraceProcess):
    def read(self, addr, len):
        return self.readBytes(addr, len)

    def write(self, addr, buff):
        self.writeBytes(addr, buff)

    def allocate(self, len):
        return local_alloc_memory(self, len)

class RSCSyscall(object):
    def __init__(self, handler):
        self.handler = handler

    def enter(self):
        pass

    def call_syscall(self, lp, rp, syscall):
        my_args = []
        for arg in self.args:
            my_args.append(arg.write_value())
        sys_res = rp.call(syscall.name, my_args)
        #ret_args = []
        for arg in self.args:
            arg.read_value()
        return sys_res

    def parse_line(self, line, lp, rp, syscall):
        lp.__class__ = LocalProcessWrapper
        self.args = []
        args_line = line[line.find('(')+1:line.find(')')]
        raw_args = args_line.split(',')
        self.isArgFd = False
        self.isReturnFd = False
        i = 0
        for raw_arg in raw_args:
            splitted_raw_arg = raw_arg[1:].split(' ')
            operator = splitted_raw_arg[0]
            type = splitted_raw_arg[1]
            if operator == 'FD':
                self.isArgFd = True
            if raw_arg[1:].find('*') == -1:
                cls = SyscallArgStack
            else:
                if type in ['int', 'long']:
                    cls = SyscallArgPointerNumber
                else:
                    cls = getattr(linux_structs, type)

            self.args.append(cls(lp, rp, syscall, self, self.handler, type, i, operator))
            i += 1
        self.name = line[line.rfind(' ', 0, line.find('('))+1: line.find('(')]
        if line.split(' ')[0] == 'FD':
            self.isReturnFd = True



class SyscallHandler(object):
    def __init__(self):
        self.syscalls = []
        self._syscall_names = []
        self.fds = []
        self.rp = RemoteProcess()

    def run_syscall(self, syscall, lp):
        if syscall.name in self._syscall_names:
            with open('syscalls.txt', 'rb') as f:
                syscalls_raw = f.read()
            for syscall_line in syscalls_raw.split("\n"):
                if syscall_line.split(' ')[2][:-1] == syscall.name:
                    my_syscall = rsc = RSCSyscall(self)
                    rsc.parse_line(syscall_line, lp, self.rp, syscall)
                    res = my_syscall.call_syscall(lp, self.rp, syscall)
                    if my_syscall.name == 'open':
                        pass

                    if my_syscall.isReturnFd:
                        self.fds.append(res)
                        #hself.libc.dup(2)
                    if my_syscall.name == 'close':
                        self.fds.remove(syscall.arguments[0].value)
                    return res


    def do_intercept(self, lp, syscall):
        '''self.parse_syscall(lp, rp)
        for my_syscall in self.syscalls:
            if my_syscall.name == syscall.name:
                if my_syscall.isArgFd:
                    if syscall.arguments[0].value in self.fds:
                        return True
                else:
                    return True
        return False'''
        if syscall.name in self._syscall_names:
            syscalls_raw = ''
            with open('syscalls.txt', 'rb') as f:
                syscalls_raw = f.read()
            for syscall_line in syscalls_raw.split("\n"):
                if syscall_line.split(' ')[2][:-1] == syscall.name:
                    rsc = RSCSyscall(self)
                    rsc.parse_line(syscall_line, lp, self.rp, syscall)
                    if rsc.isArgFd:
                        if syscall.arguments[0].value in self.fds:
                            return True
                    else:
                        return True
            return False

    def parse_syscall(self):
        if len(self.syscalls) > 0:
            return
        syscalls_raw = ''
        with open('syscalls.txt', 'rb') as f:
            syscalls_raw = f.read()
        for syscall_line in syscalls_raw.split("\n"):
            self._syscall_names.append(syscall_line.split(' ')[2][:-1])

'''
if __name__ == '__main__':
    rp = RemoteProcess()
    path = '/tmp/123'
    alloc_addr = rp.allocate(len(path))
    print alloc_addr
    rp.write(alloc_addr, path, len(path))
    res = rp.read(alloc_addr, len(path))
    print res
    print rp.call('open', [alloc_addr, 0])
    rp.s.close()
    #print rp.call('socket', [2,1,0]
'''

if __name__ == '__main__':
    sh = SyscallHandler()
    sh.parse_syscall()
