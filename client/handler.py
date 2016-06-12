import socket
import struct
import ctypes
import time

ALLOCATE_MEMORY = 4
READ_MEMORY = 1
WRITE_MEMORY = 2
RUN_CMD = 3


class sockaddr_recv(ctypes.Structure):
    _fields_ = [("sin_family", ctypes.c_ubyte),
                ("sin_port", ctypes.c_ushort)]

class in_addr(ctypes.Structure):
    _fields_ = [("s_addr", ctypes.c_char * 4)]

class sockaddr(ctypes.Structure):
    _fields_ = [("sin_family", ctypes.c_uint16),
                ("sin_port", ctypes.c_uint16),
                ("sin_addr", in_addr)]

class fd_set(ctypes.Structure):
    _fields_ = [('fds_bits', ctypes.c_long * 32)]

class timeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]

class pollfd(ctypes.Structure):
    _fields_ = [("fd", ctypes.c_uint),
                ("events", ctypes.c_short),
                ("revents", ctypes.c_short)]

class socklen_t(ctypes.Structure):
    _fields_ = [("len", ctypes.c_uint)]

class ioctl_arg_t(ctypes.Structure):
    _fields_ = [("len", ctypes.c_uint)]


class PointerStruct(ctypes.Structure):
    def map_memory_write(self, lp, rp, address):
        my_struct = self.__class__.from_buffer(bytearray(lp.readBytes(address, ctypes.sizeof(self.__class__))))
        for i in range(len(self._fields_)):
            if self._fields_[i][0].split(' ')[0] == 'C+1':
                field_len = getattr(my_struct, self._fields_[i+1][0])
                field_addr = getattr(my_struct, self._fields_[i][0])
                tmp_file = rp.allocate(field_len)
                rp.write(tmp_file, lp.readBytes(field_addr, field_len), field_len)
                setattr(my_struct, self._fields_[i][0], tmp_file)
            elif self._fields_[i][0].split(' ')[0] == 'R+1':
                rec_addr = getattr(my_struct, self._fields_[i][0])
                rec_len = getattr(my_struct, self._fields_[i+1][0])
                rec_struct = globals()[self._fields_[i][0].split(' ')[1]]
                rec_struct_ins = rec_struct()
                allocated_memory = rp.allocate(rec_len * ctypes.sizeof(rec_struct))
                for j in range(rec_len):
                    rec_ret_buffer = rec_struct_ins.map_memory_write(lp, rp, rec_addr + (j * ctypes.sizeof(rec_struct)))
                    rp.write(allocated_memory + (j * ctypes.sizeof(rec_struct)), rec_ret_buffer, ctypes.sizeof(rec_struct))
                setattr(my_struct, self._fields_[i][0], allocated_memory)

        buffer = ctypes.create_string_buffer(ctypes.sizeof(self.__class__))
        ctypes.memmove(ctypes.addressof(buffer), ctypes.addressof(my_struct), ctypes.sizeof(self.__class__))
        return buffer.raw
    def map_memory_read(self, lp, rp, r_address, l_address):
        r_struct = self.__class__.from_buffer(bytearray(rp.read(r_address, ctypes.sizeof(self.__class__))))
        l_struct = self.__class__.from_buffer(bytearray(lp.readBytes(l_address, ctypes.sizeof(self.__class__))))
        for i in range(len(self._fields_)):
            if self._fields_[i][0].split(' ')[0] == 'C+1':
                r_field_len = getattr(r_struct, self._fields_[i+1][0])
                r_field_addr = getattr(r_struct, self._fields_[i][0])
                lp.writeBytes(getattr(l_struct, self._fields_[i][0]),  rp.read(r_field_addr, r_field_len))
            elif self._fields_[i][0].split(' ')[0] == 'R+1':
                r_rec_addr = getattr(r_struct, self._fields_[i][0])
                l_rec_addr = getattr(l_struct, self._fields_[i][0])
                r_rec_len = getattr(r_struct, self._fields_[i+1][0])
                rec_struct = globals()[self._fields_[i][0].split(' ')[1]]
                rec_struct_ins = rec_struct()
                for j in range(r_rec_len):
                    rec_struct_ins.map_memory_read(lp, rp, r_rec_addr + (j * ctypes.sizeof(rec_struct)), l_rec_addr + (j * ctypes.sizeof(rec_struct)))

class iovec(PointerStruct):
    _fields_ = [('C+1 iov_base', ctypes.c_void_p),
                ('iov_len', ctypes.c_size_t)]

class msghdr(PointerStruct):
    _fields_ = [('C+1 msg_name', ctypes.c_void_p),
                ('msg_namelen', ctypes.c_size_t),
                ('R+1 iovec', ctypes.c_void_p),
                ('msg_iovlen', ctypes.c_size_t),
                ('C+1 msg_control', ctypes.c_void_p),
                ('msg_controllen', ctypes.c_size_t),
                ('msg_flags', ctypes.c_int)]


def get_ioctl_size(req):
    pass

class RemoteProcess(object):
    def __init__(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect(('10.0.0.3', 5001))

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

    def write(self, addr, buff,count):
        self.s.send(chr(WRITE_MEMORY))
        self.s.send(struct.pack('<I', addr))
        self.s.send(struct.pack('<I', count))
        self.s.send(buff)
        #return self.s.recv(count)
    def call(self, name, args):
        self.s.send(chr(RUN_CMD))
        self.s.send(name.ljust(30, chr(0)))
        self.s.send(struct.pack('<I', len(args)))
        for arg in args:
            self.s.send(struct.pack('<I', arg))
        return struct.unpack('<i',self.s.recv(4))[0]



class PesudoSyscallArg(object):
    def __init__(self, name, value):
        self.name = name
        self.value = value

class PesudoSyscall(object):
    def __init__(self, name, pid,raw_args):
        self.name = name
        self.arguments = []
        self.pid = pid
        for part in raw_args.split(' '):
            split_arg = part.split('=')
            self.arguments.append(PesudoSyscallArg(split_arg[0], split_arg[1]))

class LocalProcess(object):
    def __init__(self, syscall_handler):
        self.sh = syscall_handler

    def readBytes(self, pid, addr, length):
        mem = open('/proc/{0}/mem'.format(pid), 'rb')
        mem.seek(addr)
        return mem.read(length)

    def writeBytes(self, pid, addr, buffer):
        mem = open('/proc/{0}/mem'.format(pid), 'wb')
        mem.seek(addr)
        return mem.write(buffer)

    def handle_req(self, new_conn):
        pid = struct.unpack('<I', new_conn.recv(4))[0]
        name_size = struct.unpack('<I', new_conn.recv(4))[0]
        name = new_conn.recv(name_size)[4:]
        params_size = struct.unpack('<I', new_conn.recv(4))[0]
        params = new_conn.recv(params_size)
        ps = PesudoSyscall(name, pid, params)
        # Got Syscall
        do_intercept = self.enter(ps)
        new_conn.send(struct.pack('<I', int(do_intercept)))
        if do_intercept:
            # Intercept syscall
            got_return = struct.pack('<I', new_conn.recv(1))[0]
            if got_return:
                ret_value = self.exit(ps)
                new_conn.send(struct.pack('<I', ret_value))

    def enter(self, syscall):
        return self.sh.do_intercept(syscall)

    def exit(self, syscall):
        return self.sh.run_syscall(syscall, self)

    def socker_server(self):
        HOST = '10.0.0.2'          # Symbolic name meaning all available interfaces
        PORT = 42000              # Arbitrary non-privileged port
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(1)
        conn, addr = s.accept()
        print 'Connected by', addr
        while 1:
            self.handle_req(conn)
        conn.close()

class RSCSyscall(object):
    def __init__(self, handler):
        self.handler = handler

    def enter(self):
        pass

    def call_syscall(self, lp, rp, syscall):
        my_args = []
        for i in range(len(self.args)):
            type = self.args[i].split(' ')[0]
            if type in ['S', 'FD']:
                my_args.append(syscall.arguments[i].value)
            elif (type == 'C+1'):
                size = syscall.arguments[i+1].value
                addr = rp.allocate(size)
                rp.write(addr, lp.readBytes(syscall.arguments[i].value, size), size)
                my_args.append(addr)
            elif (type == '<'):
                #print self.args[i].split(' ')[1]
                size = ctypes.sizeof(globals()[self.args[i].split(' ')[1]])
                addr = rp.allocate(size)
                my_args.append(addr)
            elif (type == '<+1'):
                size = syscall.arguments[i+1].value
                addr = rp.allocate(size)
                my_args.append(addr)
            elif (type == '<+1R'):
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
                    len_size = ctypes.sizeof(globals()[self.args[i+1].split(' ')[1]])
                    lp.writeBytes(syscall.arguments[i].value, rp.read(my_args[i], struct.unpack('<I', rp.read(my_args[i+1], len_size))[0]))
                    pass
                elif (type == '<' or type == '<>'):
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

class SyscallHandler(object):
    def __init__(self):
        self.syscalls = []
        self.fds = []
        self.rp = RemoteProcess()
        self.fake_fds = []
        #self.libc = ctypes.CDLL('libc.so.6')

    def run_syscall(self, syscall, lp):
        for my_syscall in self.syscalls:
            if syscall.name == my_syscall.name:
                res = my_syscall.call_syscall(lp, self.rp, syscall)
                if my_syscall.name == 'open':
                    pass

                if my_syscall.isReturnFd:
                    self.fds.append(res)
                    #hself.libc.dup(2)
                if my_syscall.name == 'close':
                    self.fds.remove(syscall.arguments[0].value)
                return res


    def do_intercept(self, syscall):
        for my_syscall in self.syscalls:
            if my_syscall.name == syscall.name:
                if my_syscall.isArgFd:
                    if syscall.arguments[0].value in self.fds:
                        return True
                else:
                    return True
        return False

    def parse_syscall(self):
        syscalls_raw = ''
        with open('syscalls.txt', 'rb') as f:
            syscalls_raw = f.read()
        for syscall_line in syscalls_raw.split("\n"):
            rsc = RSCSyscall(handler=self)
            rsc.parse_line(syscall_line)
            self.syscalls.append(rsc)

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
    lp = LocalProcess(sh)
    lp.socker_server()
