import struct
import ctypes
from abc import abstractmethod


class sockaddr_recv(ctypes.Structure):
    _fields_ = [("sin_family", ctypes.c_ubyte),
                ("sin_port", ctypes.c_ushort)]





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


def get_ioctl_size(req):
    pass


class SyscallArg(object):
    def __init__(self, lp, rp, syscall, rsc, handler, arg_type, index, operator):
        self.lp = lp
        self.rp = rp
        self.syscall = syscall
        self.rsc = rsc
        self.handler = handler
        self.arg_type = arg_type
        self.index = index
        self.operator = operator

    @abstractmethod
    def write_value(self):
        pass

    def read_value(self):
        pass

class SyscallArgStack(SyscallArg):
    def write_value(self):
        return self.syscall.arguments[self.index].value

'''
class NestedStructField(object):
    def __init__(self, lp, rp, handler, operator, index, parent_struct):
        self.lp = lp
        self.rp = rp
        self.handler = handler
        self.operator = operator
        self.index = index
        self.parent_struct = parent_struct


class NestedStructFieldPointer(NestedStructField):
    def to_remote(self, local_address):
        pass



class NestedStruct(object):
    def __init__(self, lp, rp, handler):
        self.lp = lp
        self.rp = rp
        self.handler = handler
        self.sr = StructReader()
        self.values = []

    def struct_to_remote(self, local_address):
        local_struct_size = self.sr.get_size(self._fields_, 'local')
        local_struct_buffer = self.lp.readBytes(local_address, local_struct_size)
        local_struct = self.sr.from_buffer(self._fields_, local_struct_buffer, 'local')


        remote_struct_size = self.sr.get_size(self._fields_, 'remote')
        remote_struct_values = []
        r_addr = self.rp.allocate(remote_struct_size)

        return r_addr

'''


class NestedStruct(object):
    def __init__(self, lp, rp, index, operator, fields, nextarg):
        self.lp = lp
        self.rp = rp
        self.index = index
        self.operator = operator
        self._fields_ = fields
        self.nextarg = nextarg

    def addr_to_buffer(self, direction, source_addr):
        sr = StructReader()
        s_size = sr.get_size(self._fields_, direction)
        if direction == 'local':
            o_direction = 'remote'
            sp = self.lp
            rp = self.rp
        else:
            o_direction = 'local'
            sp = self.rp
            rp = self.lp


        structs_count = 1
        if '*1' in self.operator:
            structs_count = self.nextarg
        all_buffer = ''
        for j in range(structs_count):
            s_buffer = sp.read(source_addr + (j * s_size), s_size)
            s_values = sr.from_buffer(self._fields_, s_buffer, direction)
            r_values = []
            for i in range(len(s_values)):
                if self._fields_[i][2] == 'S':
                    r_values.append(s_values[i])
                elif self._fields_[i][2] == 'C+1':
                    if s_values[i+1]>0:
                        buff = sp.read(s_values[i], s_values[i+1])
                        addr = rp.allocate(len(buff))
                        rp.write(addr, buff)
                        r_values.append(addr)
                    else:
                        r_values.append(0)
                elif self._fields_[i][2] == 'C*1':
                    new_fields = getattr(globals()[self._fields_[i][0]], '_fields_')
                    ns = NestedStruct(self.lp, self.rp, 0, self._fields_[i][2], new_fields, s_values[i+1])
                    new_buff = ns.addr_to_buffer(direction, s_values[i])
                    #if direction == 'local':
                    r_addr = rp.allocate(len(all_buffer))
                    rp.write(r_addr, new_buff)
                    r_values.append(r_addr)
                elif self._fields_[i][2] == 'SO':
                    new_fields = getattr(globals()[self._fields_[i][0]], '_fields_')
                    ns = NestedStruct(self.lp, self.rp, 0, self._fields_[i][2], new_fields, s_values[i+1])
                    new_buff = ns.addr_to_buffer(direction,source_addr + (j * s_size))
                    #if direction == 'local':
                    #r_addr = rp.allocate(len(all_buffer))
                    #rp.write(r_addr, new_buff)
                    r_values.append(new_buff)
                else:
                    raise Exception("Unknown operator")

            all_buffer += sr.get_buffer(self._fields_, r_values, o_direction)
        return all_buffer
class SyscallArgPointer(SyscallArg):
    pass


class SyscallStructArg(SyscallArgPointer):

    def read_buffer(self, direction):
        if direction == 'local':
            rp = self.rp
            base_address = self.syscall.arguments[self.index].value
            o_direction = 'remote'
        else:
            o_direction = 'local'
            rp = self.lp
            base_address = self.remote_addr
            r_addr = self.syscall.arguments[self.index].value

        if base_address == 0:
            return base_address
        next_arg = None
        if len(self.syscall.arguments) > self.index+1:
            next_arg = self.syscall.arguments[self.index+1].value
        ns = NestedStruct(self.lp, self.rp, 0, self.operator, self._fields_, next_arg)
        all_buffer = ns.addr_to_buffer(direction, base_address)
        if direction == 'local':
            r_addr = rp.allocate(len(all_buffer))

        rp.write(r_addr, all_buffer)
        if direction == 'local':
            self.remote_addr = r_addr
        return r_addr

    def write_value(self):
        return self.read_buffer('local')

    def read_value(self):
        if '<' not in self.operator:
            return False
        self.read_buffer('remote')

class SyscallBufferArg(SyscallArgPointer):
    def write_value(self):
        if self.operator == '>+1':
            l_size = self.syscall.arguments[self.index+1].value
            if l_size == 0:
                return 0
            local_address = self.syscall.arguments[self.index].value
            l_buffer = self.lp.read(local_address, l_size)
            r_addr = self.rp.allocate(len(l_buffer))
            self.rp.write(r_addr, l_buffer)
            return r_addr
        if self.operator == '<+1R':
            size = self.rsc.args[self.index+1].get_pointed_value()
            if not size:
                return 0
            self.remote_addr = self.rp.allocate(size)
            return self.remote_addr

        if self.operator == '<+1':
            l_size = self.syscall.arguments[self.index+1].value
            self.remote_addr = self.rp.allocate(l_size)
            return self.remote_addr
        return False

    def read_value(self):
        if self.operator == '<+1':
            l_size = self.syscall.arguments[self.index+1].value
            local_address = self.syscall.arguments[self.index].value
            l_buffer = self.rp.read(self.remote_addr, l_size)
            self.lp.write(local_address, l_buffer)

        if self.operator == '<+1R':
            size = self.rsc.args[self.index+1].get_pointed_value()
            if not size:
                return None
            self.lp.write(self.syscall.arguments[self.index].value,
                          self.rp.read(self.remote_addr, size))
class void(SyscallBufferArg):
    pass


#TODO: Parse socketaddr and map sizes
class sockaddr(SyscallStructArg):
    _fields_ = [("sin_family", ctypes.c_uint16, 'S'),
                ("sin_port", ctypes.c_uint16, 'S'),
                ("sin_addr", ctypes.c_int, 'S')]


#TODO: more dynamic length
class c_string:
    _type_ = "s"
    def __init__(self, length):
        self._length_ = length

class fd_set(SyscallStructArg):
    _fields_ = [('fds_bits', c_string(128), 'S')]


class timeval(SyscallStructArg):
    _fields_ = [("tv_sec", ctypes.c_long, 'S'), ("tv_usec", ctypes.c_long, 'S')]

class pollfd(SyscallStructArg):
    _fields_ = [("fd", ctypes.c_uint, 'S'),
                ("events", ctypes.c_short, 'S'),
                ("revents", ctypes.c_short, 'S')]

class socklen_t(SyscallStructArg):
    _fields_ = [("len", ctypes.c_uint)]


class msghdr(SyscallStructArg):
    _fields_ = [('msg_name', ctypes.c_void_p, 'C+1'),
                ('msg_namelen', ctypes.c_uint, 'S'),
                ('iovec', ctypes.c_void_p, 'C*1'),
                ('msg_iovlen', ctypes.c_uint, 'S'),
                ('cmsghdr', ctypes.c_void_p, 'C+1'),
                ('msg_controllen', ctypes.c_uint, 'S'),
                ('msg_flags', ctypes.c_uint, 'S')]

class mmsghdr(SyscallStructArg):
    _fields_ = [('msghdr', msghdr, 'SO'),
                ('msg_len', ctypes.c_void_p, 'S')]


class iovec(SyscallStructArg):
    _fields_ = [('iov_base', ctypes.c_void_p, 'C+1'),
                ('iov_len', ctypes.c_void_p, 'S')]

class cmsghdr(SyscallStructArg):
        _fields_ = [('cmsg_len', ctypes.c_void_p, 'S'),
                    ('cmsg_level', ctypes.c_uint, 'S'),
                    ('cmsg_type', ctypes.c_uint, 'S')]



class SyscallArgPointerNumber(SyscallArgPointer):
    def write_value(self):
        if self.syscall.arguments[self.index].value == 0:
            return 0
        #TODO dynamically get taget int and long size
        r_addr = self.rp.allocate(4)
        l_buff = self.lp.read(self.syscall.arguments[self.index].value, 4)
        if '>' in self.operator:
            self.rp.write(r_addr, l_buff)
        return r_addr


    def get_pointed_value(self):
        #TODO dynamically get taget int and long size
        if self.syscall.arguments[self.index].value != 0:
            l_buff = self.lp.readBytes(self.syscall.arguments[self.index].value, 4)
            return struct.unpack('<I', l_buff)[0]
        return None

class StructReader(object):
    def __init__(self):
        self.size_mapping = [{ctypes.c_void_p: {'local': 8, 'remote': 4}}, {ctypes.c_long: {'local': 8, 'remote': 4}}]

    def fix_fields_mapping(self, fields, direction):
        for i in range(len(fields)):
            for dict_map in self.size_mapping:
                if fields[i][1] in dict_map.keys():
                    fields[i] = (fields[i][0], ctypes.c_char * dict_map[fields[i][1]][direction], fields[i][2])
        return fields


    def get_format(self, fields, direction):
        fields = self.fix_fields_mapping(list(fields), direction)
        struct_format = ''
        for field in fields:
            if issubclass(field[1], SyscallStructArg):
                struct_format += str(self.get_size(field[1]._fields_, direction)) + 's'
            elif isinstance(field[1]._type_, str):
                if field[1]._type_ == 's':
                    struct_format += str(field[1]._length_)
                struct_format += field[1]._type_
            else:
                struct_format += str(field[1]._length_) + field[1]._type_._type_
        return struct_format

    def get_size(self, fields, direction='remote'):
        struct_format = self.get_format(fields, direction)
        struct_format = struct_format.replace('4c', 'I')
        struct_format = struct_format.replace('8c', 'P')
        return struct.calcsize(struct_format)

    def get_buffer(self, fields, values, direction='remote'):
        struct_format = self.get_format(fields, direction)
        #TODO: better dynamic packing
        struct_format = struct_format.replace('4c', 'I')
        struct_format = struct_format.replace('8c', 'P')
        return struct.pack(struct_format, *values)

    def from_buffer(self, fields, buffer, direction='remote'):
        struct_format = self.get_format(fields, direction)
        struct_format = struct_format.replace('4c', 'I')
        struct_format = struct_format.replace('8c', 'P')
        #struct_values = struct.unpack(struct_format, buffer)
        values_index = 0
        char_index = 0
        struct_values = struct.unpack(struct_format, buffer)
        '''while char_index < len(struct_format):
            char = struct_format[char_index]
            if ord(char) >= ord('0') and ord(char) <= ord('9'):
                tmp_format = '@' + char + struct_format[char_index+1]
                size = struct.calcsize(tmp_format)
                return_number = ''
                for buff in buffer[values_index:values_index+size]:
                    return_number = buff.encode('hex') + return_number
                struct_values.append(int(return_number, 16))
                values_index += size
                char_index += 2
            else:
                size = struct.calcsize('@' + char)
                struct_values.append(struct.unpack('@' + char, buffer[values_index:values_index+size])[0])
                values_index += size
                char_index += 1
            #char_index +=1
        '''
        return struct_values

