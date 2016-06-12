#!/usr/bin/env python
from ptrace import PtraceError
from ptrace.debugger import (PtraceDebugger, Application,
                             ProcessExit, ProcessSignal, NewProcessEvent, ProcessExecution)
from ptrace.syscall import (SYSCALL_NAMES, SYSCALL_PROTOTYPES,
                            FILENAME_ARGUMENTS, SOCKET_SYSCALL_NAMES)
from ptrace.func_call import FunctionCallOptions
from sys import stderr, exit
from optparse import OptionParser
from logging import getLogger, error
#from ptrace.compatibility import *
from ptrace.error import PTRACE_ERRORS, writeError
from ptrace.ctypes_tools import formatAddress
import re
import ctypes
from handler import SyscallHandler

fds = []
class in_addr(ctypes.Structure):
    _fields_ = [("s_addr", ctypes.c_char * 4)]

class sockaddr_in(ctypes.Structure):
    _fields_ = [("sin_family", ctypes.c_uint16),
                ("sin_port", ctypes.c_uint16),
                ("sin_addr", in_addr)]

class fd_set(ctypes.Structure):
    _fields_ = [('fds_bits', ctypes.c_long * 32)]

class timeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]

libc = ctypes.CDLL("libc.so.6")

class RemoteSysCall(object):
    def __init__(self, ptrace_syscall, process):
        self.name = ptrace_syscall.name
        self.init_args(ptrace_syscall, process)
        self.process = process

    def init_args(self, ptrace_syscall, process):
        self.args = ptrace_syscall.arguments
        #stack_args = ['int', 'long', 'socketlen_t']

        if self.name == 'connect':
            self.args[1].memvalue = process.readBytes(self.args[1].value, self.args[2].value)
        if self.name == 'sendto':
            self.args[1].memvalue = process.readBytes(self.args[1].value, self.args[2].value)
            self.args[4].memvalue = process.readBytes(self.args[4].value, self.args[5].value)
        if self.name == 'recvfrom':
            self.args[1].memvalue = process.readBytes(self.args[1].value, self.args[2].value)
            self.args[4].memvalue = process.readBytes(self.args[4].value, self.args[5].value)
        if self.name == 'write':
            self.args[1].memvalue = process.readBytes(self.args[1].value, self.args[2].value)
        if self.name == 'read':
            self.args[1].memvalue = process.readBytes(self.args[1].value, self.args[2].value)
        if self.name == 'select':
            if self.args[1].value > 0:
                self.args[1].memvalue = process.readBytes(self.args[1].value, ctypes.sizeof(fd_set))
            if self.args[2].value > 0:
                self.args[2].memvalue = process.readBytes(self.args[2].value, ctypes.sizeof(fd_set))
            if self.args[3].value > 0:
                self.args[3].memvalue = process.readBytes(self.args[3].value, ctypes.sizeof(fd_set))
            if self.args[4].value > 0:
                self.args[4].memvalue = process.readBytes(self.args[4].value, ctypes.sizeof(timeval))
                #for arg in self.args:
                #    if arg.type not in stack_args:
                #        if arg.type == 'const struct sockaddr *addr':
                #            arg.memvalue = process.readBytes(arg.value, ctypes.sizeof(sockaddr_in))

    def call_syscall(self):
        syscall_libc = getattr(libc, self.name)
        args = []
        stack_args = ['unsigned int', 'int', 'long', 'socklen_t', 'size_t']
        for arg in self.args:
            if arg.type in stack_args:
                args.append(arg.value)
            else:
                if arg.value != 0:
                    args.append(ctypes.create_string_buffer(arg.memvalue))
                else:
                    args.append(ctypes.POINTER(ctypes.c_int)())
        #print self.name
        res = syscall_libc(*args)
        if self.name == 'recvfrom':
            #val = self.process.readBytes(self.args[1].value, self.args[2].value)
            self.process.writeBytes(self.args[1].value, args[1].raw)
        if self.name == 'socket':
            fds.append(res)
        return res
        #return libc.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
'''
sin = sockaddr_in(socket.AF_INET, socket.htons(8888),
                  (socket.inet_aton('127.0.0.1'),))
s = libc.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
print s
SIN_SIZE=16
buf = ctypes.create_string_buffer(16)

res_c = libc.connect(s, buf, 16)

get_errno_loc = libc.__errno_location
get_errno_loc.restype = ctypes.POINTER(ctypes.c_int)

print res_c
'''
syscall_list = ['socket', 'connect', 'sendto', 'select', 'write', 'read', 'recvfrom']
def handle_syscall(process, syscall):
    remoye_sys = RemoteSysCall(syscall, process)
    return remoye_sys.call_syscall()


sh = SyscallHandler()
sh.parse_syscall()

import threading

class SyscallThread(threading.Thread):
    def __init__(self, process, syscall_options, syscall):
        self.process = process
        self.syscall_options = syscall_options
        self.syscall = syscall
        threading.Thread.__init__(self)

    def run(self):
        self.syscall_thread(self.process, self.syscall)

    def syscall_thread(self, process, syscall):
        res = sh.run_syscall(syscall, process)
        process.setreg('rax', res)
        regs = process.getregs()
        syscall.result = regs.rax
        syscall.result_text  = syscall.result
        if syscall and (syscall.result is not None or self.options.enter):
            self.displaySyscall(syscall)
        process.syscall()
        '''
        #if sh.do_intercept(syscall) and syscall.result == None:
            #process.setInstrPointer(process.getInstrPointer()+6)
            #regs = process.getregs()
        #    process.setreg('orig_rax', -1)
            #process.setregs(regs)
            #process.singleStep()
            #res = handle_syscall(process, syscall)
            #process.setreg('orig_rax', 3)
        #if sh.do_intercept(syscall) and syscall.result != None:
            res = sh.run_syscall(syscall, process)
            #res = handle_syscall(process, syscall)
            #regs = process.getregs()
            #print res
            #print regs.orig_rax
        #    process.setreg('rax', res)
        #    regs = process.getregs()
            #print regs.orig_rax
        #    syscall.result = regs.rax
        #    syscall.result_text  = syscall.result
            #syscall.result = process.getreg('orig_rax')
            #syscall.result_text = syscall.result
            #process.setInstrPointer(process.getInstrPointer()+500)
            #pass

        #if syscall and (syscall.result is not None or self.options.enter):
        #    self.displaySyscall(syscall)

        # Break at next syscall
        process.syscall()'''


class SyscallTracer(Application):
    def __init__(self):
        Application.__init__(self)

        # Parse self.options
        self.parseOptions()

        # Setup output (log)
        self.setupLog()

    def setupLog(self):
        if self.options.output:
            fd = open(self.options.output, 'w')
        else:
            fd = stderr
        self._setupLog(fd)

    def parseOptions(self):
        parser = OptionParser(usage="%prog [options] -- program [arg1 arg2 ...]")
        self.createCommonOptions(parser)
        parser.add_option("--enter", help="Show system call enter and exit",
                          action="store_true", default=False)
        parser.add_option("--profiler", help="Use profiler",
                          action="store_true", default=False)
        parser.add_option("--type", help="Display arguments type and result type (default: no)",
                          action="store_true", default=False)
        parser.add_option("--name", help="Display argument name (default: no)",
                          action="store_true", default=False)
        parser.add_option("--string-length", "-s", help="String max length (default: 300)",
                          type="int", default=300)
        parser.add_option("--array-count", help="Maximum number of array items (default: 20)",
                          type="int", default=20)
        parser.add_option("--raw-socketcall", help="Raw socketcall form",
                          action="store_true", default=False)
        parser.add_option("--output", "-o", help="Write output to specified log file",
                          type="str")
        parser.add_option("--ignore-regex", help="Regex used to filter syscall names (eg. --ignore='^(gettimeofday|futex|f?stat)')",
                          type="str")
        parser.add_option("--address", help="Display structure addressl",
                          action="store_true", default=False)
        parser.add_option("--syscalls", '-e', help="Comma separated list of shown system calls (other will be skipped)",
                          type="str", default=None)
        parser.add_option("--socket", help="Show only socket functions",
                          action="store_true", default=False)
        parser.add_option("--filename", help="Show only syscall using filename",
                          action="store_true", default=False)
        parser.add_option("--show-pid",
                          help="Prefix line with process identifier",
                          action="store_true", default=False)
        parser.add_option("--list-syscalls",
                          help="Display system calls and exit",
                          action="store_true", default=False)
        parser.add_option("-i", "--show-ip",
                          help="print instruction pointer at time of syscall",
                          action="store_true", default=False)

        self.createLogOptions(parser)

        self.options, self.program = parser.parse_args()

        if self.options.list_syscalls:
            syscalls = SYSCALL_NAMES.items()
            syscalls.sort(key=lambda data: data[0])
            for num, name in syscalls:
                print "% 3s: %s" % (num, name)
            exit(0)

        if self.options.pid is None and not self.program:
            parser.print_help()
            exit(1)

        # Create "only" filter
        only = set()
        if self.options.syscalls:
            # split by "," and remove spaces
            for item in self.options.syscalls.split(","):
                item = item.strip()
                if not item or item in only:
                    continue
                ok = True
                valid_names = SYSCALL_NAMES.values()
                for name in only:
                    if name not in valid_names:
                        print >>stderr, "ERROR: unknow syscall %r" % name
                        ok = False
                if not ok:
                    print >>stderr
                    print >>stderr, "Use --list-syscalls options to get system calls list"
                    exit(1)
                # remove duplicates
                only.add(item)
        if self.options.filename:
            for syscall, format in SYSCALL_PROTOTYPES.iteritems():
                restype, arguments = format
                if any(argname in FILENAME_ARGUMENTS for argtype, argname in arguments):
                    only.add(syscall)
        if self.options.socket:
            only |= SOCKET_SYSCALL_NAMES
        self.only = only
        if self.options.ignore_regex:
            try:
                self.ignore_regex = re.compile(self.options.ignore_regex)
            except Exception, err:
                print "Invalid regular expression! %s" % err
                print "(regex: %r)" % self.options.ignore_regex
                exit(1)
        else:
            self.ignore_regex = None

        if self.options.fork:
            self.options.show_pid = True

        self.processOptions()

    def ignoreSyscall(self, syscall):
        name = syscall.name
        if self.only and (name not in self.only):
            return True
        if self.ignore_regex and self.ignore_regex.match(name):
            return True
        return False

    def displaySyscall(self, syscall):
        name = syscall.name
        text = syscall.format()
        if syscall.result is not None:
            text = "%-40s = %s" % (text, syscall.result_text)
        prefix = []
        if self.options.show_pid:
            prefix.append("[%s]" % syscall.process.pid)
        if self.options.show_ip:
            prefix.append("[%s]" % formatAddress(syscall.instr_pointer))
        if prefix:
            text = ''.join(prefix) + ' ' + text
        error(text)
    def syscall(self, process):
        state = process.syscall_state
        syscall = state.event(self.syscall_options)
        print syscall.name
        if sh.do_intercept(process, syscall):
            if syscall.result == None:
                process.setreg('orig_rax', -1)
                process.syscall()
            else:
                #t1 = SyscallThread(process, self.syscall_options, syscall)
                #t1.run()
                #t1.start()
                #t1.join()
                res = sh.run_syscall(syscall, process)
                process.setreg('rax', res)
                regs = process.getregs()
                syscall.result = regs.rax
                syscall.result_text  = syscall.result
                if syscall and (syscall.result is not None or self.options.enter):
                    self.displaySyscall(syscall)
                process.syscall()
        else:
            process.syscall()


    def syscallTrace(self, process):
        # First query to break at next syscall
        self.prepareProcess(process)

        while True:
            # No more process? Exit
            if not self.debugger:
                break

            # Wait until next syscall enter
            try:
                event = self.debugger.waitSyscall()
                process = event.process
            except ProcessExit, event:
                self.processExited(event)
                continue
            except ProcessSignal, event:
                event.display()
                process.syscall(event.signum)
                continue
            except NewProcessEvent, event:
                self.newProcess(event)
                continue
            except ProcessExecution, event:
                self.processExecution(event)
                continue

            # Process syscall enter or exit
            self.syscall(process)

    def processExited(self, event):
        # Display syscall which has not exited
        state = event.process.syscall_state
        if (state.next_event == "exit") \
                and (not self.options.enter) \
                and state.syscall:
            self.displaySyscall(state.syscall)

        # Display exit message
        error("*** %s ***" % event)

    def prepareProcess(self, process):
        process.syscall()
        process.syscall_state.ignore_callback = self.ignoreSyscall

    def newProcess(self, event):
        process = event.process
        error("*** New process %s ***" % process.pid)
        self.prepareProcess(process)
        process.parent.syscall()

    def processExecution(self, event):
        process = event.process
        error("*** Process %s execution ***" % process.pid)
        process.syscall()

    def runDebugger(self):
        # Create debugger and traced process
        self.setupDebugger()
        process = self.createProcess()
        if not process:
            return

        self.syscall_options = FunctionCallOptions(
            write_types=self.options.type,
            write_argname=self.options.name,
            string_max_length=self.options.string_length,
            replace_socketcall=not self.options.raw_socketcall,
            write_address=self.options.address,
            max_array_count=self.options.array_count,
        )
        self.syscall_options.instr_pointer = self.options.show_ip

        self.syscallTrace(process)

    def main(self):
        if self.options.profiler:
            from ptrace.profiler import runProfiler
            runProfiler(getLogger(), self._main)
        else:
            self._main()

    def _main(self):
        self.debugger = PtraceDebugger()
        try:
            self.runDebugger()
        except ProcessExit, event:
            self.processExited(event)
        except PtraceError, err:
            error("ptrace() error: %s" % err)
        except KeyboardInterrupt:
            error("Interrupted.")
        #except PTRACE_ERRORS, err:
        #    writeError(getLogger(), err, "Debugger error")
        self.debugger.quit()

    def createChild(self, program):
        pid = Application.createChild(self, program)
        error("execve(%s, %s, [/* 40 vars */]) = %s" % (
            program[0], program, pid))
        return pid

if __name__ == "__main__":
    SyscallTracer().main()
