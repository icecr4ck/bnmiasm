from binaryninja import *
from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm2.analysis.machine import Machine

def stop_sentinelle(jitter):
    jitter.run = False
    jitter.pc = 0
    return True

def emulate(bv, addr):
    archs = { "x86":"x86_32", "x86_64":"x86_64", "armv7":"arml", "aarch64":"aarch64l", "mips32":"mips32l", "powerpc":"ppc32b"}
    stop_addr = get_address_input("Stop emulation at (address):", "[Miasm] Emulation")
    try:
        jitter = Machine(archs[bv.arch.name]).jitter("gcc")
    except:
        show_message_box("[Miasm] Emulation", "Jitter not available for this architecture (" + archs[bv.arch.name] + ")", MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)
        return
    jitter.init_stack()
    for s in bv.segments:
        data = bv.read(s.start, len(s))
        jitter.vm.add_memory_page(s.start, PAGE_READ | PAGE_WRITE, data)
    jitter.set_trace_log()
    jitter.add_breakpoint(stop_addr, stop_sentinelle)
    jitter.init_run(addr)
    jitter.continue_run()
    for s in bv.segments:
        bv.write(s.start, jitter.vm.get_mem(s.start, len(s)))

PluginCommand.register_for_address("[Miasm] Emulate from this instruction", "Execute the code in a sandbox and apply the changes on the BNDB", emulate)
