from binaryninja import *
from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm2.analysis.machine import Machine

def stop_sentinelle(jitter):
    jitter.run = False
    jitter.pc = 0
    return True

def emulate(bv, addr):
    choice = get_choice_input("Ready to emulate code?", "[Miasm] Emulation", ["Yes", "No"])
    if choice is 2:
        return
    stop_addr = get_address_input("Stop emulation at (address):", "[Miasm] Emulation")
    jitter = Machine("x86_32").jitter("gcc")
    jitter.init_stack()
    data = bv.read(bv.start, bv.end-bv.start)
    jitter.vm.add_memory_page(bv.start, PAGE_READ | PAGE_WRITE, data)
    jitter.add_breakpoint(stop_addr, stop_sentinelle)
    jitter.init_run(addr)
    jitter.continue_run()
    bv.write(bv.start, jitter.vm.get_mem(bv.start, bv.end-bv.start))

PluginCommand.register_for_address("[Miasm] Emulate from this instruction", "Execute the code in a sandbox and apply the changes on the BNDB", emulate)
