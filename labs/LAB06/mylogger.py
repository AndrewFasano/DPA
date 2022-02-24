from pandare import PyPlugin

class TaintArgvs(PyPlugin):
  def __init__(self, panda):

    @panda.ppp("proc_start_linux", "on_rec_auxv")
    def proc_starts(cpu, tb, auxv):
      procname = panda.ffi.string(auxv.argv[0]).decode()

      for x in range(1, auxv.argc):
        data = auxv.argv[x]
        s = panda.ffi.string(data)
        ptr = auxv.arg_ptr[x]
        print(f"{procname} arg {x} is {s} at {ptr:x}. Tainting")

        # Apply a taint label to the physical address for each char
        for idx in range(len(s)):
          paddr = panda.virt_to_phys(cpu, ptr+idx)
          panda.taint_label_ram(paddr, x)

class MySyscallLogger(PyPlugin):
  def __init__(self, panda):

    @panda.ppp("syscalls2", "on_all_sys_enter")
    def before_syscall_enter(cpu, pc, callno):
      if callno != 59:
        return

      # print something like "Syscall #X with arguments: A, B, C, D"
      args = panda.arch.get_args(cpu, 5, convention='syscall')
      #print(f"Syscall #{args[0]} with args: {[hex(x) for x in args[1:]]}")

      for arg in args[1:]:
          # Is this argument possibly a string pointer?
          try:
              value = panda.read_str(cpu, arg)
          except ValueError:
              continue

          print(f"Syscall #{args[0]} {arg:x} points to string: {value[:100]}")

          paddr = panda.virt_to_phys(cpu, arg)

          if paddr == 2**64-1:
              print("Unable to map")
              continue

          tainted = panda.taint_check_ram(paddr)
          if tainted:
              tq = panda.taint_get_ram(paddr)
              taint_labels = tq.get_labels()
              print("TAINTED:", taint_labels, "\n")
          else:
              print(f"{paddr:x} is untainted")

if __name__ == '__main__':
  # If this script is run directly, do a small test

  from pandare import Panda
  panda = Panda(generic="x86_64")

  panda.pyplugins.load(MySyscallLogger)

  @panda.queue_blocking
  def driver():
    panda.revert_sync("root")
    print(panda.run_serial_cmd("whoami"))
    panda.end_analysis()
  
  panda.run()
