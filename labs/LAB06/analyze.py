from pandare import Panda
from mylogger import MySyscallLogger, TaintArgvs

panda = Panda(generic="x86_64")

panda.pyplugins.load(TaintArgvs)
panda.pyplugins.load(MySyscallLogger)

panda.run_replay("myrec")
