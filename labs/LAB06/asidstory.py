from pandare import Panda
panda = Panda(generic="x86_64")
panda.load_plugin("asidstory")
panda.run_replay("myrec")
