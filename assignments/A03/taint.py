from pandare import Panda
panda = Panda(arch='i386', os_version='linux-32-debian:3.2.0-4-686-pae')

panda.load_plugin("file_taint", {"filename": "id_rsa"})
panda.load_plugin("tainted_net", {"query_outgoing_network": True, "filename": "id_rsa"})
panda.run_replay("commands_wat")
