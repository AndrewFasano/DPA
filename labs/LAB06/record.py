from pandare import Panda
panda = Panda(generic="x86_64")

@panda.queue_blocking
def driver():
    panda.record_cmd("prog/a.out /usr/bin/whoami", 'prog',
                      recording_name='myrec')

    #panda.revert_sync("root")
    #panda.copy_to_guest("prog")
    #print(panda.run_serial_cmd("find prog"))
    #print(panda.run_serial_cmd("prog/a.out $(cat prog/input.txt)"))
    panda.end_analysis()

panda.run()
