Issues:
    Can't trace execution of suid binary - host /proc/sys/fs/suid_dumpable setting, but even changing to 1 doesn't work with dynamorio. See deployment limitations in https://dynamorio.org/release_notes.html.


Code based off https://axtaxt.wordpress.com/2014/03/02/implementing-a-simple-hit-tracer-in-dynamorio/ written by axt


# Alternative code


## Set up
Inside your shared folder, clone the repo https://github.com/mephi42/drtrace
edit CMAKELists.txt to add the following line at the top of the file:
```
list(APPEND CMAKE_PREFIX_PATH "/dynamorio/build/cmake")
```

Also edit the line with `DRTRACE_C_FLAGS` to add ` -DPAGE_SIZE=2048` to the end of the quoted string.

Now, inside your container, go into the directory for that repo and run
```
cmake .
make
```

You should now have a custom tool built and ready to run! Give it a try with
```
/dynamorio/build/bin64/drrun -c ./libdrtrace.so -- whoami
```

And examine the trace.out file

