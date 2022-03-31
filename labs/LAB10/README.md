LAB10: CFG Reconstruction
===

In this lab, you'll used forced execution to construct an
intra-procedural control flow graph showing all the control
flow transfers in target programs.

**NOTE**: This lab is optional. I couldn't get the PANDA forced execution plugin to behave
as I'd expect it to on non-trivial programs. We will use the time to debug the PANDA approach
and/or explore how we would use other tools (e.g., DBI) to accomplish the same thing.


## System setup

Install cytoscape from https://cytoscape.org.

If necessary, build the panda container again.
Run it with two shared directories: one for panda images and one for general files to share with your host. If you still have the images from LAB05, be sure to set that as the shared images directory.

```
docker run --rm -it -v $(pwd):/host -v $(pwd)/images:/root/.panda panda
```

Copy the provided files into your shared `/host` directory:

starter.py


Inside the container, install networkx with

```
pip install networkx
```


## Part 1: Data collection

Using the provided `starter.py`, expand the code to populate the [Networkx DiGraph](https://networkx.org/documentation/stable/reference/classes/digraph.html) (variable `graph`) with nodes and edges as necessary.
Break the main execution loop at the end of the first run.

Open the generated `out.graphml` file in Cytoscape.
Under the left "Style" menu, set the "node" fill color to be a continuous mapping for the `run_idx` node feature. Set the node shape to be different depending on the `is_branch` feature.
Under the same menu, select "edge" at the bottom and make the color a continuous mapping for the `run_idx` edge feature.
Change the graph layout to hierarchical

Check in 1: Show off the graph you generated from the first run.


## Part 2: Forced execution

Modify your script such that branches are flipped between runs such that you run different parts of the program.
