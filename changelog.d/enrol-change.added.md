- `deploy/edge/enrol_change.py` writes the `enrol_edge` change the desk's Edges page asks for, from the cosigned
  statement and `targets.yaml`, and refuses a statement the desk would refuse (an officer that is not an anchor, a
  missing signature). The desk's page asked for a change "prepared with edge_cli", which has no such command, and a
  change written by hand had missed the unlock key (#177). The install guide says root reads the anchors on the People
  page, which only root sees, and hands them to the edge officer.
