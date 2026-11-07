- The agent's state directory (and the fleet's) is 0700 in images built with podman: the Dockerfiles copied it
  with `COPY --chmod=0700`, which buildah applies to the contents and not to the directory, so a fresh volume started
  0755 and the agent refused it (#165, F13 of the rc.2 walk was not fixed). The parent directory is copied instead.
