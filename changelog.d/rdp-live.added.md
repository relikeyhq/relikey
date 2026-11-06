- RDP is now exercised end to end, not only taken from Warpgate's documentation: `tools/warpgate_live.py <version>
  --rdp` holds a real RDP session (FreeRDP to an xrdp target, images in `tools/rdp-live/`, Debian pinned by digest)
  through Warpgate and checks what the agent relies on. The session is listed under its user and names its target,
  closing it as the agent does when a lease ends cuts the client, revoking the role alone cuts it as well, and it is
  recorded. It passes on Warpgate 0.30.4.
