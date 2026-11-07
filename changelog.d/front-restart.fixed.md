- Adding the fleet page no longer breaks the core: `fleet_page.py` restarted the front alone, and a restarted front gets
  a new network namespace while the services sharing it stay in the old one, so the broker lost its database. It now
  restarts the front, then every running service in its namespace, in compose's order.
