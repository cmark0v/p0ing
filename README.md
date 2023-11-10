## p0ing

passive online interactive network graph


graph visualization tool for passive network recon, attack surface monitoring. 
Primarily uses ``p0f``  to collect data and networkx to organize it. visualization in pyvis(as a static webapp) and networkx builtins(as a tkint interface)

requirements
------------

```
geoip-bin
libpcap-dev
```


env vars
--------

- ``TKINT`` - ``true`` default, show tkinter interface, otherwise just generate pyvis html
