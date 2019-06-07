# Logchain

Logchain creates a PoS blockchain network which shares the content of logfiles with the network to secure them for post hacking analysis.

## Prerequisites

The PyNaCl library is needed. 

```
pip install pynacl
```

## How to start a network

Start the first client with a defined ip and port. This one will create the genisis block.
```
python logchain.py -i 10.0.0.1 -p 9999
```

Start all further clients with the aditional defined node adress.
```
python logchain.py -i 10.0.0.2 -p 9999 -ni 10.0.0.1 -np 9999
```

## Acknowledgments

* Idea of sharing logfiles http://www.thinkmind.org/download.php?articleid=cloud_computing_2017_3_20_28005
* PoS system created by https://nxtwiki.org/wiki/Whitepaper:Nxt


