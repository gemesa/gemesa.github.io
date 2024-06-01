---
title: Deploying a Bitcoin node on Synology DS923+
published: true
---

## Introduction

Bitcoin is a decentralized digital currency that operates without a central authority. It relies on blockchain technology, which is a public ledger that securely records all transactions. A Bitcoin node is a computer that participates in the Bitcoin network, storing and verifying all transactions and blocks on the blockchain. Nodes help maintain the network's security and integrity, but they do not necessarily mine Bitcoin (as will be the case with our node).

Since Bitcoin is storage-heavy, using a NAS is ideal for running a node. With transaction indexing enabled the required storage is currently around 670GB. In this post, we will set up a Bitcoin node running in a Docker container on the [Synology DS923+](https://www.synology.com/en-us/products/DS923+).

## Setting up the Bitcoin node

### Prerequisites

- **Container Manager** installed via **Package Center**
- *docker* folder created in **File Station**
- 2 subfolders created under *docker*:
  - *bitcoin-conf*
  - *bitcoin-data*
- *bitcoin-conf* contains your *bitcoin.conf* config file

![docker folder]({{site.baseurl}}/assets/btc-node/file-station-0.png)

In my case I wanted to enable transaction indexing (to be able to query transactions) so it looks like this:

```
$ cat bitcoin.conf 
regtest=0
txindex=1
disablewallet=1
printtoconsole=1
rpcuser=bitcoinrpc
rpcpassword=XXXXXXXXXXXXXXXXXXXX
```

### Deployment

Download the Docker image:

![Docker image]({{site.baseurl}}/assets/btc-node/container-manager-0.png)

Note: the source code for the image is available [here](https://github.com/kylemanna/docker-bitcoind/tree/master).

Create the Docker container:

![Docker container (pt. 1)]({{site.baseurl}}/assets/btc-node/container-manager-1.png)

![Docker container (pt. 2)]({{site.baseurl}}/assets/btc-node/container-manager-2.png)

![Docker container (pt. 3)]({{site.baseurl}}/assets/btc-node/container-manager-3.png)

![Docker container (pt. 4)]({{site.baseurl}}/assets/btc-node/container-manager-4.png)

Check the details of your container:

![Docker container (pt. 5)]({{site.baseurl}}/assets/btc-node/container-manager-5.png)

![Docker container (pt. 6)]({{site.baseurl}}/assets/btc-node/container-manager-6.png)

### RPC

After deploying your node, you can access it via the [RPC API](https://developer.bitcoin.org/reference/rpc/index.html).

#### `getblockchaininfo` method

```
$ curl --user bitcoinrpc --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "getblockchaininfo", "params": []}' -H 'content-type: text/plain;' http://<your-NAS-IP>:8332/
Enter host password for user 'bitcoinrpc':
{"result":{"chain":"main","blocks":846055,"headers":846055,"bestblockhash":"000000000000000000031d1a1542824cdff964b6a41cae6f12ab898d7f1bc79f","difficulty":84381461788831.34,"time":1717242899,"mediantime":1717240458,"verificationprogress":0.9999987878944071,"initialblockdownload":false,"chainwork":"00000000000000000000000000000000000000007c69af78866c43febdf9a730","size_on_disk":654058297284,"pruned":false,"warnings":""},"error":null,"id":"curltest"}
```

#### `getblockhash` method

```
$ curl --user bitcoinrpc --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "getblockhash", "params": [846055]}' -H 'content-type: text/plain;' http://<your-NAS-IP>:8332/
Enter host password for user 'bitcoinrpc':
{"result":"000000000000000000031d1a1542824cdff964b6a41cae6f12ab898d7f1bc79f","error":null,"id":"curltest"}
```

#### `getblock` method

```
$ curl --user bitcoinrpc --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "getblock", "params": ["000000000000000000031d1a1542824cdff964b6a41cae6f12ab898d7f1bc79f"]}' -H 'content-type: text/plain;' http://<your-NAS-IP>:8332/
Enter host password for user 'bitcoinrpc':
{"result":{"hash":"000000000000000000031d1a1542824cdff964b6a41cae6f12ab898d7f1bc79f","confirmations":1,"height":846055,"version":536928256,"versionHex":"2000e000","merkleroot":"5f0135c60e24c51fe1d9289b9e84fbadc8524ed963276c04a3d29d6d397ee961","time":1717242899,"mediantime":1717240458,"nonce":2354787640,"bits":"170355f0","difficulty":84381461788831.34,"chainwork":"00000000000000000000000000000000000000007c69af78866c43febdf9a730","nTx":6855,"previousblockhash":"00000000000000000003077380907f3901c7349b50bbd21c42a7aff50e736e7d","strippedsize":841674,"size":1468411,"weight":3993433,"tx":["735ece2302b6dce19040e7cc5b0ad1cc1528b8d1689e94617f114956d4e30196",...,"9fbc16eadc5deb6196a393cd07f1c4a110a8fd3b056091b639fb61f3c519d90b"]},"error":null,"id":"curltest"}
```

#### `getrawtransaction` method

```
$ curl --user bitcoinrpc --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "getrawtransaction", "params": ["735ece2302b6dce19040e7cc5b0ad1cc1528b8d1689e94617f114956d4e30196", true]}' -H 'content-type: text/plain;' http://<your-NAS-IP>:8332/
Enter host password for user 'bitcoinrpc':
{"result":{"txid":"735ece2302b6dce19040e7cc5b0ad1cc1528b8d1689e94617f114956d4e30196","hash":"1c4866fadb1ba987fa93335aadb2071c3f9283ef80068f0fb81c658499595643","version":1,"size":396,"vsize":369,"weight":1476,"locktime":0,"vin":[{"coinbase":"03e7e80c1d506f7765726564206279204c75786f722054656368f3003006ad4cb988fabe6d6d2583d8d6ca38f23524c77066c785b1fd15e1857e65b028e472f1d5812f52f8c610000000000000000000a22a008b840900000000","txinwitness":["0000000000000000000000000000000000000000000000000000000000000000"],"sequence":4294967295}],"vout":[{"value":0.00000546,"n":0,"scriptPubKey":{"asm":"OP_HASH160 bf73ad4cf3a107812bad3deb310611bee49a3c79 OP_EQUAL","desc":"addr(3K9KZZPB8NRwZVP5wNKX4VYhnswrJxpgZ4)#t30ua08r","hex":"a914bf73ad4cf3a107812bad3deb310611bee49a3c7987","address":"3K9KZZPB8NRwZVP5wNKX4VYhnswrJxpgZ4","type":"scripthash"}},{"value":3.31289953,"n":1,"scriptPubKey":{"asm":"OP_HASH160 056adde53ebc396a1b3b678bb0d3a5c116ff430c OP_EQUAL","desc":"addr(32BfKjhByDSxx3BM5vUkQ3NQq9csZR6nt6)#qgnhjqsh","hex":"a914056adde53ebc396a1b3b678bb0d3a5c116ff430c87","address":"32BfKjhByDSxx3BM5vUkQ3NQq9csZR6nt6","type":"scripthash"}},{"value":0.00000000,"n":2,"scriptPubKey":{"asm":"OP_RETURN aa21a9ed217ace2c57944754913f920d63e5cb52d02e5155a31fa560e0b5ab55a45d5019","desc":"raw(6a24aa21a9ed217ace2c57944754913f920d63e5cb52d02e5155a31fa560e0b5ab55a45d5019)#wnc5jsrm","hex":"6a24aa21a9ed217ace2c57944754913f920d63e5cb52d02e5155a31fa560e0b5ab55a45d5019","type":"nulldata"}},{"value":0.00000000,"n":3,"scriptPubKey":{"asm":"OP_RETURN 434f524501a21cbd3caa4fe89bccd1d716c92ce4533e4d4733f459cc4ca322d298304ff163b2a360d756c5db84","desc":"raw(6a2d434f524501a21cbd3caa4fe89bccd1d716c92ce4533e4d4733f459cc4ca322d298304ff163b2a360d756c5db84)#nnnlquj0","hex":"6a2d434f524501a21cbd3caa4fe89bccd1d716c92ce4533e4d4733f459cc4ca322d298304ff163b2a360d756c5db84","type":"nulldata"}},{"value":0.00000000,"n":4,"scriptPubKey":{"asm":"OP_RETURN 52534b424c4f434b3a445aa000be7b84af6989aff87d6704eeb64de3a71f718c2cb11db81b0061983a","desc":"raw(6a2952534b424c4f434b3a445aa000be7b84af6989aff87d6704eeb64de3a71f718c2cb11db81b0061983a)#d8nm0xra","hex":"6a2952534b424c4f434b3a445aa000be7b84af6989aff87d6704eeb64de3a71f718c2cb11db81b0061983a","type":"nulldata"}}],"hex":"010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff5a03e7e80c1d506f7765726564206279204c75786f722054656368f3003006ad4cb988fabe6d6d2583d8d6ca38f23524c77066c785b1fd15e1857e65b028e472f1d5812f52f8c610000000000000000000a22a008b840900000000ffffffff05220200000000000017a914bf73ad4cf3a107812bad3deb310611bee49a3c79876115bf130000000017a914056adde53ebc396a1b3b678bb0d3a5c116ff430c870000000000000000266a24aa21a9ed217ace2c57944754913f920d63e5cb52d02e5155a31fa560e0b5ab55a45d501900000000000000002f6a2d434f524501a21cbd3caa4fe89bccd1d716c92ce4533e4d4733f459cc4ca322d298304ff163b2a360d756c5db8400000000000000002b6a2952534b424c4f434b3a445aa000be7b84af6989aff87d6704eeb64de3a71f718c2cb11db81b0061983a0120000000000000000000000000000000000000000000000000000000000000000000000000","blockhash":"000000000000000000031d1a1542824cdff964b6a41cae6f12ab898d7f1bc79f","confirmations":1,"time":1717242899,"blocktime":1717242899},"error":null,"id":"curltest"}
```

References:
- https://bitcoindev.network/running-a-bitcoin-node-on-synology-nas/
- https://github.com/kylemanna/docker-bitcoind/blob/master/docs/config.md
- https://developer.bitcoin.org/reference/rpc/index.html
- https://www.blockchain.com/explorer
