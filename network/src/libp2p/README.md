# ckb node with libp2p connectivity

## dial a libp2p node

You can dial a libp2p node by sending a `Dial` command to `NetworkController`'s `command_receiver`.

We implement a simple rpc to do that.

```
curl --json '{"id": 42, "jsonrpc": "2.0", "method": "dial_libp2p_peer", "params": ["/ip4/127.0.0.1/tcp/12345/p2p/12D3KooWHmBLmYH1u68t1nEZKqdqkmQGMYNLGXdxkmAj9viHKynz"]}' 127.0.0.1:8113
```
Here the MultiAddr for the node `/ip4/127.0.0.1/tcp/12345/p2p/12D3KooWHmBLmYH1u68t1nEZKqdqkmQGMYNLGXdxkmAj9viHKynz` is
obtained from inspecting this node's output

```
2023-12-07 11:12:50.440 +00:00 GlobalRt-2 INFO ckb_network::libp2p  libp2p listen on /ip4/0.0.0.0/tcp/12345/p2p/12D3KooWHmBLmYH1u68t1nEZKqdqkmQGMYNLGXdxkmAj9viHKynz
2
```
and `127.0.0.1:8113` is the rpc listening port of the peer trying to connect to
`/ip4/0.0.0.0/tcp/12345/p2p/12D3KooWHmBLmYH1u68t1nEZKqdqkmQGMYNLGXdxkmAj9viHKynz`.

## DisconnectMessage protocol

You can also disconnect from a peer by sending a `DisconnectMessage` request to the peer.

We implement a simple rpc to do that.

```
curl --json '{"id": 42, "jsonrpc": "2.0", "method": "disconnect_libp2p_peer", "params": ["12D3KooWHmBLmYH1u68t1nEZKqdqkmQGMYNLGXdxkmAj9viHKynz", "fuck off"]}' 127.0.0.1:8113
```
here `12D3KooWHmBLmYH1u68t1nEZKqdqkmQGMYNLGXdxkmAj9viHKynz` is the peer that we want to disconnect from, and "fuck off" is the good by message
we want to send to this peer.
