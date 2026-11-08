return {
    endpoint = "192.0.2.2", -- Replace with the server's reachable numeric IPv4.
    port = 51215,
    identity = "client-1",
    psk_file = "peer.key", -- Relative to this configuration file.
    name = "xtun0",
    address = "10.77.0.2",
    peer_address = "10.77.0.1",
    routes = { "198.19.0.0/24" }, -- Explicit remote networks only; no /0.
}
