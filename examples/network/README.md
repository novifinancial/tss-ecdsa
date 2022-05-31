To run this example, spin up at least two servers (three in this example)
on different ports and in separate terminals:
`cargo run --example network -- -r server -p 8000`
`cargo run --example network -- -r server -p 8001`
`cargo run --example network -- -r server -p 8002`

Then, spin up a client which connects to each of the servers:
`cargo run --example network -- -r client -s 8000 -s 8001 -s 8002`

You can then use the client interface to interact with the servers
by producing auxinfo, keyshares, presignatures, and signatures.
