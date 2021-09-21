# Statistics

In order to produce the flame graph for the execution of
the protocol, run:
```
cargo +nightly test --features flame_it
```

For details on how to expand the flame graph, see here: https://github.com/llogiq/flamer

Also, note that this is currently being generated on tests, which is not as accurate as building in release mode and running it. But at least we can figure out what is slowing down our testing.
