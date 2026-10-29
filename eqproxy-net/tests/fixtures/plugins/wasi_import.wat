;; ABI v1 fixture: imports WASI; capability gate must reject it at load.
(module
  (import "wasi_snapshot_preview1" "fd_write"
    (func $write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "eqproxy_alloc") (param i32) (result i32) i32.const 1024)
  (func (export "eqproxy_on_request") (param i32 i32) (result i32) i32.const 0))
