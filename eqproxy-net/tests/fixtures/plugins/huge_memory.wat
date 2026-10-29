;; ABI v1 fixture: initial memory (4 MiB) exceeds a 1 MiB bound.
(module
  (memory (export "memory") 64)
  (func (export "eqproxy_alloc") (param i32) (result i32) i32.const 1024)
  (func (export "eqproxy_on_request") (param i32 i32) (result i32) i32.const 0))
