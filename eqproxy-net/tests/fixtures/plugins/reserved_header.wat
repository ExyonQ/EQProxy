;; ABI v1 fixture: tries to rewrite Content-Length (a reserved header).
(module
  (import "eqproxy" "set_request_header"
    (func $set (param i32 i32 i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "content-length")
  (data (i32.const 32) "0")
  (func (export "eqproxy_alloc") (param i32) (result i32) i32.const 1024)
  (func (export "eqproxy_on_request") (param i32 i32) (result i32)
    (call $set (i32.const 0) (i32.const 14) (i32.const 32) (i32.const 1))
    i32.const 0))
