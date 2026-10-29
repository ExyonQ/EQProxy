;; ABI v1 fixture: adds x-plugin: on to every forwarded request.
(module
  (import "eqproxy" "set_request_header"
    (func $set (param i32 i32 i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "x-plugin")
  (data (i32.const 16) "on")
  (func (export "eqproxy_alloc") (param i32) (result i32) i32.const 1024)
  (func (export "eqproxy_on_request") (param i32 i32) (result i32)
    (call $set (i32.const 0) (i32.const 8) (i32.const 16) (i32.const 2))
    i32.const 0))
