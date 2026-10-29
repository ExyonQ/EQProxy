;; ABI v1 fixture: rejects every request with 403.
(module
  (memory (export "memory") 1)
  (func (export "eqproxy_alloc") (param i32) (result i32) i32.const 1024)
  (func (export "eqproxy_on_request") (param i32 i32) (result i32)
    i32.const 403))
