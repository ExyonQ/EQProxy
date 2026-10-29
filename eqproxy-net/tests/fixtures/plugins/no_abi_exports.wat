;; ABI v1 fixture: missing eqproxy_on_request; load must reject it.
(module
  (memory (export "memory") 1)
  (func (export "eqproxy_alloc") (param i32) (result i32) i32.const 0))
