;; ABI v1 fixture: grows 100 pages past a 1 MiB store limit.
(module
  (memory (export "memory") 1)
  (func (export "eqproxy_alloc") (param i32) (result i32) i32.const 1024)
  (func (export "eqproxy_on_request") (param i32 i32) (result i32)
    (drop (memory.grow (i32.const 100)))
    i32.const 0))
