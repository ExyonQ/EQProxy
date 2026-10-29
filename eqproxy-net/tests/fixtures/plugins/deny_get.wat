;; ABI v1 fixture: reads the request head and rejects only GET.
(module
  (memory (export "memory") 1)
  (func (export "eqproxy_alloc") (param i32) (result i32) i32.const 1024)
  (func (export "eqproxy_on_request") (param $ptr i32) (param $len i32) (result i32)
    (if (result i32)
      (i32.and
        (i32.and
          (i32.eq (i32.load8_u (local.get $ptr)) (i32.const 71))
          (i32.eq (i32.load8_u (i32.add (local.get $ptr) (i32.const 1))) (i32.const 69)))
        (i32.eq (i32.load8_u (i32.add (local.get $ptr) (i32.const 2))) (i32.const 84)))
      (then i32.const 403)
      (else i32.const 0))))
