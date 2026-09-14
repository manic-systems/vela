;; Exercises every construct vela rewrites: active data segments referenced by i32.const
;; addresses, direct calls, a data-resident pointer table, and an indirect call through the
;; function table. `run` folds all of it into one number so a transformed module can be compared
;; against the original by value.
(module
  (memory (export "memory") 1)

  (data (i32.const 256) "the quick brown fox jumps over the lazy dog")
  (data (i32.const 512) "supercell clash of clans logic layer")
  (data (i32.const 768) "\00\01\00\00\00\02\00\00")

  ;; A pointer into the segment at 256, stored as data rather than as an i32.const. vela must not
  ;; lazily gate segment 0 on the strength of code references alone.
  (data (i32.const 1024) "\00\01\00\00")

  (table 4 funcref)
  (elem (i32.const 0) $sum_bytes $length $checksum $zero)

  (type $unary (func (param i32) (result i32)))

  (func $zero (param i32) (result i32)
    i32.const 0)

  (func $length (param $ptr i32) (result i32)
    (local $n i32)
    block $done
      loop $scan
        local.get $ptr
        local.get $n
        i32.add
        i32.load8_u
        i32.eqz
        br_if $done
        local.get $n
        i32.const 1
        i32.add
        local.set $n
        br $scan
      end
    end
    local.get $n)

  (func $sum_bytes (param $ptr i32) (result i32)
    (local $n i32) (local $acc i32)
    local.get $ptr
    call $length
    local.set $n
    block $done
      loop $walk
        local.get $n
        i32.eqz
        br_if $done
        local.get $acc
        local.get $ptr
        local.get $n
        i32.const 1
        i32.sub
        local.tee $n
        i32.add
        i32.load8_u
        i32.add
        local.set $acc
        br $walk
      end
    end
    local.get $acc)

  (func $checksum (param $ptr i32) (result i32)
    local.get $ptr
    call $sum_bytes
    i32.const 31
    i32.mul
    local.get $ptr
    call $length
    i32.add)

  ;; Reads a pointer out of data rather than materialising it as a constant.
  (func $via_pointer (result i32)
    i32.const 1024
    i32.load
    call $sum_bytes)

  (func $via_table (param $which i32) (param $ptr i32) (result i32)
    local.get $ptr
    local.get $which
    call_indirect (type $unary))

  (func (export "run") (result i32)
    (local $acc i32)
    i32.const 256
    call $checksum
    local.set $acc

    local.get $acc
    i32.const 512
    call $checksum
    i32.add
    local.set $acc

    local.get $acc
    i32.const 768
    i32.load16_u
    i32.add
    local.set $acc

    local.get $acc
    call $via_pointer
    i32.add
    local.set $acc

    local.get $acc
    i32.const 0
    i32.const 512
    call $via_table
    i32.add
    local.set $acc

    local.get $acc
    i32.const 1
    i32.const 256
    call $via_table
    i32.add)
)
