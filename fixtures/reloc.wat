(module
  (import "env" "__memory_base" (global $base i32))
  (memory (export "memory") 2)
  (data (global.get $base) "relocatable payload here")
  (data (offset (global.get $base) (i32.const 64) (i32.add)) "second relocatable chunk")
  (func $sum (param $ptr i32) (param $n i32) (result i32)
    (local $acc i32)
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
  (func (export "run") (result i32)
    global.get $base
    i32.const 24
    call $sum
    global.get $base
    i32.const 64
    i32.add
    i32.const 24
    call $sum
    i32.add)
)
