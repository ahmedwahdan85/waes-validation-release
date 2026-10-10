# Load and run the WAES-256 PS benchmark on the ZCU102 over JTAG, with the
# platform's FSBL doing the PS initialization (no PL, no bitstream).
# Usage: xsdb scripts/run_fsbl.tcl   (board in JTAG boot mode, UART0 at 115200 baud)
set root  [file normalize [file dirname [info script]]/..]
set build $root/build
set fsbl  $root/ws/ps_plat/export/ps_plat/sw/boot/fsbl.elf

connect
# Halt the cores of a previous run before resetting, so no DDR traffic is in flight
foreach core {0 1 2 3} {
  catch {targets -set -nocase -filter "name =~ \"*A53*#$core\""; stop}
}
after 500
targets -set -nocase -filter {name =~ "*APU*"}
rst -system
after 3000

# FSBL on core 0: clocks, DDR, MIO/UART, system timer
targets -set -nocase -filter {name =~ "*A53*#0"}
rst -processor -clear-registers
dow $fsbl
con
after 5000
stop
puts "FSBL done"

# Load one image per Cortex-A53 core
foreach core {0 1 2 3} {
  targets -set -nocase -filter "name =~ \"*A53*#$core\""
  if {$core != 0} { rst -processor -clear-registers }
  dow $build/waes_bench_core$core.elf
}
# Core 0 first (clears the shared block), then the worker cores
targets -set -nocase -filter {name =~ "*A53*#0"}
con
after 1000
foreach core {1 2 3} {
  targets -set -nocase -filter "name =~ \"*A53*#$core\""
  con
}
puts "All 4 cores running; results appear on UART0 in about 25 s."
disconnect
