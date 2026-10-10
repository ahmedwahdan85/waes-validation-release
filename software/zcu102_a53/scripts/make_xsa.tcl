# PS-only hardware platform for the ZCU102 (no PL logic, no bitstream).
# Usage: vivado -mode batch -source scripts/make_xsa.tcl
set root [file normalize [file dirname [info script]]/..]
set proj $root/hw/ps_only
file delete -force $proj
create_project ps_only $proj -part xczu9eg-ffvb1156-2-e
set bp [lindex [lsort [get_board_parts -quiet *zcu102*]] end]
if {$bp ne ""} { set_property board_part $bp [current_project] }
puts "board_part=$bp"

create_bd_design ps_only
set ps [create_bd_cell -type ip -vlnv xilinx.com:ip:zynq_ultra_ps_e ps]
if {$bp ne ""} {
  apply_bd_automation -rule xilinx.com:bd_rule:zynq_ultra_ps_e \
    -config {apply_board_preset "1"} $ps
}
# No PL: disable the PS-PL AXI masters/slaves, PL clocks, PL resets and PL interrupts
set_property -dict [list \
  CONFIG.PSU__USE__M_AXI_GP0 {0} \
  CONFIG.PSU__USE__M_AXI_GP1 {0} \
  CONFIG.PSU__USE__M_AXI_GP2 {0} \
  CONFIG.PSU__USE__IRQ0 {0} \
  CONFIG.PSU__USE__IRQ1 {0} \
  CONFIG.PSU__FPGA_PL0_ENABLE {0} \
  CONFIG.PSU__FPGA_PL1_ENABLE {0} \
  CONFIG.PSU__FPGA_PL2_ENABLE {0} \
  CONFIG.PSU__FPGA_PL3_ENABLE {0} \
  CONFIG.PSU__NUM_FABRIC_RESETS {0} \
] $ps
validate_bd_design
save_bd_design
make_wrapper -files [get_files ps_only.bd] -top -import
generate_target all [get_files ps_only.bd]
set_property top ps_only_wrapper [current_fileset]
update_compile_order -fileset sources_1

# APU clock as configured
puts "apu_clk=[get_property CONFIG.PSU__CRF_APB__ACPU_CTRL__ACT_FREQMHZ $ps]"
write_hw_platform -fixed -force -file $root/hw/ps_only.xsa
puts "XSA written"
