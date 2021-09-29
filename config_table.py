table1 = bfrt.hesam_switch.pipe.SwitchIngress.ipv4_lpm
entry = table1.entry_with_ipv4_forward(dst_addr=0x0A32000A , dst_mac=0x9a98fa7dbbc2, port="1").push()
entry = table1.entry_with_ipv4_forward(dst_addr=0x0A32000B , dst_mac=0x4a3a95a42aed, port="2").push()
entry = table1.entry_with_ipv4_forward(dst_addr=0x0A320010 , dst_mac=0x627fb1e6d8a8, port="3").push()



table2 = bfrt.hesam_switch.pipe.SwitchIngress.LB
entry = table2.entry_with_LB_forward(dst_addr=0x0A320064).push()
table2.dump(from_hw=True)

#bfrt.hesam_switch.pipe.bloom_filter.dump(from_hw=True)
bfrt.hesam_switch.pipe.available_server.dump(from_hw=True)


table3 = bfrt.hesam_switch.pipe.SwitchIngress.update_available_server
entry = table3.entry_with_update_server(dst_addr=0x0A320065).push()

#entry = table3.entry_with_update_server(dst_addr=0xA3200D8).push()
#entry = table3.entry_with_update_server(dst_addr=0xA3200D3).push()
table3.dump(from_hw=True)


#entry = table2.entry_with_LB_forward(dst_addr=0x0A320064 , dst_mac=0xb8599fdf07cb , dst_ip=0x0A32000b, port="48").push()


table3 = bfrt.hesam_switch.pipe.SwitchIngress.server
entry = table3.entry_with_select_server(dst_addr=0x0A320065 , dst_mac=0xb8599fdf07d1 , dst_ip=0x0A320010, port="48").push()
entry = table3.entry_with_select_server(dst_addr=0x0A320066 , dst_mac=0xb8599fdf07cb , dst_ip=0x0A32000B, port="48").push()
table3.dump(from_hw=True)



ip neighbor add 10.50.0.100 lladdr b8:59:9f:df:07:cb dev enp1s0np0 nud permanent
ip neighbor add 10.50.0.11 lladdr b8:59:9f:df:07:cb dev enp1s0np0 nud permanent
ip neighbor add 10.50.0.16 lladdr b8:59:9f:df:07:d1 dev enp1s0np0 nud permanent


ip neighbor add 10.50.0.5 lladdr 00:15:4d:12:11:a8 dev enp101s0f1 nud permanent
ip neighbor add 10.50.0.101 lladdr b8:59:9f:df:07:cb dev enp101s0f1 nud permanent
ip neighbor add 10.50.0.102 lladdr b8:59:9f:df:07:cb dev enp101s0f1 nud permanent


ip neighbor add 10.50.0.5 lladdr 00:15:4d:12:11:a8 dev p1 nud permanent


ip neighbor add 10.50.0.216 lladdr b8:59:9f:df:86:86 dev veth2 nud permanent
