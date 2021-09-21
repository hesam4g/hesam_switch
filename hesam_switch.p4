

#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "headers.p4"
#include "util.p4"

struct metadata_t {
    bit<16> checksum_udp_tmp;
	bit<8> computed_hash;
}

const bit<16> TYPE_IPV4 = 0x800;


// bit<32> smartnic = 0x0A32000B;

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;
        Checksum() ipv4_checksum;
    Checksum() udp_checksum;
    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        ig_md.checksum_udp_tmp = 0;
	ig_md.computed_hash = 0;
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        ipv4_checksum.add(hdr.ipv4);

        udp_checksum.subtract({hdr.ipv4.dst_addr});
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_UDP : parse_udp;
            default : accept;
        }
    }
    state parse_udp {
        // The tcp checksum cannot be verified, since we cannot compute
        // the payload's checksum.
        pkt.extract(hdr.udp);
        udp_checksum.subtract({hdr.udp.checksum});
        ig_md.checksum_udp_tmp = udp_checksum.get();
        transition accept;
    }
}

// ---------------------------------------------------------------------------
// Ingress
// ---------------------------------------------------------------------------
// Here is the bloom filter
Register<bit<32>, bit<8>>(256) bloom_filter;

control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {
    
    RegisterAction<bit<32>, bit<8>, bit<32>>(bloom_filter) read = {
        void apply(inout bit<32> value, out bit<32> rv) {
		bit<32> in_value;
		if (value == 0) { value = 0x0A32000a; }
		in_value = value;
		if (hdr.ipv4.total_len==28) {value = 0;}
		rv = value;
        }
    };
	RegisterAction<bit<32>, bit<8>, bit<32>>(bloom_filter) clear_bloom_filter = {
		void apply(inout bit<32> value) {
			value = 0;
		}
	};

    DirectCounter<bit<32>>(CounterType_t.PACKETS) pktcount;
    action drop() {
        ig_intr_dprsr_md.drop_ctl = 0;
        pktcount.count();
    }
    Hash<bit<8>>(HashAlgorithm_t.CRC8) hash;
    action LB_forward() {

        {
            ig_md.computed_hash = hash.get({ hdr.udp.src_port,
				hdr.ipv4.src_addr});
            hdr.ipv4.dst_addr = read.execute(ig_md.computed_hash);
        }

        pktcount.count();
    }

    table LB {
        key = {
            hdr.ipv4.dst_addr: exact;
        }
        actions = {
            LB_forward;
            drop;
        }
        size = 1024;
        counters = pktcount;
        default_action = drop();
    }

    action drop_() {
        ig_intr_dprsr_md.drop_ctl = 0;
    }
    action ipv4_forward(PortId_t port, mac_addr_t dst_mac) {
        ig_intr_tm_md.ucast_egress_port = port;
	hdr.ethernet.dst_addr = dst_mac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dst_addr: exact;
        }
        actions = { 
            ipv4_forward;
            drop_;
        }
        size = 1024;
        default_action = drop_();
    }
	
	DirectCounter<bit<32>>(CounterType_t.PACKETS) pktcount2;
	action clear_table_action (){
		{
			clear_bloom_filter.execute(ig_md.computed_hash);
		}
		pktcount2.count();	
	}
	table clear_table {
		key = {
			hdr.ipv4.src_addr: exact;
		}
		actions = {
			clear_table_action;
		}
		counters = pktcount2;
		size = 1024;
	}
    apply {
        if (hdr.ipv4.isValid()) {
		LB.apply();
		ipv4_lpm.apply();
		clear_table.apply();
        ig_intr_tm_md.bypass_egress = 1w1;
        }
    } 
}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {

    Checksum() ipv4_checksum;
    Checksum() udp_checksum;
    apply {
         hdr.ipv4.hdr_checksum = ipv4_checksum.update(
            {hdr.ipv4.version,
             hdr.ipv4.ihl,
             hdr.ipv4.diffserv,
             hdr.ipv4.total_len,
             hdr.ipv4.identification,
             hdr.ipv4.flags,
             hdr.ipv4.frag_offset,
             hdr.ipv4.ttl,
             hdr.ipv4.protocol,
             hdr.ipv4.src_addr,
             hdr.ipv4.dst_addr});

        hdr.udp.checksum = udp_checksum.update(data = {
            hdr.ipv4.dst_addr,
            ig_md.checksum_udp_tmp
            }, zeros_as_ones = true);
        // UDP specific checksum handling
         
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.udp);
    }
}

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         EmptyEgressParser(),
         EmptyEgress(),
         EmptyEgressDeparser()) pipe;

Switch(pipe) main;


