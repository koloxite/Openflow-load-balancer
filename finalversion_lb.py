from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ether_types
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib import mac
import json
import random
import time
class LoadBalancer(app_manager.RyuApp):
    # define the default values, some useful global variables
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    wild3ips=['0.0.0.1/3','32.0.0.1/3','64.0.0.1/3','96.0.0.1/3','128.0.0.1/3','160.0.0.1/3','192.0.0.1/3','254.0.0.1/3']
    wild2ips=['0.0.0.1/2','64.0.0.1/2','128.0.0.1/2','192.0.0.1/2']
    wild1ips=['0.0.0.1/1','128.0.0.1/1']

    serverips=['10.0.0.1','10.0.0.2','10.0.0.3']
    bigserver='10.0.1.0'
    transitionip=[]
    oldip=0
    newip=0

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #use the hardcode laad values to change load
        strs=[4,3,1]
        self.change_load(datapath,strs,ev)
        #sleep for several seconds to make another change
        time.sleep(1000)
        newstrs=[5,2,1]
        pcount=0
        #find the part that need to change load for transition part
        for x in range(0,3):
            if strs[x]<newstrs[x]:
                self.newip=self.serverips[x]
                for y in range(pcount+strs[x],pcount+newstrs[x]):
                    self.transitionip.append(self.wild3ips[y])
            if strs[x]>newstrs[x]:
                self.oldip=self.serverips[x]
            if strs[x]>newstrs[x]:
                pcount=pcount+strs[x]

        #delete all the rules

        match=parser.OFPMatch()
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE,
                                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                                match=match)
        datapath.send_msg(mod)

        #change again
        self.change(datapath,strs,ev)



    def change_load(self,datapath,strs,ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        #add arp and ip rules for switch
        match=parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP,arp_spa='10.0.0.0/24')
        act=[]
        act.append(parser.OFPActionSetField(arp_spa='10.0.1.0'))
        act.append(parser.OFPActionOutput(ofproto.OFPP_FLOOD))
        self.add_flow(datapath,100, match,act)

        match=parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src='10.0.0.0/24')
        act=[]
        act.append(parser.OFPActionSetField(ipv4_src='10.0.1.0'))
        act.append(parser.OFPActionOutput(ofproto.OFPP_FLOOD))
        self.add_flow(datapath,100, match,act)
        #use algorithm to minimize the size of the wild card rule
        ip3c=0
        ip2c=0
        ip1c=0
        serverc=0
        strs.sort(reverse=True)
        for x in strs:
            while x/4>=1:
                x=x-4
                self.add_wildcard(datapath, self.wild1ips[ip1c],self.serverips[serverc])
                ip1c +=1
                ip2c+=2
                ip3c+=4
            while x/2>=1:
                x=x-2
                self.add_wildcard(datapath, self.wild2ips[ip2c],self.serverips[serverc])
                ip2c+=1
                ip3c+=2
            while x>=1:
                x=x-1
                self.add_wildcard(datapath, self.wild3ips[ip3c],self.serverips[serverc])
                ip3c+=1

            serverc=serverc+1
        #send a transition rule to take every packet go through controller
        self.refresh_idle(datapath)

    # transition rule, the second time would be use for refresh the idle_timeout
    def refresh_idle(self,datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        for x in self.transitionip:
            match=parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, tcp_src=x)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                            ofproto.OFPCML_NO_BUFFER)]
            self.add_flow_entry(datapath,10000, match,actions)


    def add_wildcard(self,datapath,clientip,serverip):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #add wild card rule for clients
        match=parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, arp_tpa='10.0.1.0',arp_spa=clientip)
        act=[]
        act.append(parser.OFPActionSetField(arp_tpa=serverip))
        act.append(parser.OFPActionOutput(ofproto.OFPP_FLOOD))
        self.add_flow(datapath,10, match,act)



        match=parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst='10.0.1.0',ipv4_src=clientip)
        act=[]
        act.append(parser.OFPActionSetField(ipv4_dst=serverip))
        act.append(parser.OFPActionOutput(ofproto.OFPP_FLOOD))
        self.add_flow(datapath,2, match,act)



    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)


    def add_flow_entry(self, datapath, priority, match, actions, timeout=60):
        # helper function to insert flow entries into flow table

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                            match=match, instructions=inst, idle_timeout=60)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        #only handle packets are in transition
        msg=ev.msg
        print(msg)
        dp=msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        p=packet.Packet(msg.data)

        actions=[]
        ippacket=p.get_protocol(ipv4.ipv4)
        dstip=ippacket.dst
        srcip=ippacket.src
        # check the packet, if no syn bit then go to old path and refresh idle time
        #if has syn bit then go to new path
        if dstip=='10.0.1.0':
            if (pkt.has_flags(tcp.TCP_SYN)):
                actions.append(ofp_parser.OFPActionSetField(ipv4_dst=self.newip))
            else:
                actions.append(ofp_parser.OFPActionSetField(ipv4_dst=self.oldip))
                self.refresh_idle(datapath)
        if srcip==self.oldip | srcip==self.newip:
            actions.append(ofp_parser.OFPActionSetField(ipv4_src='10.0.1.0'))
        actions.append(ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD))
        p.serialize()
        out = ofp_parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=dp.ofproto.OFPP_CONTROLLER,actions=actions,data=p.data)
        dp.send_msg(out)
