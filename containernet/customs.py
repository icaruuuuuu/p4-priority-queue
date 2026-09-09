def orchestrate(nodes_dict, duration):
    """ 
    Insert custom orchestration here.
    Nodes are called via nodes_dict['node_name']. Use the .cmd method to call bash commands.
    e.g.: nodes_dict['h1'].cmd(f"bash -c 'scripts/custom-script.sh {duration}'")
    """
    """
    Insert custom orchestration here.
    Nodes are called via nodes_dict['node_name']. Use the .cmd method to call bash commands.
    e.g.: nodes_dict['h1'].cmd(f"bash -c 'scripts/custom-script.sh {duration}'")
    """
    h1, h2 = nodes_dict['h1'], nodes_dict['h2']
    s1 = nodes_dict['s1']
    h1.cmd("arp -s 10.0.0.2 00:00:01:00:00:01")
    h2.cmd("arp -s 10.0.0.1 00:00:01:00:00:02")

    h1.cmd("sysctl -w net.ipv4.tcp_timestamps=0")
    h1.cmd("sysctl -w net.ipv4.tcp_window_scaling=0")

    h1.cmd("ethtool -K h1-eth0 tx off rx off")
    h2.cmd("ethtool -K h2-eth0 tx off rx off")
    
    h1.cmd("tc qdisc add dev h1-eth0 root tbf rate 10mbit burst 32kbit latency 30ms 2> /tmp/tc.err &")

    s1.cmd("ip link set s1-eth0 up")
    s1.cmd("ip link set s1-eth1 up")
    s1.cmd('cat /tmp/compile/ipv4lpm.txt | simple_switch_CLI')
    s1.cmd('cat /tmp/compile/table.txt | simple_switch_CLI')

    h2.cmd("service vsftpd start; iperf3 -sD; nginx -g 'daemon off;' &")
    h1.cmd("tcpdump -i h1-eth0 -s0 -w /tmp/dump-$(date +'%Y%m%d_%H%M%S').pcap &")
    h1.cmd(f"scripts/consume.sh {duration}")

    nodes_dict['s1'].cmd('echo "counter_read MyIngress.resultCounter 0" | simple_switch_CLI > /tmp/class')
    nodes_dict['s1'].cmd('echo "counter_read MyIngress.resultCounter 1" | simple_switch_CLI >> /tmp/class')

    return
