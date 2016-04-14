package ids2;

import java.io.*;
import java.util.*;
import org.jnetpcap.*;
import org.jnetpcap.packet.*;
import org.jnetpcap.protocol.tcpip.*;
import org.jnetpcap.protocol.network.Ip4;
import java.util.*;
import org.jnetpcap.packet.format.FormatUtils;

/**
 *
 * @author Genevieve Suwara
 */
public class Ids2 {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        String policyFile = "C:\\Users\\smart_000\\Desktop\\policy1.txt";//args[0] 
        String pcapFile = "C:\\Users\\smart_000\\Desktop\\trace1.pcap";//args[1]
        //TODO Make sure policy and pcap will be read-in in this order
        Boolean stateful = false;
        String host, name, type, proto, host_port, attacker_port, attacker, flags;
        host = name = type = proto = host_port = attacker_port = attacker = flags = "";
        LinkedList to_host = new LinkedList();
        LinkedList from_host = new LinkedList();
        
        //get info from policy file
        try{
            FileReader reader = new FileReader(policyFile);
            BufferedReader buffer = new BufferedReader(reader);
            
            host = buffer.readLine().substring(5);
            buffer.readLine();
            name = buffer.readLine().substring(5);
            type = buffer.readLine().substring(5);
            
            stateful = type.equals("stateful");
            
            if(!stateful){
                proto = buffer.readLine().substring(6);
            }
            host_port = buffer.readLine().substring(10);
            attacker_port = buffer.readLine().substring(14);
            attacker = buffer.readLine().substring(9);
            
            String line;
            while((line = buffer.readLine()) != null)
            {
                int index;
                if((index = line.indexOf(" with flags=")) != -1)
                {
                    if(line.contains("to_host"))
                    {
                        to_host.add(line.substring(8, index));
                    } else {
                        from_host.add(line.substring(10, index));
                    }
                    flags = line.substring((index + 12));
                }
                else{
                    if(line.contains("to_host"))
                    {
                        to_host.add(line.substring(8));
                    } else {
                        from_host.add(line.substring(10));
                    }      
                }
            }//TODO account for flags
        } 
        catch(FileNotFoundException ex){
            System.out.println("Could not find policy file.");
        }
        catch(IOException ex){
            System.out.println("Could not read policy file.");
        }
        
        if (!stateful){
            //Stateless check
            scan(pcapFile);
        }
        
        System.out.println("host " + host);
        System.out.println("name " + name);
        System.out.println("type " + type);
        System.out.println("proto " + proto);
        System.out.println("host_port " + host_port);
        System.out.println("attacker_port " + attacker_port);
        System.out.println("attacker " + attacker);
        for(int i = 0; i < to_host.size(); i++)
        {
            System.out.println("to_host " + to_host.get(i));
        }
        for(int i = 0; i < from_host.size(); i++)
        {
            System.out.println("from_host " + from_host.get(i));
        }
        System.out.println("flags " + flags);
        
        //Kevin - here we need to call the scan method
    }
    
    private static void scan(String file){
        final StringBuilder errbuf = new StringBuilder();
        
        //open the pcap file
        final Pcap pcap = Pcap.openOffline(file, errbuf);
        //print error if pcap is null
        if (pcap == null){
            System.err.println(errbuf);
        }
        
        ////create maps for the two categories of IP addresses we want to track
        //final Map<String, Integer> synSenders = new HashMap<>();
        //final Map<String, Integer> synAckReceivers = new HashMap<>();
            
        //loop through the pcap file until it there are no more packets to read
        pcap.loop(Pcap.LOOP_INFINITE, new JPacketHandler<StringBuilder>() {
            //create storage for headers
            final Ip4 ip = new Ip4();
            final Tcp tcp = new Tcp();
            
            //get the next packet
            @Override
            public void nextPacket(JPacket packet, StringBuilder errbuf){
                //if headers are available...
                if(packet.hasHeader(Ip4.ID) && packet.hasHeader(Tcp.ID)){
                    //put them in our header storage
                    packet.getHeader(ip);
                    packet.getHeader(tcp);
                    
                    //Kevin - here we need to get the information to compare against the policy file
                    //Kevin - somewhere (maybe not here, I'm not sure) we need to compare info againt the policy file
                    
                    int host_port = tcp.source();
                    int attacker_port = tcp.destination();
                    String attacker = FormatUtils.ip(ip.destination());
                    byte [] payload = new byte[tcp.getPayloadLength()];
                    for (int i = 0; i < tcp.getPayloadLength(); i++){
                        payload[i] = tcp.getPayload()[i];
                        System.out.println(payload[i]);
                    }
                    
                    //if the packet is sending SYN...
                    if(tcp.flags_SYN())
                    {
                        //if the packet is not sending ACK...
                        if(!tcp.flags_ACK())
                        {
//                            //if the sender IP has not been put in the map yet...
//                            if (!synSenders.containsKey(FormatUtils.ip(ip.source())))
//                            {
//                                //put the IP in the map and record their 1 SYN packet sent
//                                synSenders.put(FormatUtils.ip(ip.source()), 1);
//                            }
//                            else 
//                            {
//                                //increment the number of SYN packets associated with that IP
//                                synSenders.put(FormatUtils.ip(ip.source()), synSenders.get(FormatUtils.ip(ip.source())) + 1);
//                            }
                        }
                        //otherwise, if the packet IS sending ACK...
                        else 
                        {
//                            //if the destination IP has not been put int the map yet...
//                            if (!synAckReceivers.containsKey(FormatUtils.ip(ip.destination())))
//                            {
//                                //put the IP in the map and record their 1  SYN+ACK packet received
//                                synAckReceivers.put(FormatUtils.ip(ip.destination()), 1);
//                            }
//                            else 
//                            {
//                                //increment the number of SYN+ACK packets associated with that IP
//                                synAckReceivers.put(FormatUtils.ip(ip.destination()), synAckReceivers.get(FormatUtils.ip(ip.destination())) + 1);
//                            }
                        }
                    }
                }
            }
        }, errbuf);
        
        //for each IP in the map of SYN packet senders...
//        for (Map.Entry<String, Integer> entry : synSenders.entrySet())
//        {
//            //if that IP also appears in the map of SYN+ACK packet receivers...
//            if (synAckReceivers.get(entry.getKey()) != null)
//            {
//                //if that IP sent more than 3 times as many SYN packets as SYN+ACK packets it received...
//                if (entry.getValue() > (3 * synAckReceivers.get(entry.getKey()))){
//                    //print that IP
//                    System.out.println(entry.getKey());
//                }
//            }
//            //otherwise, if that IP doesn't also appear in the map of SYN+ACK packet receivers
//            //print that IP (since it only sent SYN packets and didn't receive any SYN+ACK packets)
//            else System.out.println(entry.getKey());
//        }
    }    
}
