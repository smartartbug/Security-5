package ids2;

import java.io.*;
import java.util.*;
import org.jnetpcap.*;
import org.jnetpcap.packet.*;
import org.jnetpcap.protocol.tcpip.*;
import org.jnetpcap.protocol.network.Ip4;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import org.jnetpcap.packet.format.FormatUtils;

/**
 *
 * @author Genevieve Suwara
 */
public class Ids2 {

    static LinkedList policies = new LinkedList();
    static LinkedList info = new LinkedList();
    static LinkedList info2 = new LinkedList();
    static Map<String, String> packets = new HashMap<>();

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        //get files from args
        String policyFile = "C:\\Users\\smart_000\\Desktop\\policy5.txt";   //args[0] 
        String pcapFile = "C:\\Users\\smart_000\\Desktop\\trace5.pcap";     //args[1]

        boolean stateful = false;
        String host, flags;
        flags = "";
        LinkedList to_host = new LinkedList();
        LinkedList from_host = new LinkedList();
        LinkedList communication = new LinkedList();

        try {
            //set up file reader
            FileReader reader = new FileReader(policyFile);
            BufferedReader buffer = new BufferedReader(reader);

            try {
                //until the end of the file...
                while ((host = buffer.readLine()) != null) {
                    LinkedList policy = new LinkedList();
                    policy.add(host.substring(5)); //get host 0
                    buffer.readLine();
                    policy.add(buffer.readLine().substring(5)); //get name 1
                    policy.add(buffer.readLine().substring(5)); //get type 2
                    stateful = policy.get(2).equals("stateful");

                    if (!stateful) {
                        policy.add(buffer.readLine().substring(6)); //get proto 3
                    } else {
                        policy.add("none"); //set proto to null
                    }
                    policy.add(buffer.readLine().substring(10));    //get host-port 4
                    policy.add(buffer.readLine().substring(14));    //get attacker_port 5
                    policy.add(buffer.readLine().substring(9));     //get attacker 6

                    String line;
                    while ((line = buffer.readLine()) != null && (line.contains("from_host") || line.contains("to_host"))) {
                        int index;
                        if ((index = line.indexOf(" with flags=")) != -1) {
                            if (line.contains("to_host")) {
                                communication.add(0);
                                communication.add(line.substring(9, index - 1));
                                to_host.add(line.substring(9, index - 1));
                            } else {
                                communication.add(1);
                                communication.add(line.substring(11, index - 1));
                                from_host.add(line.substring(11, index - 1));
                            }
                            flags = line.substring((index + 12));
                        } else if (line.contains("to_host")) {
                            communication.add(0);
                            communication.add(line.substring(9, line.length() - 1));
                            to_host.add(line.substring(9, line.length() - 1));
                        } else {
                            communication.add(1);
                            communication.add(line.substring(11, line.length() - 1));
                            from_host.add(line.substring(11, line.length() - 1));
                        }
//                        policy.add(to_host);
//                        policy.add(from_host);
                        policy.add(communication);
                        policy.add(flags);
                    }
                    policies.add(policy);
                }
            } catch (IOException ex) {
                System.out.println("Could not read policy file.");
            }
        } catch (FileNotFoundException ex) {
            System.out.println("Could not find policy file.");
        }
        //get info from policy file

//        if (!stateful){
//            //Stateless check
//            scan(pcapFile);
//        }
//        for (int i = 0; i < policies.size(); i++) {
//            LinkedList policy;
//            policy = (LinkedList) policies.get(i);
//            System.out.println("host " + policy.get(0));
//            System.out.println("name " + policy.get(1));
//            System.out.println("type " + policy.get(2));
//            System.out.println("proto " + policy.get(3));
//            System.out.println("host_port " + policy.get(4));
//            System.out.println("attacker_port " + policy.get(5));
//            System.out.println("attacker " + policy.get(6));
//            to_host = (LinkedList) policy.get(7);
//            from_host = (LinkedList) policy.get(8);
//            for (int j = 0; j < to_host.size(); j++) {
//                System.out.println("to_host " + to_host.get(i));
//            }
//            for (int j = 0; j < from_host.size(); j++) {
//                System.out.println("from_host " + from_host.get(i));
//            }
//            System.out.println("flags " + policy.get(9));
//            System.out.println("");
//        }
        scan(pcapFile);
    }

    private static void scan(String file) {
        final StringBuilder errbuf = new StringBuilder();

        //open the pcap file
        final Pcap pcap = Pcap.openOffline(file, errbuf);
        //print error if pcap is null
        if (pcap == null) {
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
            final Udp udp = new Udp();

            //get the next packet
            @Override
            public void nextPacket(JPacket packet, StringBuilder errbuf) {

                //System.out.println(packet.toString());
                //if headers are available...
                if (packet.hasHeader(Ip4.ID) && packet.hasHeader(Tcp.ID)) {
                    //put them in our header storage
                    packet.getHeader(ip);
                    packet.getHeader(tcp);

                    //System.out.println("TCP________________________________");
                    int source = tcp.source();
                    info.add(source); //get source
                    //System.out.println("source " + source);
                    int destination = tcp.destination();
                    info.add(destination); //get destination
                    //System.out.println("destination " + destination);
                    String sourceIP = FormatUtils.ip(ip.source());
                    info.add(sourceIP); //get sourceIP
                    //System.out.println("source IP " + sourceIP);
                    String destinationIP = FormatUtils.ip(ip.destination());
                    info.add(destinationIP); //get destinationIP
                    //System.out.println("destination IP " + destinationIP);
                    //byte [] payload = new byte[tcp.getPayloadLength()];
                    byte[] payload = tcp.getPayload();
                    String load = new String(payload);
                    info.add(load); //get payload
                    //System.out.println("payload " + load);
                    //System.out.println("flags " + tcp.flagsCompactString());
                    info.add(tcp.flagsCompactString()); //get flags
                    //System.out.println("");
                }

                if (packet.hasHeader(Udp.ID) && packet.hasHeader(Ip4.ID)) {
                    packet.getHeader(udp);
                    packet.getHeader(ip);

                    //System.out.println("UDP______________________________");
                    int source = udp.source();
                    info2.add(source);
                    //System.out.println("source " + source);
                    int destination = udp.destination();
                    info2.add(destination);
                    //System.out.println("destination " + destination);
                    String sourceIP = FormatUtils.ip(ip.source());
                    info2.add(sourceIP);
                    //System.out.println("source IP " + sourceIP);
                    String destinationIP = FormatUtils.ip(ip.destination());
                    info2.add(destinationIP);
                    //System.out.println("destination IP " + destinationIP);
                    byte[] payload = udp.getPayload();
                    String load = new String(payload);
                    info2.add(load);
                    //System.out.println("payload " + load);
                    //System.out.println("");
                }
                check();
                info = new LinkedList();
                info2 = new LinkedList();
            }
        }, errbuf);
    }

    public static void check() {
        for (int i = 0; i < policies.size(); i++) {
            LinkedList policy = (LinkedList) policies.get(i);
            String host = policy.get(0).toString();
            String name = policy.get(1).toString();
            String type = policy.get(2).toString();
            String proto = policy.get(3).toString();
            String host_port = policy.get(4).toString();
            String attacker_port = policy.get(5).toString();
            String attacker = policy.get(6).toString();
            LinkedList communication = (LinkedList) policy.get(7);

            if (proto.equals("tcp") || proto.equals("none")) {
                String source = info.get(0).toString();
                String destination = info.get(1).toString();
                String sourceIP = info.get(2).toString();
                String destinationIP = info.get(3).toString();
                String load = info.get(4).toString();
            } else if (proto.equals("udp") && !info2.isEmpty()) {
                String source = info2.get(0).toString();
                String destination = info2.get(1).toString();
                String sourceIP = info2.get(2).toString();
                String destinationIP = info2.get(3).toString();
                String load = info2.get(4).toString();
            }
            
            if (type.equals("stateful")) {
                for (int j = 0; j < communication.size(); j++)
                {
                    if (communication.get(j).toString().equals("0"))
                    {
                        
                    }
                    
                }
            } else {

            }

        }
        String name = policy.get(1);
        String type = policy.get(2);
        if (stateful) {

        }

        for (int i = 0; i < policies.size(); i++) {
            LinkedList policy = (LinkedList) policies.get(i);
            LinkedList to_host = (LinkedList) policy.get(7);
            if (policy.get(3).equals("tcp") || policy.get(3).equals("none")) {
                for (int j = 0; j < to_host.size(); j++) {
                    boolean match = true;

                    //check if the host_port equals the destination port
                    //check if the attacker_port equals the source port
                    if (!policy.get(4).equals("any") && !policy.get(4).equals(info.get(1).toString())) {
                        System.out.println("destination " + info.get(1) + ".");
                        System.out.println("host_port " + policy.get(4) + ".");
                        System.out.println("");
                        match = false;
                    }

                    if (!policy.get(5).equals("any") && !policy.get(5).equals(info.get(0).toString())) {
                        System.out.println("source " + info.get(0));
                        System.out.println("attacker_port " + policy.get(5));
                        System.out.println("");
                        match = false;
                    }

                    //check if the attacker = any 
                    //check if attacker ip equals sourceIP
                    if (!policy.get(6).equals("any") && !policy.get(6).equals(info.get(2).toString())) {
                        System.out.println("here2");
                        System.out.println("");
                        match = false;
                    }

                    String regex = to_host.get(j).toString();
                    regex.replace("\\\\", "\\\\\\\\");

                    Pattern p = Pattern.compile(".*" + regex + ".*", Pattern.DOTALL);
                    Matcher m = p.matcher(info.get(4).toString());
                    boolean b = m.matches();

                    if (!b) {
                        System.out.println("here3");
                        System.out.println("");
                        match = false;
                    }

                    if (match) {
                        System.out.println(policy.get(1));
                    }
                }
            } else if (policy.get(3).equals("udp") && !info2.isEmpty()) {
                for (int j = 0; j < to_host.size(); j++) {
                    boolean match = true;

                    if (!policy.get(4).equals("any") && !policy.get(4).equals(info2.get(1).toString())) {

                        System.out.println(policy.get(4).equals(info2.get(1).toString()));
                        System.out.println(policy.get(4).equals("any"));
                        System.out.println("destination " + info2.get(1).toString());
                        System.out.println("host_port " + policy.get(4).toString());
                        System.out.println("");
                        match = false;
                    }

                    if (!policy.get(5).equals("any") && !policy.get(5).equals(info2.get(0).toString())) {
                        System.out.println("source " + info2.get(0));
                        System.out.println("attacker_port " + policy.get(5));
                        System.out.println("");
                        match = false;
                    }

                    if (!policy.get(6).equals("any") && !policy.get(6).equals(info2.get(2).toString())) {
                        System.out.println("here2");
                        System.out.println("");
                        match = false;
                    }

                    String regex = to_host.get(j).toString();
                    regex.replace("\\\\", "\\\\\\\\");

                    String pattern = Pattern.quote(regex);
                    Pattern p = Pattern.compile(pattern, Pattern.DOTALL);
                    Matcher m = p.matcher(info2.get(4).toString());
                    boolean b = m.matches();

                    if (!b) {
                        System.out.println("here3");
                        System.out.println("");
                        match = false;
                    }

                    if (match) {
                        System.out.println(policy.get(1));
                    }
                }
            }
            //stateful //check if hostIP, host_port, attacker_port, and attackerIP match
            //LinkedList communication = (LinkedList) policy.get(7);
            //for (int j = 0; j < communication.size(); j++) {
            boolean match = true;
            if (policy.get(3).equals("tcp") || policy.get(3).equals("none")) {
                if ((!policy.get(4).equals("any")
                        && !policy.get(4).equals(info.get(1).toString())) || (!policy.get(5).equals("any")
                        && !policy.get(5).equals(info.get(0).toString()))
                        || !policy.get(6).equals("any") && policy.get(6).equals(info.get(2).toString())) {
                    match = false;
                }
            } else if (policy.get(3).equals("udp") && !info2.isEmpty()) {
                if (!policy.get(0).equals(info2.get(i)) || (!policy.get(4).equals("any")
                        && !policy.get(4).equals(info2.get(1).toString())) || (!policy.get(5).equals("any")
                        && !policy.get(5).equals(info2.get(0).toString()))
                        || !policy.get(6).equals("any") && policy.get(6).equals(info2.get(2).toString())) {
                    match = false;
                }
                if (match) {
                    if (!packets.containsKey(policy.get(5))
                }
                //}
                //if yes, record attacker_port along with payload to be added to later
                //if no, ignore
                //check if regex is found after collecting all
                stateless //check if hostIP, host_port, attacker_port, and attackerIP match
                        // if yes, look for next pattern
                        // if found print  
            }

        }
    }
}
