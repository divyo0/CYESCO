# CYESCO
CYBERTOOL KIT P
cyesco is a lightweight network security toolkit created as part of a college project. the goal of this project is to provide a simple platform where different network analysis and monitoring tools are available in one place. many cybersecurity tools are either complex or require separate installations, so this project tries to combine useful features inside a single interface.

the toolkit includes modules that help users analyze networks, monitor traffic and understand basic security risks. the project is mainly designed for educational learning, research practice and authorized network testing environments.

main features

the current version of cyesco includes several modules that help in basic network analysis:

wifi network analyzer – shows nearby networks and security types

packet sniffer and mini ids – monitors network packets and basic suspicious activity

port scanner with banner grabbing – checks open ports and service information

firewall rule analyzer – reviews firewall rules and identifies possible issues

attack surface / osint module – gathers public information related to domains or ip

endpoint security helper – checks local network connections and system activity

ip and domain geolocation – shows approximate location information

honeypot system – simple simulated services used to detect connection attempts

these modules are available through a web dashboard interface and command line interaction.

technologies used

the project is built mainly using python and some commonly used open source libraries.

python

flask (for web dashboard)

networking libraries such as scapy and socket

basic html and css for interface

system monitoring libraries for endpoint checks

since most tools are open source the system can run on normal computers without expensive infrastructure.

project purpose

the main idea behind cyesco is to help students understand how different security tools work together in a real environment. it demonstrates concepts like network scanning packet monitoring traffic inspection and security analysis in a simplified way.

this toolkit is not intended to replace professional enterprise security systems. instead it acts as a learning platform for cybersecurity concepts.

ethical use notice

this toolkit must only be used on systems or networks where the user has proper authorization. running network scans or monitoring tools on networks without permission may violate laws or security policies. this project is created only for educational research and authorized testing purposes.

our team is not responsible for misuse of the software.

project status

this repository currently contains partial implementation of the cyesco toolkit. more modules and improvements may be added later such as:

better visualization dashboards

improved alert detection

automated reporting features

integration with more security analysis tools
