Server program which implements an API to implement firewall rules: 
List of available commands is as follows: 
- System takes in Firewall rules in the format of <Ip> <port> or <Ip-Ip> <port-port> and checks their validity; rules are added with the starting character A followed by the rule 
- Clients can view all previous requests by submitting R 
- Clients can query the server to check if an IP and Port is allowed according to the rules, valid queries are added to the rule, queries begin with C 
- Clients can delete rules by typing D followed by the rule they want to delete
- The input L allow clients to see the rules and their queries
- The command F frees all the rules 
