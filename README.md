# ddfub
Decentralised Distributed Firewall using Blockchain (Dissertation)

This project was created as my disseratation for my BSc in Computer Science (Security and Resilience).

This distributed system allows a host on a network to alert all other hosts of a potential cyberattack, by broadcasting firewall rules to other hosts to apply.

Blockchain is used to validate these broadcasts, whereby a very primitive consensus mechanism is used (the block must fit on the chain for more than N% of hosts).

If consensus is obtained, the message can be sent from the victim, and will be added to the blockchain for all hosts on the network.

Hosts can join the system at any time, but their blockchains will not be backfilled.
