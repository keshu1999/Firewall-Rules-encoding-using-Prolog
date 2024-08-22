## PROLOG ASSIGNMENT (Firewall Rules Encoding)

By
* Keshav Sharma - 2017A7PS0140P
* Ranga Sriram - 2017A7PS0047P
* Ishan Sharma - 2016B2A70773P


### General Information
* This Program implements firewall rules on an incoming packet.
* It accepts an incoming packet as a query and checks the data values of each clause with respect to the rule set defined in the database.
* The rule set follows a specific syntax and that should be followed for the program to execute correctly.
* The packet will be either accepted, rejected or dropped based on the conditions specified in the database.
* The packet will be accepted only is all the clauses are satisfied.
* The packet will be rejected if any one clause is rejected.
* The packet will be dropped if one or more clause is dropped and no clause is rejected.
* The highest priority is given to Rejected after which Dropped is given priority.
* Accept has the least priority.


### Database Description
* The database consists of multiple rules in the form of three predicates
   - 'accept'
   - 'reject'
   - 'drop'


### How to Run?
You need a Prolog Environment installed ([SWI-Prolog](https://www.swi-prolog.org/) is preferred) to run this program.