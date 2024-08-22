
%*****************************************************************To address IPV4 addresses***********************************************************
hex(Hex, Num) :-
	atom_concat('0x', Hex, HexAtom),
	atom_codes(HexAtom, HexCodes),
	number_codes(Num, HexCodes).

incoming_packet(adapter(P),ethernet(protocol_id(Q),vlan_no(R)),ipv4(ipv4_src_address(A),ipv4_dst_address(B),tcp_udp_src_port(C),tcp_udp_dst_port(D),icmp(icmp_type(E),icmp_message(F)),ip_protocol_no(G))):-

	(	adapter(P),
		ethernet(protocol_id(Q),
				vlan_no(R)),
		ipv4(ipv4_src_address(A),
			ipv4_dst_address(B),
			tcp_udp_src_port(C),
			tcp_udp_dst_port(D),
			icmp(icmp_type(E),
			icmp_message(F)),
			ip_protocol_no(G))
	),


	(
		(
			(rejected_adapter(P);
			rejected_protocol_id(Q);
			rejected_vlan_no(R);
			ipv4_src_address_reject(A);
			ipv4_dst_address_reject(B);
			rejected_tcp_udp_src_port(C);	
			rejected_tcp_udp_dst_port(D);
			reject_icmp_type(E);
			reject_icmp_message(F);
			rejected_IP_protocol_no(G)
			)
			-> write("\n\nPACKET REJECTED ")
		);

		(
			(dropped_adapter(P);
			dropped_protocol_id(Q);
			dropped_vlan_no(R);
			ipv4_src_address_drop(A);
			ipv4_dst_address_drop(B);
			dropped_tcp_udp_src_port(C);
			dropped_tcp_udp_dst_port(D);
			drop_icmp_type(E);
			drop_icmp_message(F);
			dropped_IP_protocol_no(G)
			)
		 	-> write("\n\nPACKET DROPPED")
		);

		(
			(allowed_adapter(P),
			allowed_protocol_id(Q),
			allowed_vlan_no(R),
			ipv4_src_address_accept(A),
			ipv4_dst_address_accept(B),
			allowed_tcp_udp_src_port(C),
			allowed_tcp_udp_dst_port(D),
			accept_icmp_type(E),
			accept_icmp_message(F),
			allowed_IP_protocol_no(G)
			) 
			-> write("\n\nPACKET ACCEPTED")
		)
	).

%****************************************************************************************************************************************************


adapter(X):-

(X= "any")->  write("\nAccepted Adapter " : X );

((rejected_adapter(X)) -> write("\nRejected Adapter " : X));
(dropped_adapter(X) -> write("\nDropped Adapter " : X));
(allowed_adapter(X) -> write("\nAccepted Adapter " : X )).


allowed_adapter(X):- 

accept([P|Q],_,_,_,_,_,_,_,_,_),member(X,[P|Q]);

(accept(L,_,_,_,_,_,_,_,_,_),string(L),
(split_string(L,"-","",[H|[T|_]]),
X>=H,
X=<T)).

rejected_adapter(X):-

reject([P|Q],_,_,_,_,_,_,_,_,_),member(X,[P|Q]);

(reject(L,_,_,_,_,_,_,_,_,_),string(L),
split_string(L,"-","",[H|[T|_]]),
X>=H,
X=<T).

dropped_adapter(X):-

drop([P|Q],_,_,_,_,_,_,_,_,_),member(X,[P|Q]);

(drop(L,_,_,_,_,_,_,_,_,_),string(L),
split_string(L,"-","",[H|[T|_]]),
X>=H,
X=<T).



%_______________________





ethernet(protocol_id(P),vlan_no(Q)):- 
vlan_no(Q), 
protocol_id(P). 


protocol_id(X):-
(rejected_protocol_id(X) -> write("\nRejected Protocol-ID " : X));
(dropped_protocol_id(X) -> write("\nDropped Protocol-ID " : X));
(allowed_protocol_id(X) -> write("\nAccepted Protocol-ID " : X)).

allowed_protocol_id(X):-

accept(_,[P|Q],_,_,_,_,_,_,_,_),member(X,[P|Q]);

(accept(_,L,_,_,_,_,_,_,_,_),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X >= W1,
X =< W2).

rejected_protocol_id(X):-

reject(_,[P|Q],_,_,_,_,_,_,_,_),member(X,[P|Q]);

(reject(_,L,_,_,_,_,_,_,_,_),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X>=W1,
X =< W2).

dropped_protocol_id(X):-

drop(_,[P|Q],_,_,_,_,_,_,_,_),member(X,[P|Q]);

(drop(_,L,_,_,_,_,_,_,_,_),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X>=W1,
X=<W2).


vlan_no(X):-
(rejected_vlan_no(X) -> write("\nRejected VLAN No " : X ));
(dropped_vlan_no(X) -> write("\nDropped VLAN No " : X));
(allowed_vlan_no(X) -> write("\nAccepted  VLAN No " : X )).

allowed_vlan_no(X):-

accept(_,_,[P|Q],_,_,_,_,_,_,_),member(X,[P|Q]);

(accept(_,_,L,_,_,_,_,_,_,_),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X>=W1,
X=<W2).


rejected_vlan_no(X):-

reject(_,_,[P|Q],_,_,_,_,_,_,_),member(X,[P|Q]);

(reject(_,_,L,_,_,_,_,_,_,_),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X>=W1,
X=<W2).

dropped_vlan_no(X):-

drop(_,_,[P|Q],_,_,_,_,_,_,_),member(X,[P|Q]);

(drop(_,_,L,_,_,_,_,_,_,_),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X>=W1,
X=<W2).



%_______________________





ipv4(ipv4_src_address(A),ipv4_dst_address(B),tcp_udp_src_port(C),tcp_udp_dst_port(D),icmp(icmp_type(E),icmp_message(F)),ip_protocol_no(G)):-

 ipv4_src_address(A),
 ipv4_dst_address(B),
 tcp_udp_src_port(C),
 tcp_udp_dst_port(D),
 icmp(icmp_type(E),
 icmp_message(F)),
 ip_protocol_no(G).


tcp_udp_src_port(X):- 
(rejected_tcp_udp_src_port(X) -> write("\nRejected TCP-UDP-Source Port " : X));
(dropped_tcp_udp_src_port(X) -> write("\nDropped TCP-UDP-Source Port " : X));
(allowed_tcp_udp_src_port(X) -> write("\nAccepted TCP-UDP-Source Port " : X)).



allowed_tcp_udp_src_port(X):-

accept(_,_,_,_,_,[P|Q],_,_,_,_),member(X,[P|Q]);

(accept(_,_,_,_,_,L,_,_,_,_),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X>=W1,
X=<W2).


rejected_tcp_udp_src_port(X):-

reject(_,_,_,_,_,[P|Q],_,_,_,_),member(X,[P|Q]);

(reject(_,_,_,_,_,L,_,_,_,_),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X>=W1,
X=<W2).

dropped_tcp_udp_src_port(X):-

drop(_,_,_,_,_,[P|Q],_,_,_,_),member(X,[P|Q]);

(drop(_,_,_,_,_,L,_,_,_,_),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X>=W1,
X=<W2).



tcp_udp_dst_port(X):- 
(rejected_tcp_udp_dst_port(X) -> write("\nRejected TCP-UDP-DST Port " : X));
(dropped_tcp_udp_dst_port(X) -> write("\nDropped TCP-UDP-DST Port " : X));
(allowed_tcp_udp_dst_port(X) -> write("\nAccepted TCP-UDP-DST Port " : X)).


allowed_tcp_udp_dst_port(X):-

accept(_,_,_,_,_,_,[P|Q],_,_,_),member(X,[P|Q]);

(accept(_,_,_,_,_,_,L,_,_,_),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X>=W1,
X=<W2).


rejected_tcp_udp_dst_port(X):-

reject(_,_,_,_,_,_,[P|Q],_,_,_),member(X,[P|Q]);

(reject(_,_,_,_,_,_,L,_,_,_),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X>=W1,
X=<W2).

dropped_tcp_udp_dst_port(X):-

drop(_,_,_,_,_,_,[P|Q],_,_,_),member(X,[P|Q]);

(drop(_,_,_,_,_,_,L,_,_,_),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X>=W1,
X=<W2).

ip_protocol_no(X):-
(rejected_IP_protocol_no(X) -> write("\nRejected IP-Protocol_No " : X));
(dropped_IP_protocol_no(X) -> write("\nDropped IP-Protocol_No " : X));
(allowed_IP_protocol_no(X) -> write("\nAccepted IP-Protocol_No " : X)).


allowed_IP_protocol_no(X):-

accept(_,_,_,_,_,_,_,_,_,[P|Q]),member(X,[P|Q]);

(accept(_,_,_,_,_,_,_,_,_,L),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X>=W1,
X=<W2).


rejected_IP_protocol_no(X):-

reject(_,_,_,_,_,_,_,_,_,[P|Q]),member(X,[P|Q]);

(reject(_,_,_,_,_,_,_,_,_,L),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X>=W1,
X=<W2).

dropped_IP_protocol_no(X):-

drop(_,_,_,_,_,_,_,_,_,[P|Q]),member(X,[P|Q]);

(drop(_,_,_,_,_,_,_,_,_,L),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X>=W1,
X=<W2).

ipv4_src_address(X):-
(ipv4_src_address_reject(X) -> write("\nRejected SOURCE IP-Address " : X));
(ipv4_src_address_drop(X) -> write("\nDropped SOURCE IP-Address " : X));
(ipv4_src_address_accept(X) -> write("\nAccepted SOURCE IP-Address " : X)).




ipv4_src_address_accept(X):-


(accept(_,_,_,[P|Q],_,_,_,_,_,_),
member(X,[P|Q]));

accept(_,_,_,L,_,_,_,_,_,_),string(L),
split_string(L,"-","",[S1|[S2|_]]),
split_string(S1,".","",[SS1|[SSS1|[SSSS1|[SSSSS1|_]]]]),
split_string(S2,".","",[SS2|[SSS2|[SSSS2|[SSSSS2|_]]]]),
split_string(X,".","",[XX1|[XXX1|[XXXX1|[XXXXX1|_]]]]),

string_concat(SS1,SSS1,T1),
string_concat(T1,SSSS1,TT1),
string_concat(TT1,SSSSS1,Tf1),

string_concat(SS2,SSS2,T2),
string_concat(T2,SSSS2,TT2),
string_concat(TT2,SSSSS2,Tf2),

string_concat(XX1,XXX1,T3),
string_concat(T3,XXXX1,TT3),
string_concat(TT3,XXXXX1,Tf3),

atom_number(Tf1,N1),
atom_number(Tf2,N2),
atom_number(Tf3,Xn),

between(N1,N2,Xn).


ipv4_src_address_reject(X):-


(reject(_,_,_,[P|Q],_,_,_,_,_,_),
member(X,[P|Q]));

reject(_,_,_,L,_,_,_,_,_,_),string(L),
split_string(L,"-","",[S1|[S2|_]]),
split_string(S1,".","",[SS1|[SSS1|[SSSS1|[SSSSS1|_]]]]),
split_string(S2,".","",[SS2|[SSS2|[SSSS2|[SSSSS2|_]]]]),
split_string(X,".","",[XX1|[XXX1|[XXXX1|[XXXXX1|_]]]]),

string_concat(SS1,SSS1,T1),
string_concat(T1,SSSS1,TT1),
string_concat(TT1,SSSSS1,Tf1),

string_concat(SS2,SSS2,T2),
string_concat(T2,SSSS2,TT2),
string_concat(TT2,SSSSS2,Tf2),

string_concat(XX1,XXX1,T3),
string_concat(T3,XXXX1,TT3),
string_concat(TT3,XXXXX1,Tf3),

atom_number(Tf1,N1),
atom_number(Tf2,N2),
atom_number(Tf3,Xn),

between(N1,N2,Xn).

ipv4_src_address_drop(X):-


(drop(_,_,_,[P|Q],_,_,_,_,_,_),
member(X,[P|Q]));

drop(_,_,_,L,_,_,_,_,_,_),string(L),
split_string(L,"-","",[S1|[S2|_]]),
split_string(S1,".","",[SS1|[SSS1|[SSSS1|[SSSSS1|_]]]]),
split_string(S2,".","",[SS2|[SSS2|[SSSS2|[SSSSS2|_]]]]),
split_string(X,".","",[XX1|[XXX1|[XXXX1|[XXXXX1|_]]]]),

string_concat(SS1,SSS1,T1),
string_concat(T1,SSSS1,TT1),
string_concat(TT1,SSSSS1,Tf1),

string_concat(SS2,SSS2,T2),
string_concat(T2,SSSS2,TT2),
string_concat(TT2,SSSSS2,Tf2),

string_concat(XX1,XXX1,T3),
string_concat(T3,XXXX1,TT3),
string_concat(TT3,XXXXX1,Tf3),

atom_number(Tf1,N1),
atom_number(Tf2,N2),
atom_number(Tf3,Xn),

between(N1,N2,Xn).


ipv4_dst_address(X):-
(ipv4_dst_address_reject(X) -> write("\nRejected DESTINATION IP-Address " : X));
(ipv4_dst_address_drop(X) -> write("\nDropped DESTINATION IP-Address " : X));
(ipv4_dst_address_accept(X) -> write("\nAccepted DESTINATION IP-Address " : X)).

ipv4_dst_address_accept(X):-


(accept(_,_,_,_,[P|Q],_,_,_,_,_),
member(X,[P|Q]));

accept(_,_,_,_,L,_,_,_,_,_),string(L),
split_string(L,"-","",[S1|[S2|_]]),
split_string(S1,".","",[SS1|[SSS1|[SSSS1|[SSSSS1|_]]]]),
split_string(S2,".","",[SS2|[SSS2|[SSSS2|[SSSSS2|_]]]]),
split_string(X,".","",[XX1|[XXX1|[XXXX1|[XXXXX1|_]]]]),

string_concat(SS1,SSS1,T1),
string_concat(T1,SSSS1,TT1),
string_concat(TT1,SSSSS1,Tf1),

string_concat(SS2,SSS2,T2),
string_concat(T2,SSSS2,TT2),
string_concat(TT2,SSSSS2,Tf2),

string_concat(XX1,XXX1,T3),
string_concat(T3,XXXX1,TT3),
string_concat(TT3,XXXXX1,Tf3),

atom_number(Tf1,N1),
atom_number(Tf2,N2),
atom_number(Tf3,Xn),

between(N1,N2,Xn).


ipv4_dst_address_reject(X):-


(reject(_,_,_,_,[P|Q],_,_,_,_,_),
member(X,[P|Q]));

reject(_,_,_,_,L,_,_,_,_,_),string(L),
split_string(L,"-","",[S1|[S2|_]]),
split_string(S1,".","",[SS1|[SSS1|[SSSS1|[SSSSS1|_]]]]),
split_string(S2,".","",[SS2|[SSS2|[SSSS2|[SSSSS2|_]]]]),
split_string(X,".","",[XX1|[XXX1|[XXXX1|[XXXXX1|_]]]]),

string_concat(SS1,SSS1,T1),
string_concat(T1,SSSS1,TT1),
string_concat(TT1,SSSSS1,Tf1),

string_concat(SS2,SSS2,T2),
string_concat(T2,SSSS2,TT2),
string_concat(TT2,SSSSS2,Tf2),

string_concat(XX1,XXX1,T3),
string_concat(T3,XXXX1,TT3),
string_concat(TT3,XXXXX1,Tf3),

atom_number(Tf1,N1),
atom_number(Tf2,N2),
atom_number(Tf3,Xn),

between(N1,N2,Xn).

ipv4_dst_address_drop(X):-


(drop(_,_,_,_,[P|Q],_,_,_,_,_),
member(X,[P|Q]));

drop(_,_,_,_,L,_,_,_,_,_),string(L),
split_string(L,"-","",[S1|[S2|_]]),
split_string(S1,".","",[SS1|[SSS1|[SSSS1|[SSSSS1|_]]]]),
split_string(S2,".","",[SS2|[SSS2|[SSSS2|[SSSSS2|_]]]]),
split_string(X,".","",[XX1|[XXX1|[XXXX1|[XXXXX1|_]]]]),

string_concat(SS1,SSS1,T1),
string_concat(T1,SSSS1,TT1),
string_concat(TT1,SSSSS1,Tf1),

string_concat(SS2,SSS2,T2),
string_concat(T2,SSSS2,TT2),
string_concat(TT2,SSSSS2,Tf2),

string_concat(XX1,XXX1,T3),
string_concat(T3,XXXX1,TT3),
string_concat(TT3,XXXXX1,Tf3),

atom_number(Tf1,N1),
atom_number(Tf2,N2),
atom_number(Tf3,Xn),

between(N1,N2,Xn).





icmp(icmp_type(X),icmp_message(Y)):-

icmp_type(X),icmp_message(Y).



icmp_type(X) :-
(reject_icmp_type(X) -> write("\nRejected ICMP type " : X));
(drop_icmp_type(X) -> write("\nDropped ICMP type " : X));
(accept_icmp_type(X) -> write("\nAccepted ICMP type " : X)).


accept_icmp_type(X):-

accept(_,_,_,_,_,_,_,[P|Q],_,_),member(X,[P|Q]);

(accept(_,_,_,_,_,_,_,L,_,_),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X>=W1,
X=<W2).

reject_icmp_type(X):-

reject(_,_,_,_,_,_,_,[P|Q],_,_),member(X,[P|Q]);

(reject(_,_,_,_,_,_,_,L,_,_),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X>=W1,
X=<W2).

drop_icmp_type(X):-

drop(_,_,_,_,_,_,_,[P|Q],_,_),member(X,[P|Q]);

(drop(_,_,_,_,_,_,_,L,_,_),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X>=W1,
X=<W2).


icmp_message(X):-
(reject_icmp_message(X) -> write("\nRejected ICMP Message "  :X));
(drop_icmp_message(X) -> write("\nDropped ICMP Message " : X));
(accept_icmp_message(X) -> write("\nAccepted ICMP Message " : X)).


accept_icmp_message(X):-

accept(_,_,_,_,_,_,_,_,[P|Q],_),member(X,[P|Q]).

reject_icmp_message(X):-

reject(_,_,_,_,_,_,_,_,[P|Q],_),member(X,[P|Q]).


drop_icmp_message(X):-

drop(_,_,_,_,_,_,_,_,[P|Q],_),member(X,[P|Q]).






%*****************************************************************To address IPV6 addresses***********************************************************


incoming_packet(adapterv6(P),ethernetv6(protocol_idv6(Q),vlan_no_v6(R)),ipv6(ipv6_src_address(A),ipv6_dst_address(B),tcp_udp_src_port_v6(C),tcp_udp_dst_port_v6(D),icmpv6(icmpv6_type(E),icmpv6_message(F)),ip_protocol_no_v6(G))):-
	
(adapterv6(P),
ethernetv6(protocol_idv6(Q),vlan_no_v6(R)),
ipv6(ipv6_src_address(A),
	ipv6_dst_address(B),
	tcp_udp_src_port_v6(C),
	tcp_udp_dst_port_v6(D),
	icmpv6(icmpv6_type(E),
	icmpv6_message(F)),
	ip_protocol_no_v6(G))),


(((rejected_adapterv6(P);
rejected_protocol_idv6(Q);
rejected_vlan_no_v6(R);
ipv6_src_address_reject(A);
ipv6_dst_address_reject(B);
rejected_tcp_udp_src_port_v6(C);
rejected_tcp_udp_dst_port_v6(D);
reject_icmpv6_type(E);
reject_icmpv6_message(F);
rejected_IP_protocol_no_v6(G)) -> write("\n\nPACKET REJECTED "));


((dropped_adapterv6(P);
dropped_protocol_idv6(Q);
dropped_vlan_no_v6(R);
ipv6_src_address_drop(A);
ipv6_dst_address_drop(B);
dropped_tcp_udp_src_port_v6(C);
dropped_tcp_udp_dst_port_v6(D);
drop_icmpv6_type(E);
drop_icmpv6_message(F);
dropped_IP_protocol_no_v6(G)) -> write("\n\nPACKET DROPPED"));

((allowed_adapterv6(P),
allowed_protocol_idv6(Q),
allowed_vlan_no_v6(R),
ipv6_src_address_accept(A),
ipv6_dst_address_accept(B),
allowed_tcp_udp_src_port_v6(C),
allowed_tcp_udp_dst_port_v6(D),
accept_icmpv6_type(E),
accept_icmpv6_message(F),
allowed_IP_protocol_no_v6(G)) -> write("\n\nPACKET ACCEPTED"))).

adapterv6(X):-

(X= "any")->  write("\nAccepted Adapter " : X );

((rejected_adapterv6(X)) -> write("\nRejected Adapter " : X));
(dropped_adapterv6(X) -> write("\nDropped Adapter " : X));
(allowed_adapterv6(X) -> write("\nAccepted Adapter " : X )).


allowed_adapterv6(X):- 

acceptv6([P|Q],_,_,_,_,_,_,_,_,_),member(X,[P|Q]);

(acceptv6(L,_,_,_,_,_,_,_,_,_),string(L),
(split_string(L,"-","",[H|[T|_]]),
X>=H,
X=<T)).

rejected_adapterv6(X):-

rejectv6([P|Q],_,_,_,_,_,_,_,_,_),member(X,[P|Q]);

(rejectv6(L,_,_,_,_,_,_,_,_,_),string(L),
split_string(L,"-","",[H|[T|_]]),
X>=H,
X=<T).

dropped_adapterv6(X):-

dropv6([P|Q],_,_,_,_,_,_,_,_,_),member(X,[P|Q]);

(dropv6(L,_,_,_,_,_,_,_,_,_),string(L),
split_string(L,"-","",[H|[T|_]]),
X>=H,
X=<T).



%_______________________


ethernetv6(protocol_idv6(P),vlan_no_v6(Q)):- 
vlan_no_v6(Q), 
protocol_idv6(P). 


protocol_idv6(X):-
(rejected_protocol_idv6(X) -> write("\nRejected Protocol-ID " : X));
(dropped_protocol_idv6(X) -> write("\nDropped Protocol-ID " : X));
(allowed_protocol_idv6(X) -> write("\nAccepted Protocol-ID " : X)).

allowed_protocol_idv6(X):-

acceptv6(_,[P|Q],_,_,_,_,_,_,_,_),member(X,[P|Q]);

(acceptv6(_,L,_,_,_,_,_,_,_,_),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X >= W1,
X =< W2).

rejected_protocol_idv6(X):-

rejectv6(_,[P|Q],_,_,_,_,_,_,_,_),member(X,[P|Q]);

(rejectv6(_,L,_,_,_,_,_,_,_,_),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X>=W1,
X =< W2).

dropped_protocol_idv6(X):-

dropv6(_,[P|Q],_,_,_,_,_,_,_,_),member(X,[P|Q]);

(dropv6(_,L,_,_,_,_,_,_,_,_),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X>=W1,
X=<W2).


vlan_no_v6(X):-
(rejected_vlan_no_v6(X) -> write("\nRejected VLAN No " : X ));
(dropped_vlan_no_v6(X) -> write("\nDropped VLAN No " : X));
(allowed_vlan_no_v6(X) -> write("\nAccepted  VLAN No " : X )).

allowed_vlan_no_v6(X):-

acceptv6(_,_,[P|Q],_,_,_,_,_,_,_),member(X,[P|Q]);

(acceptv6(_,_,L,_,_,_,_,_,_,_),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X>=W1,
X=<W2).


rejected_vlan_no_v6(X):-

rejectv6(_,_,[P|Q],_,_,_,_,_,_,_),member(X,[P|Q]);

(rejectv6(_,_,L,_,_,_,_,_,_,_),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X>=W1,
X=<W2).

dropped_vlan_no_v6(X):-

dropv6(_,_,[P|Q],_,_,_,_,_,_,_),member(X,[P|Q]);

(dropv6(_,_,L,_,_,_,_,_,_,_),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X>=W1,
X=<W2).



%_______________________



ipv6(ipv6_src_address(A),ipv6_dst_address(B),tcp_udp_src_port_v6(C),tcp_udp_dst_port_v6(D),icmpv6(icmpv6_type(E),icmpv6_message(F)),ip_protocol_no_v6(G)):-

 ipv6_src_address(A),
 ipv6_dst_address(B),
 tcp_udp_src_port_v6(C),
 tcp_udp_dst_port_v6(D),
 icmpv6(icmpv6_type(E),
 icmpv6_message(F)),
 ip_protocol_no_v6(G).


tcp_udp_src_port_v6(X):- 
(rejected_tcp_udp_src_port_v6(X) -> write("\nRejected TCP-UDP-Source Port " : X));
(dropped_tcp_udp_src_port_v6(X) -> write("\nDropped TCP-UDP-Source Port " : X));
(allowed_tcp_udp_src_port_v6(X) -> write("\nAccepted TCP-UDP-Source Port " : X)).

allowed_tcp_udp_src_port_v6(X):-

acceptv6(_,_,_,_,_,[P|Q],_,_,_,_),member(X,[P|Q]);

(acceptv6(_,_,_,_,_,L,_,_,_,_),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X>=W1,
X=<W2).


rejected_tcp_udp_src_port_v6(X):-

rejectv6(_,_,_,_,_,[P|Q],_,_,_,_),member(X,[P|Q]);

(rejectv6(_,_,_,_,_,L,_,_,_,_),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X>=W1,
X=<W2).

dropped_tcp_udp_src_port_v6(X):-

dropv6(_,_,_,_,_,[P|Q],_,_,_,_),member(X,[P|Q]);

(dropv6(_,_,_,_,_,L,_,_,_,_),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X>=W1,
X=<W2).



tcp_udp_dst_port_v6(X):- 
(rejected_tcp_udp_dst_port_v6(X) -> write("\nRejected TCP-UDP-DST Port " : X));
(dropped_tcp_udp_dst_port_v6(X) -> write("\nDropped TCP-UDP-DST Port " : X));
(allowed_tcp_udp_dst_port_v6(X) -> write("\nAccepted TCP-UDP-DST Port " : X)).


allowed_tcp_udp_dst_port_v6(X):-

acceptv6(_,_,_,_,_,_,[P|Q],_,_,_),member(X,[P|Q]);

(acceptv6(_,_,_,_,_,_,L,_,_,_),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X>=W1,
X=<W2).


rejected_tcp_udp_dst_port_v6(X):-

rejectv6(_,_,_,_,_,_,[P|Q],_,_,_),member(X,[P|Q]);

(rejectv6(_,_,_,_,_,_,L,_,_,_),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X>=W1,
X=<W2).

dropped_tcp_udp_dst_port_v6(X):-

dropv6(_,_,_,_,_,_,[P|Q],_,_,_),member(X,[P|Q]);

(dropv6(_,_,_,_,_,_,L,_,_,_),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X>=W1,
X=<W2).

ip_protocol_no_v6(X):-
(rejected_IP_protocol_no_v6(X) -> write("\nRejected IP-Protocol_No " : X));
(dropped_IP_protocol_no_v6(X) -> write("\nDropped IP-Protocol_No " : X));
(allowed_IP_protocol_no_v6(X) -> write("\nAccepted IP-Protocol_No " : X)).


allowed_IP_protocol_no_v6(X):-

acceptv6(_,_,_,_,_,_,_,_,_,[P|Q]),member(X,[P|Q]);

(acceptv6(_,_,_,_,_,_,_,_,_,L),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X>=W1,
X=<W2).


rejected_IP_protocol_no_v6(X):-

rejectv6(_,_,_,_,_,_,_,_,_,[P|Q]),member(X,[P|Q]);

(rejectv6(_,_,_,_,_,_,_,_,_,L),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X>=W1,
X=<W2).

dropped_IP_protocol_no_v6(X):-

dropv6(_,_,_,_,_,_,_,_,_,[P|Q]),member(X,[P|Q]);

(dropv6(_,_,_,_,_,_,_,_,_,L),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X>=W1,
X=<W2).



ipv6_src_address(X):-
(ipv6_src_address_reject(X) -> write("\nRejected SOURCE IP-Address " : X));
(ipv6_src_address_drop(X) -> write("\nDropped SOURCE IP-Address " : X));
(ipv6_src_address_accept(X) -> write("\nAccepted SOURCE IP-Address " : X)).

ipv6_src_address_accept(X):-

(acceptv6(_,_,_,[P|Q],_,_,_,_,_,_),
member(X,[P|Q]));

acceptv6(_,_,_,L,_,_,_,_,_,_),string(L),
split_string(L,"-","",[S1|[S2|_]]),
split_string(S1,":","",[SS1|[SSS1|[SSSS1|[SSSSS1|[SSSSSS1|[SSSSSSS1|[SSSSSSSS1|[SSSSSSSSS1|_]]]]]]]]),
split_string(S2,":","",[SS2|[SSS2|[SSSS2|[SSSSS2|[SSSSSS2|[SSSSSSS2|[SSSSSSSS2|[SSSSSSSSS2|_]]]]]]]]),
split_string(X,":","",[XX1|[XXX1|[XXXX1|[XXXXX1|[XXXXXX1|[XXXXXXX1|[XXXXXXXX1|[XXXXXXXXX1|_]]]]]]]]),

string_concat(SS1,SSS1,T1),
string_concat(T1,SSSS1,TT1),
string_concat(TT1,SSSSS1,TTT1),
string_concat(TTT1,SSSSSS1,TTTT1),
string_concat(TTTT1,SSSSSSS1,TTTTT1),
string_concat(TTTTT1,SSSSSSSS1,TTTTTT1),
string_concat(TTTTTT1,SSSSSSSSS1,Tf1),


string_concat(SS2,SSS2,T2),
string_concat(T2,SSSS2,TT2),
string_concat(TT2,SSSSS2,TTT2),
string_concat(TTT2,SSSSSS2,TTTT2),
string_concat(TTTT2,SSSSSSS2,TTTTT2),
string_concat(TTTTT2,SSSSSSSS2,TTTTTT2),
string_concat(TTTTTT2,SSSSSSSSS2,Tf2),

string_concat(XX1,XXX1,T3),
string_concat(T3,XXXX1,TT3),
string_concat(TT3,XXXXX1,TTT3),
string_concat(TTT3,XXXXXX1,TTTT3),
string_concat(TTTT3,XXXXXXX1,TTTTT3),
string_concat(TTTTT3,XXXXXXXX1,TTTTTT3),
string_concat(TTTTTT3,XXXXXXXXX1,Tf3),

hex(Tf1, N1),
hex(Tf2, N2),
hex(Tf3, Xn),


between(N1,N2,Xn).


ipv6_src_address_reject(X):-

(rejectv6(_,_,_,[P|Q],_,_,_,_,_,_),member(X,[P|Q]));

rejectv6(_,_,_,L,_,_,_,_,_,_),string(L),
split_string(L,"-","",[S1|[S2|_]]),
split_string(S1,":","",[SS1|[SSS1|[SSSS1|[SSSSS1|[SSSSSS1|[SSSSSSS1|[SSSSSSSS1|[SSSSSSSSS1|_]]]]]]]]),
split_string(S2,":","",[SS2|[SSS2|[SSSS2|[SSSSS2|[SSSSSS2|[SSSSSSS2|[SSSSSSSS2|[SSSSSSSSS2|_]]]]]]]]),
split_string(X,":","",[XX1|[XXX1|[XXXX1|[XXXXX1|[XXXXXX1|[XXXXXXX1|[XXXXXXXX1|[XXXXXXXXX1|_]]]]]]]]),

string_concat(SS1,SSS1,T1),
string_concat(T1,SSSS1,TT1),
string_concat(TT1,SSSSS1,TTT1),
string_concat(TTT1,SSSSSS1,TTTT1),
string_concat(TTTT1,SSSSSSS1,TTTTT1),
string_concat(TTTTT1,SSSSSSSS1,TTTTTT1),
string_concat(TTTTTT1,SSSSSSSSS1,Tf1),


string_concat(SS2,SSS2,T2),
string_concat(T2,SSSS2,TT2),
string_concat(TT2,SSSSS2,TTT2),
string_concat(TTT2,SSSSSS2,TTTT2),
string_concat(TTTT2,SSSSSSS2,TTTTT2),
string_concat(TTTTT2,SSSSSSSS2,TTTTTT2),
string_concat(TTTTTT2,SSSSSSSSS2,Tf2),

string_concat(XX1,XXX1,T3),
string_concat(T3,XXXX1,TT3),
string_concat(TT3,XXXXX1,TTT3),
string_concat(TTT3,XXXXXX1,TTTT3),
string_concat(TTTT3,XXXXXXX1,TTTTT3),
string_concat(TTTTT3,XXXXXXXX1,TTTTTT3),
string_concat(TTTTTT3,XXXXXXXXX1,Tf3),

hex(Tf1, N1),
hex(Tf2, N2),
hex(Tf3, Xn),

between(N1,N2,Xn).


ipv6_src_address_drop(X):-


(dropv6(_,_,_,[P|Q],_,_,_,_,_,_),member(X,[P|Q]));

dropv6(_,_,_,L,_,_,_,_,_,_),string(L),
split_string(L,"-","",[S1|[S2|_]]),
split_string(S1,":","",[SS1|[SSS1|[SSSS1|[SSSSS1|[SSSSSS1|[SSSSSSS1|[SSSSSSSS1|[SSSSSSSSS1|_]]]]]]]]),
split_string(S2,":","",[SS2|[SSS2|[SSSS2|[SSSSS2|[SSSSSS2|[SSSSSSS2|[SSSSSSSS2|[SSSSSSSSS2|_]]]]]]]]),
split_string(X,":","",[XX1|[XXX1|[XXXX1|[XXXXX1|[XXXXXX1|[XXXXXXX1|[XXXXXXXX1|[XXXXXXXXX1|_]]]]]]]]),

string_concat(SS1,SSS1,T1),
string_concat(T1,SSSS1,TT1),
string_concat(TT1,SSSSS1,TTT1),
string_concat(TTT1,SSSSSS1,TTTT1),
string_concat(TTTT1,SSSSSSS1,TTTTT1),
string_concat(TTTTT1,SSSSSSSS1,TTTTTT1),
string_concat(TTTTTT1,SSSSSSSSS1,Tf1),


string_concat(SS2,SSS2,T2),
string_concat(T2,SSSS2,TT2),
string_concat(TT2,SSSSS2,TTT2),
string_concat(TTT2,SSSSSS2,TTTT2),
string_concat(TTTT2,SSSSSSS2,TTTTT2),
string_concat(TTTTT2,SSSSSSSS2,TTTTTT2),
string_concat(TTTTTT2,SSSSSSSSS2,Tf2),

string_concat(XX1,XXX1,T3),
string_concat(T3,XXXX1,TT3),
string_concat(TT3,XXXXX1,TTT3),
string_concat(TTT3,XXXXXX1,TTTT3),
string_concat(TTTT3,XXXXXXX1,TTTTT3),
string_concat(TTTTT3,XXXXXXXX1,TTTTTT3),
string_concat(TTTTTT3,XXXXXXXXX1,Tf3),

hex(Tf1, N1),
hex(Tf2, N2),
hex(Tf3, Xn),

between(N1,N2,Xn).


ipv6_dst_address(X):-
(ipv6_dst_address_reject(X) -> write("\nRejected DESTINATION IP-Address " : X));
(ipv6_dst_address_drop(X) -> write("\nDropped DESTINATION IP-Address " : X));
(ipv6_dst_address_accept(X) -> write("\nAccepted DESTINATION IP-Address " : X)).

ipv6_dst_address_accept(X):-

(acceptv6(_,_,_,_,[P|Q],_,_,_,_,_),
member(X,[P|Q]));

acceptv6(_,_,_,L,_,_,_,_,_,_),string(L),
split_string(L,"-","",[S1|[S2|_]]),
split_string(S1,":","",[SS1|[SSS1|[SSSS1|[SSSSS1|[SSSSSS1|[SSSSSSS1|[SSSSSSSS1|[SSSSSSSSS1|_]]]]]]]]),
split_string(S2,":","",[SS2|[SSS2|[SSSS2|[SSSSS2|[SSSSSS2|[SSSSSSS2|[SSSSSSSS2|[SSSSSSSSS2|_]]]]]]]]),
split_string(X,":","",[XX1|[XXX1|[XXXX1|[XXXXX1|[XXXXXX1|[XXXXXXX1|[XXXXXXXX1|[XXXXXXXXX1|_]]]]]]]]),

string_concat(SS1,SSS1,T1),
string_concat(T1,SSSS1,TT1),
string_concat(TT1,SSSSS1,TTT1),
string_concat(TTT1,SSSSSS1,TTTT1),
string_concat(TTTT1,SSSSSSS1,TTTTT1),
string_concat(TTTTT1,SSSSSSSS1,TTTTTT1),
string_concat(TTTTTT1,SSSSSSSSS1,Tf1),


string_concat(SS2,SSS2,T2),
string_concat(T2,SSSS2,TT2),
string_concat(TT2,SSSSS2,TTT2),
string_concat(TTT2,SSSSSS2,TTTT2),
string_concat(TTTT2,SSSSSSS2,TTTTT2),
string_concat(TTTTT2,SSSSSSSS2,TTTTTT2),
string_concat(TTTTTT2,SSSSSSSSS2,Tf2),

string_concat(XX1,XXX1,T3),
string_concat(T3,XXXX1,TT3),
string_concat(TT3,XXXXX1,TTT3),
string_concat(TTT3,XXXXXX1,TTTT3),
string_concat(TTTT3,XXXXXXX1,TTTTT3),
string_concat(TTTTT3,XXXXXXXX1,TTTTTT3),
string_concat(TTTTTT3,XXXXXXXXX1,Tf3),

atom_number(Tf1,N1),
atom_number(Tf2,N2),
atom_number(Tf3,Xn),

between(N1,N2,Xn).


ipv6_dst_address_reject(X):-

(rejectv6(_,_,_,_,[P|Q],_,_,_,_,_),member(X,[P|Q]));

rejectv6(_,_,_,L,_,_,_,_,_,_),string(L),
split_string(L,"-","",[S1|[S2|_]]),
split_string(S1,":","",[SS1|[SSS1|[SSSS1|[SSSSS1|[SSSSSS1|[SSSSSSS1|[SSSSSSSS1|[SSSSSSSSS1|_]]]]]]]]),
split_string(S2,":","",[SS2|[SSS2|[SSSS2|[SSSSS2|[SSSSSS2|[SSSSSSS2|[SSSSSSSS2|[SSSSSSSSS2|_]]]]]]]]),
split_string(X,":","",[XX1|[XXX1|[XXXX1|[XXXXX1|[XXXXXX1|[XXXXXXX1|[XXXXXXXX1|[XXXXXXXXX1|_]]]]]]]]),

string_concat(SS1,SSS1,T1),
string_concat(T1,SSSS1,TT1),
string_concat(TT1,SSSSS1,TTT1),
string_concat(TTT1,SSSSSS1,TTTT1),
string_concat(TTTT1,SSSSSSS1,TTTTT1),
string_concat(TTTTT1,SSSSSSSS1,TTTTTT1),
string_concat(TTTTTT1,SSSSSSSSS1,Tf1),


string_concat(SS2,SSS2,T2),
string_concat(T2,SSSS2,TT2),
string_concat(TT2,SSSSS2,TTT2),
string_concat(TTT2,SSSSSS2,TTTT2),
string_concat(TTTT2,SSSSSSS2,TTTTT2),
string_concat(TTTTT2,SSSSSSSS2,TTTTTT2),
string_concat(TTTTTT2,SSSSSSSSS2,Tf2),

string_concat(XX1,XXX1,T3),
string_concat(T3,XXXX1,TT3),
string_concat(TT3,XXXXX1,TTT3),
string_concat(TTT3,XXXXXX1,TTTT3),
string_concat(TTTT3,XXXXXXX1,TTTTT3),
string_concat(TTTTT3,XXXXXXXX1,TTTTTT3),
string_concat(TTTTTT3,XXXXXXXXX1,Tf3),

atom_number(Tf1,N1),
atom_number(Tf2,N2),
atom_number(Tf3,Xn),

between(N1,N2,Xn).


ipv6_dst_address_drop(X):-


(dropv6(_,_,_,_,[P|Q],_,_,_,_,_),member(X,[P|Q]));

dropv6(_,_,_,L,_,_,_,_,_,_),string(L),
split_string(L,"-","",[S1|[S2|_]]),
split_string(S1,":","",[SS1|[SSS1|[SSSS1|[SSSSS1|[SSSSSS1|[SSSSSSS1|[SSSSSSSS1|[SSSSSSSSS1|_]]]]]]]]),
split_string(S2,":","",[SS2|[SSS2|[SSSS2|[SSSSS2|[SSSSSS2|[SSSSSSS2|[SSSSSSSS2|[SSSSSSSSS2|_]]]]]]]]),
split_string(X,":","",[XX1|[XXX1|[XXXX1|[XXXXX1|[XXXXXX1|[XXXXXXX1|[XXXXXXXX1|[XXXXXXXXX1|_]]]]]]]]),

string_concat(SS1,SSS1,T1),
string_concat(T1,SSSS1,TT1),
string_concat(TT1,SSSSS1,TTT1),
string_concat(TTT1,SSSSSS1,TTTT1),
string_concat(TTTT1,SSSSSSS1,TTTTT1),
string_concat(TTTTT1,SSSSSSSS1,TTTTTT1),
string_concat(TTTTTT1,SSSSSSSSS1,Tf1),


string_concat(SS2,SSS2,T2),
string_concat(T2,SSSS2,TT2),
string_concat(TT2,SSSSS2,TTT2),
string_concat(TTT2,SSSSSS2,TTTT2),
string_concat(TTTT2,SSSSSSS2,TTTTT2),
string_concat(TTTTT2,SSSSSSSS2,TTTTTT2),
string_concat(TTTTTT2,SSSSSSSSS2,Tf2),

string_concat(XX1,XXX1,T3),
string_concat(T3,XXXX1,TT3),
string_concat(TT3,XXXXX1,TTT3),
string_concat(TTT3,XXXXXX1,TTTT3),
string_concat(TTTT3,XXXXXXX1,TTTTT3),
string_concat(TTTTT3,XXXXXXXX1,TTTTTT3),
string_concat(TTTTTT3,XXXXXXXXX1,Tf3),

atom_number(Tf1,N1),
atom_number(Tf2,N2),
atom_number(Tf3,Xn),

between(N1,N2,Xn).



icmpv6(icmpv6_type(X),icmpv6_message(Y)):-

icmpv6_type(X),icmpv6_message(Y).



icmpv6_type(X) :-
(reject_icmpv6_type(X) -> write("\nRejected ICMPV6 type " : X));
(drop_icmpv6_type(X) -> write("\nDropped ICMPV6 type " : X));
(accept_icmpv6_type(X) -> write("\nAccepted ICMPV6 type " : X)).


accept_icmpv6_type(X):-

acceptv6(_,_,_,_,_,_,_,[P|Q],_,_),member(X,[P|Q]);

(acceptv6(_,_,_,_,_,_,_,L,_,_),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X>=W1,
X=<W2).

reject_icmpv6_type(X):-

rejectv6(_,_,_,_,_,_,_,[P|Q],_,_),member(X,[P|Q]);

(rejectv6(_,_,_,_,_,_,_,L,_,_),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X>=W1,
X=<W2).

drop_icmpv6_type(X):-

dropv6(_,_,_,_,_,_,_,[P|Q],_,_),member(X,[P|Q]);

(dropv6(_,_,_,_,_,_,_,L,_,_),string(L),
split_string(L,"-","",[H|[T|_]]),
atom_number(H,W1),
atom_number(T,W2),
X>=W1,
X=<W2).


icmpv6_message(X):-
(reject_icmpv6_message(X) -> write("\nRejected ICMPV6 Message "  :X));
(drop_icmpv6_message(X) -> write("\nDropped ICMPV6 Message " : X));
(accept_icmpv6_message(X) -> write("\nAccepted ICMPV6 Message " : X)).


accept_icmpv6_message(X):-

acceptv6(_,_,_,_,_,_,_,_,[P|Q],_),member(X,[P|Q]).

reject_icmpv6_message(X):-

rejectv6(_,_,_,_,_,_,_,_,[P|Q],_),member(X,[P|Q]).


drop_icmpv6_message(X):-

dropv6(_,_,_,_,_,_,_,_,[P|Q],_),member(X,[P|Q]).



%_______________________
