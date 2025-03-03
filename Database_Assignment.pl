/*1- adapter;*/				/*2- protocol;*/															/*3- vlan;*/		/*4-ip_src_address*/																			/*5-ip_dst_address*/																		/*6-tcp_udp_src_port*/			/*7-tcp_udp_dst_port*/			/*8-icmp type;*/		/*9-icmp message;*/																/*10-protocol_no*/

accept("A-D",           	["arp","aarp","atalk","ipx","mpls","netbui","pppoe","rarp","sna","xns"], 	[18],				["34.62.58.24"],																				"43.34.46.24-63.56.86.27",    																[12],    						[20,21],						[2],  					["Echo Reply accept"],                                  						[1]).
accept(["P","Q","R","Z"],	[10],																		"3-12",				"34.62.58.24-55.45.59.25",																		["254.46.5.34"],    																		"34-43",						"78-80",						[3,5],					["Redirect accept","Parameter Problem accept","Time Exceeded accept"],			"12-19").
accept(["T"],			 	"1-6",          															[21,22,24],			["192.45.54.2","192.126.23.87","172.46.68.2"], 													["90.87.89.43,23.67.34.34"],																[2,4],	  						[3,4],						"100-120",  			["Source Quench accept"],								  						[2,3,4]).
accept("any",				[1,2,8],																	[4],				["169.84.12.91"],																				["172.34.33.63"],																			[6,7,8],						[45],							[1,2,4],				["Unassigned accept","Source Quench accept"],									[23,27]).


reject(["X"],				[11,12],																	[24],				["192.45.54.2"],																				"34.34.33.63-45.62.58.25",																	[45],							[34,897],						[24],					["Information Request reject"],													[78,37]).
reject(["Y","Z"],			["atalk","ipx"],															"10-14",			["172.23.45.13","34.46.51.64"],																	["0.34.33.63","1.62.58.25"],																[46],							[22],							[180],					["Source Quench reject"],														"4-10").
reject("C-E",				["5-11"],																	[56,58],			"52.34.48.73-65.48.35.24",																		["62.34.33.63","72.62.58.25"],																[9],							"7-8",							"120-140",				["Echo Reply reject"],															[99]).


drop(["P"],					[6],																		[8],				["192.45.54.3"],																				["192.45.54.3","172.21.87.90"],																[32],							[35],							[33],					["Timestamp Request drop"],														[13]	).
drop(["D"],					[12],																		"57-59",			["192.45.54.3"],																				["192.45.54.3","172.21.87.90"],																[32],							[1],							[37],					["Information Request drop"],													"54-76"	).

		 
acceptv6("A-D",           	["arp","aarp","atalk","ipx","mpls","netbui","pppoe","rarp","sna","xns"], 	[18],				["2001:0000:9938:6668:1148:3311:1955:5113"],													["2001:0000:9938:6668:1148:3311:1955:5112"],    											[12],    						[20,21],						[2],  					["Echo Reply acceptv6"],                                  						[1]).
acceptv6(["P","Q","R","Z"],	[10],																		"3-12",				["2001:0000:9d38:6ab8:1c48:3a1c:a95a:b1c2"],													["2041:0000:130F:0000:0000:07C0:853A:140C"],    											"34-43",						"78-80",						[3,5],					["Redirect acceptv6","Parameter Problem acceptv6","Time Exceeded acceptv6"],	"12-19").
acceptv6(["T"],			 	"1-6",          															[21,22,24],			["2001:0000:9d38:6ab8:1c48:3a1c:a95a:b1c2","2041:0000:130F:0000:0000:07C0:853A:140B"], 			["2001:0000:9d38:6ab8:1c48:3a1c:a95a:b1c3","2041:0000:130F:0000:0000:07C0:853A:140C"],		[2,4],	  						[3,4],						"100-120",  			["Source Quench acceptv6"],								  						[2,3,4]).
acceptv6("any",				[1,2,8],																	[4],				["2001:0000:9d38:6ab8:1c48:3a1c:a95a:b1c2"],													["2041:0000:130F:0000:0000:07C0:853A:140C"],												[6,7,8],						[45],							[1,2,4],				["Unassigned acceptv6","Source Quench acceptv6"],								[23,27]).


rejectv6(["X"],				[11,12],																	[24],				["2001:0000:9d38:6ab8:1c48:3a1c:a95a:b1c3"],													["2001:0000:9d38:6ab8:1c48:3a1c:a95a:b1c2"],												[45],							[34,897],						[24],					["Information Request rejectv6"],												[78,37]).
rejectv6(["Y","Z"],			["atalk","ipx"],															"10-14",			["2001:0000:9d38:6ab8:1c48:3a1c:a95a:b1c3","2041:0000:130F:0000:0000:07C0:853A:140C"],			["2041:0000:130F:0000:0000:07C0:853A:140B"],												[46],							[22],							[180],					["Source Quench rejectv6"],														"4-10").
rejectv6("C-E",				["5-11"],																	[56,58],			["2001:0000:9d38:6ab8:1c48:3a1c:a95a:b1c3"],													["2001:0000:9d38:6ab8:1c48:3a1c:a95a:b1c2"],												[9],							"7-8",							"120-140",				["Echo Reply rejectv6"],														[99]).


dropv6(["P"],				[6],																		[8],				["2001:0000:9d38:6ab8:1c48:3a1c:a95a:b1c3","2041:0000:130F:0000:0000:07C0:853A:140C"],			["2001:0000:9d38:6ab8:1c48:3a1c:a95a:b1c2","2041:0000:130F:0000:0000:07C0:853A:140B"],		[32],							[35],							[33],					["Timestamp Request dropv6"],													[13]	).
dropv6(["D"],				[12],																		"57-59",			["2001:0000:9d38:6ab8:1c48:3a1c:a95a:b1c3"],													["2001:0000:9d38:6ab8:1c48:3a1c:a95a:b1c2"],												[32],							[1],							[37],					["Information Request dropv6"],													"54-76"	).



