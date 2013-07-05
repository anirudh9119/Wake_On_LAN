-module(f013_packet_capture).
-export([start/0, stop/0]).
-vsn(1.0).
-author("Saurabh Barjatiya").
-description("This example is implementation of connected process for port which can help in "
		" capturing packets via libpcap and send them to erlang process for processing.").


%This function starts packet capturing port
start() ->
	case os:getenv("USER") of
		"root" -> ok;
		_ -> 
			io:format("This program must be run as root user so that it can start port program "
					"f013_packet_capture.out as root for capturing packets.~n"),
			error("Not run as root")
	end,
	case whereis(pcapture_handler) of
		undefined ->
			spawn(fun() ->
					register(pcapture_handler, self()),
					process_flag(trap_exit, true),
					Port=open_port({spawn, "./f013_packet_capture.out"}, [{packet, 4}]),
					loop(Port,true)
				end);
		_Pid1 -> 
			io:format("Cannot start server, already running.~n"),
			error
	end.


%This function can be used to stop the port
stop() ->
	case whereis(pcapture_handler) of
		undefined ->
			io:format("Server not started. Cannot stop.~n"),
			error;
		_Pid1 -> 
			pcapture_handler ! stop
	end.



%%%This is the main receive loop of connected process.
%%%@spec (Port, Flag) -> ok Here if Flag is true the we need
%%%to send a command to port to indicate we are ready to
%%%receive next packet.  However if flag is false then we
%%%should not send any command as a command might have been
%%%sent already.
loop(Port, Flag1) ->
    %%We send 1 to indicate that we want to continue receiving
    %%more packets. The code should work even if we do not
    %%send this single byte. Note that since packet has four byte
    %%packet length header, sending one byte would result in to
    %%sending five bytes to port program.
    if
	Flag1 ->  Port ! {self(), {command, [1]}};
	Flag1 =:= false -> ok
    end,
    receive 
	{lookup, Sender, MACAddress} ->
	    Sender ! get(MACAddress),
	    loop(Port, false);

	{Port, {data, PacketNumberData}} ->
	    PacketNumber=decode(PacketNumberData),
	    %% io:format("Received PacketNumber as ~p.~n", [PacketNumber]),
	    receive	
		{Port, {data, SecondsData}} -> 
		    _Seconds=decode(SecondsData)
	    end,
	    %%			io:format("Received seconds as ~p.~n", [_Seconds]),
	    receive
		{Port, {data, MicrosecondsData}} ->
		    _Microseconds=decode(MicrosecondsData)
	    end,
						%			io:format("Received Microseconds as ~p.~n", [_Microseconds]),
	    receive
		{Port, {data, PacketLengthData}} ->
		    _PacketLength=decode(PacketLengthData)
	    end,
	    %% io:format("Received PacketLength as ~p.~n", [_PacketLength]),
	    receive
		{Port, {data, EncodedPacketDataList}} ->
		    EncodedPacketDataList
	    end,
	    %% io:format("Received ~p bytes of packet data~n", [length(EncodedPacketDataList)]),
	    PacketDataList=lists:sublist(EncodedPacketDataList, length(EncodedPacketDataList)-1),
	    %%io:format("~p. Packet Data : ~p~n", [PacketNumber, PacketDataList]),
	    PacketDataBinary=list_to_binary(PacketDataList),
	    analyze_packet(PacketNumber, PacketDataBinary),
	    loop(Port, true);

	stop ->
	    Port ! {self(), close},
	    receive
		{Port, closed} ->
		    exit(normal)
	    end;

	{'EXIT', Port, Reason} ->
	    io:format("Port closed as ~p.~n", [Reason]),
	    exit({port_terminated, Reason})
    end.


decode(Number) ->
	Length=length(Number),
	Last_value=lists:nth(Length, Number),
	if 
		Last_value =/= 0 -> 
			io:format("Last byte of received encoded number was not zero~n", []),
			DecodedNumber=Number;

		true ->
			DecodedNumber=(Number -- [0])
	end,
	list_to_integer(DecodedNumber).

	
analyze_packet(PacketNumber, PacketDataBinary) ->
    <<_DestinationMAC:48,
      _SourceMAC:48,
      _ExtraBytes:16,
      EtherType:16,
      EthernetPayload/binary>> = PacketDataBinary,
    if 
	EtherType =:= 16#0806 ->
	    analyze_arp_packet(PacketNumber,
			       EthernetPayload);

	true -> ok
    end. 





analyze_arp_packet(PacketNumber, EthernetPayload) ->
    case EthernetPayload of
	<<1:16,  %%Hardware type = Ethernet  (0001)
	  16#0800:16,  %%Protocol type = IP (0800)
	  6:8, %%Hardware size = 6 
	  4:8, %%Protocol size = 4
	  _Opcode:16,
	  SenderMACAddress:48,
	  SA1:8, SA2:8, SA3:8, SA4:8,
	  _TargetMACAddress:48,
	  _TargetIPAddress:32,
	  _RestData/binary>> ->
	    %% io:format("~p. Sender MAC is ~.16B ~n", [PacketNumber, SenderMACAddress]),
	    %% io:format("~p. Sender IP is ~p.~p.~p.~p ~n", [PacketNumber, SA1, SA2, SA3, SA4]),
	    put(SenderMACAddress, {SA1, SA2, SA3, SA4}),
	    void;

	EthernetPayload -> 
	    io:format("~p. Incorrectly formed IPv4 packet~n", [PacketNumber])
    end.


