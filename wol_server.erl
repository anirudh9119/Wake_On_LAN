-module(wol_server).
-compile(export_all).
-vsn(1.0).
-author("Saurabh Barjatiya").
-description("This is a WOL server backend.  This server will register "
	     "itself with name wol_server and listen for WOL requests."
	     "After receiving requests it will call ether-wake "
	     "appropriately with received MAC and interface name").



start() ->
    Pid1=spawn(fun wol_server_loop/0),
    register(wol_server, Pid1),
    f013_packet_capture:start(),
    ok.

wol_server_loop() ->
    receive
	{send_wol, Sender, Eth1, MAC1} ->
	    String1 = io_lib:format("ether-wake -i ~p ~p",[Eth1, MAC1]),
	    String2 = lists:flatten(String1),
	    %io:format("~p~n",[String2]),
	    os:cmd(String2),
	    Sender ! ok,
	    wol_server_loop()
    end.
			  
