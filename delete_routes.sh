#!/usr/bin/env escript

main(_Args) ->
    Route1 = os:cmd("route -n"),
    Route2 = string:tokens(Route1, "\n"),
    Route3 = lists:map(fun(Line1) ->
			       string:tokens(Line1, " \t")
		       end,
		       Route2),
    Route4 = lists:filter(fun(List1) ->
				  [H1 | _T1] = List1,
				  [X1, Y1 | _ ] = H1,
				  if 
				      [X1, Y1] =:= "10" -> true;
				      true -> false
				  end
			  end,
			  Route3),
    delete_routes(Route4, "10.4.4.0"),
    ok.


delete_routes([], _ ) -> ok;
delete_routes([H1 | T1], Exception1) ->
    [Network1, _Gw1, Mask1 | _T2] = H1,
    if 
	Network1 =:= Exception1 ->
	    ok;
	true ->
	    if
		Mask1 =:= "255.255.255.0" ->
		    Mask2="24";
		Mask1 =:= "255.255.254.0" ->
		    Mask2="23";
		Mask1 =:= "255.255.252.0" ->
		    Mask2="22";
		true ->
		    io:format("Error unsupported mask ~p. Exiting~n", [Mask1]),
		    init:stop(),
		    Mask2=""
	    end,
	    Command1=io_lib:format("route del -net ~s/~s", [Network1,Mask2]),
	    Command2=lists:flatten(Command1),
	    io:format("~s~n", [Command2]),
	    os:cmd(Command2)
    end,
    delete_routes(T1, Exception1).
		    
    
