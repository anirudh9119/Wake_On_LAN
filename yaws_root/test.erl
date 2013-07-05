-module(test).
-compile(export_all).


%[I | O | P ] = L

string_to_list_of_tuples([],L) ->
	L;
string_to_list_of_tuples([I ,O | P],L) ->
		A = [{I,O}],
		B= lists:append(L,A) ,
		string_to_list_of_tuples(P,B).

