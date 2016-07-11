%% Google Cloud Messaging for Ejabberd
%% Created: 02/08/2015 by mrDoctorWho
%% License: MIT/X11

-module(mod_notification).
-author("Laslo@Primo.me").

-include("ejabberd.hrl").
-include("logger.hrl").
-include("jlib.hrl").

-behaviour(gen_mod).

-record(gcm_users, {user, gcm_key, last_seen}).
-record(offline_tokens, {resource, user, token, time, badge}).


-define(NS_GCM, "urn:xmpp:gcm:0").
-define(NS_APN, "urn:xmpp:apn:0").
-define(CONTENT_TYPE, "application/x-www-form-urlencoded;charset=UTF-8").


-export([start/2, stop/1, user_send_packet/4, iq/3]).

%% 114196@stackoverflow
-spec(url_encode(string()) -> string()).

escape_uri(S) when is_list(S) ->
    escape_uri(unicode:characters_to_binary(S));
escape_uri(<<C:8, Cs/binary>>) when C >= $a, C =< $z ->
    [C] ++ escape_uri(Cs);
escape_uri(<<C:8, Cs/binary>>) when C >= $A, C =< $Z ->
    [C] ++ escape_uri(Cs);
escape_uri(<<C:8, Cs/binary>>) when C >= $0, C =< $9 ->
    [C] ++ escape_uri(Cs);
escape_uri(<<C:8, Cs/binary>>) when C == $. ->
    [C] ++ escape_uri(Cs);
escape_uri(<<C:8, Cs/binary>>) when C == $- ->
    [C] ++ escape_uri(Cs);
escape_uri(<<C:8, Cs/binary>>) when C == $_ ->
    [C] ++ escape_uri(Cs);
escape_uri(<<C:8, Cs/binary>>) ->
    escape_byte(C) ++ escape_uri(Cs);
escape_uri(<<>>) ->
    "".

escape_byte(C) ->
    "%" ++ hex_octet(C).

hex_octet(N) when N =< 9 ->
    [$0 + N];
hex_octet(N) when N > 15 ->
    hex_octet(N bsr 4) ++ hex_octet(N band 15);
hex_octet(N) ->
    [N - 10 + $a].


url_encode(Data) ->
    url_encode(Data,"").

url_encode([],Acc) ->
    Acc;
url_encode([{Key,Value}|R],"") ->
    url_encode(R, escape_uri(Key) ++ "=" ++ escape_uri(Value));
url_encode([{Key,Value}|R],Acc) ->
    url_encode(R, Acc ++ "&" ++ escape_uri(Key) ++ "=" ++ escape_uri(Value)).



%% Send an HTTP request to Google APIs and handle the response
send([{Key, Value}|R], PUSH_URL) ->
	Header = [],
	Body = url_encode([{Key, Value}|R]),
	ssl:start(),
	application:start(inets),
	{ok, RawResponse} = httpc:request(post, {PUSH_URL, Header, ?CONTENT_TYPE, Body}, [], []),
	%% {{"HTTP/1.1",200,"OK"} ..}
	{{_, SCode, Status}, ResponseBody} = {element(1, RawResponse), element(3, RawResponse)},
	%% TODO: Errors 5xx
	case catch SCode of
		200 -> ?DEBUG("mod_notification: A message was sent", []);
		401 -> ?ERROR_MSG("mod_notification: ~s", [Status]);
		_ -> ?ERROR_MSG("mod_notification: ~s", [ResponseBody])
	end.

%% TODO: Define some kind of a shaper to prevent floods and the GCM API to burn out :/
%% Or this could be the limits, like 10 messages/user, 10 messages/hour, etc
message(From, To, Packet) ->
	Type = xml:get_tag_attr_s(<<"type">>, Packet),
	?INFO_MSG("Offline message ~s", [From]),
	case catch Type of 
		"normal" -> ok;
		_ ->
			%% Strings
			JFrom = jlib:jid_to_string(From#jid{user = From#jid.user, server = From#jid.server, resource = <<"">>}),
			JTo = jlib:jid_to_string(To#jid{user = To#jid.user, server = To#jid.server, resource = <<"">>}),
			ToUser = To#jid.user,
			ToServer = To#jid.server,

			Body = xml:get_path_s(Packet, [{elem, <<"body">>}, cdata]),

			%% Checking subscription
			{Subscription, _Groups} = 
				ejabberd_hooks:run_fold(roster_get_jid_info, ToServer, {none, []}, [ToUser, ToServer, From]),
			case Subscription of
				both ->
					case catch Body of
						<<>> -> ok; %% There is no body
						_ ->
							Result = mnesia:dirty_read(offline_tokens, {ToUser, ToServer}),
							case catch Result of 
								[] -> ?DEBUG("mod_notification: No such record found for ~s", [JTo]);
								[#offline_tokens{token = API_KEY}] ->
									Args = [{"registration_id", API_KEY}, {"data.message", Body}, {"data.source", JFrom}, {"data.destination", JTo}],
									send(Args, ejabberd_config:get_global_option(push_url, fun(V) -> V end))
							end
						end;
					_ -> ok
			end
	end.


iq(#jid{user = User, server = Server} = From, To, #iq{type = Type, sub_el = SubEl} = IQ) ->
	LUser = jlib:nodeprep(User),
	LServer = jlib:nameprep(Server),

	{MegaSecs, Secs, _MicroSecs} = now(),
	TimeStamp = MegaSecs * 1000000 + Secs,

	API_KEY = xml:get_tag_cdata(xml:get_subtag(SubEl, <<"key">>)),

	F = fun() -> mnesia:write(#offline_tokens{user={LUser, LServer}, token=API_KEY, time=TimeStamp}) end,

	case catch mnesia:dirty_read(offline_tokens, {LUser, LServer}) of
		[] ->
			mnesia:transaction(F),
			?DEBUG("mod_notification: New user registered ~s@~s", [LUser, LServer]);

		%% Record exists, the key is equal to the one we know
		[#offline_tokens{user={LUser, LServer}, token=API_KEY}] ->
			mnesia:transaction(F),
			?DEBUG("mod_notification: Updating time for user ~s@~s", [LUser, LServer]);

		%% Record for this key was found, but for another key
		[#offline_tokens{user={LUser, LServer}, token=_KEY}] ->
			mnesia:transaction(F),
			?DEBUG("mod_notification: Updating token for user ~s@~s", [LUser, LServer])
		end,
	
	IQ#iq{type=result, sub_el=[]}. %% We don't need the result, but the handler have to send something.


start(Host, Opts) -> 
	mnesia:create_table(offline_tokens, [{disc_copies, [node()]}, {attributes, record_info(fields, offline_tokens)}]),
	case catch ejabberd_config:get_global_option(push_url, fun(V) -> V end) of
		undefined -> ?ERROR_MSG("There is no PUSH URL set! The PUSH module won't work without the URL!", []);
		_ ->
			gen_iq_handler:add_iq_handler(ejabberd_local, Host, <<?NS_GCM>>, ?MODULE, iq, no_queue),
      gen_iq_handler:add_iq_handler(ejabberd_local, Host, <<?NS_APN>>, ?MODULE, iq, no_queue),
      ejabberd_hooks:add(user_send_packet, Host, ?MODULE, user_send_packet, 500),
			?INFO_MSG("mod_notification Has started successfully!", []),
			ok
		end.

should_send_notification(#xmlel{name = <<"message">>} = Pkt, LServer) ->
  case fxml:get_attr_s(<<"type">>, Pkt#xmlel.attrs) of
    <<"chat">> ->
      case fxml:get_subtag_cdata(Pkt, <<"body">>) of
        <<>> ->
          %% Empty body
          false;
        _ ->
          true
      end;
    _ ->
      false
  end.


user_send_packet(Pkt, C2SState, JID, Peer) ->
  LUser = JID#jid.luser,
  LServer = JID#jid.lserver,
  From = JID#jid.luser,
  case should_send_notification(Pkt, LServer) of
    true ->
      send_to_offline_resources(LUser, From, Pkt, LServer);
    false ->
      Pkt
  end.

send_to_offline_resources(LUser, From, Pkt, LServer) ->
  Body = fxml:get_subtag_cdata(Pkt, <<"body">>),
  MessageFormat = get_message_format(Pkt),
  MessageBody = get_body_text(From, MessageFormat, Body, Pkt),
  Message = #{"msg" => MessageBody, "from" => LUser, "type" => MessageFormat, "format" => "chat"},
  case catch ejabberd_sql:sql_query(
    LServer,
    ?SQL("select @(resource)s, @(token)s, @(badges)d from offline_tokens"
      " where username=%(Peer)s")) of
    {selected, Rows} ->
      lists:flatmap(
        fun({Resource, Token, Badges}) ->
          Args = [{"push", Token},
            {"message", Message},
            {"username", LUser},
            {"title", "PRIMO Message"},
            {"badge": Badges+1},
            {"category": "IM_ACTION"},
            {"body": Body}],
          send(Args, ejabberd_config:get_global_option(push_url, fun(V) -> V end)),
          update_badge(LServer, Resource, Badges+1)
        end, Rows);
    _Err ->
      []
  end.

update_badge(LServer, Resource, Badges) ->
  case catch ejabberd_sql:sql_query(
    LServer,
    ?SQL("update offline_tokens set"
    " badges=%(Badges)d"
    "where resource=%(Resource)s")) of
    {updated, _} ->
      ?DEBUG("Sucessfully update badge for resource ~s", [Resource]);
    _Err ->
      ?ERROR_MSG("There was a ERROR increasing badge for resource ~s", [Resource])
  end.

delete_resource(LServer, Resource, Badges) ->
  case catch ejabberd_sql:sql_query_t(
    ?SQL("delete from offline_tokens where "
    "resource=%(Resource)s")) of
    {updated, _} ->
      ?DEBUG("Sucessfully deleted offline_token for resource ~s", [Resource]);
    _Err ->
      ?ERROR_MSG("There was a ERROR deleteting offline_token for resource ~s", [Resource])
  end.

insert_offline_token(LServer, SUser, SResurce, SToken, STime, SBadges) ->
  case ejabberd_sql:sql_query(
    LServer,
    ?SQL("insert into offline_tokens (user, resource,"
    " token, time, badges) values ("
    "%(SUser)s, "
    "%(SResurce)s, "
    "%(SToken)s, "
    "%(STime)d, "
    "%(SBadges)d)")) of
    {updated, _} ->
      {ok};
    Err ->
      Err
  end.

get_message_format(Pkt) ->
  case fxml:get_subtag(Pkt, <<"message_format">>) of
    <<>> ->
    %% Empty
    "application/chat";
    {MessageFormat} ->
    case xml:get_subtag(MessageFormat, <<"format">>) of
      <<>> ->
        %% Empty body
        "application/chat";
      _ ->
        xml:get_subtag_cdata(MessageFormat, <<"format">>)
    end
  end.

get_body_text(From, MessageFormat, Body, Pkt) ->
  case MessageFormat of
    {"application/file_sharing"} ->
      From ++ " sent you a file";
    {"application/ping"} ->
      From ++ " pinged youe";
    {"announcement"} ->
      case fxml:get_subtag_cdata(Pkt, <<"subject">>) of
        <<>> ->
          %% Empty body
          From ++ Body;
        {Subject} -> Subject
      end;
    _ -> From ++ Body
  end.

stop(Host) -> ok.