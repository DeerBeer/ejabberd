%% Google Cloud Messaging for Ejabberd
%% Created: 02/08/2015 by Laslo@Primo.me
%% License: MIT/X11

-module(mod_notification).
-author("Laslo@Primo.me").

-compile([{parse_transform, ejabberd_sql_pt}]).

-include_lib("stdlib/include/ms_transform.hrl").
-include("ejabberd.hrl").
-include("logger.hrl").
-include("jlib.hrl").
-include("ejabberd_sql_pt.hrl").
-include("mod_notification.hrl").

-behaviour(gen_mod).

-record(gcm_users, {user, gcm_key, last_seen}).
-record(offline_tokens, {resource, user, token, time, badge}).


-define(NS_GCM, "urn:xmpp:gcm:0").
-define(NS_APN, "urn:xmpp:apn:0").
-define(CONTENT_TYPE, "application/x-www-form-urlencoded;charset=UTF-8").


-export([start/2, stop/1, user_send_packet/4, iq/3, user_offline/3, user_online/3]).

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
	case catch SCode of
		200 -> ?INFO_MSG("mod_notification: A message was sent", []);
		401 -> ?ERROR_MSG("mod_notification: ~s", [Status]);
		_ -> ?ERROR_MSG("mod_notification: ~s", [ResponseBody])
	end.

iq(#jid{resource = LResource},
    #jid{lserver = LServer},
    #iq{type = get, sub_el = #xmlel{name = <<"register">>}} = IQ) ->
  process_iq(LResource, IQ).

process_iq(Resource, #iq{sub_el = #xmlel{attrs = Attrs}} = IQ) ->
  LResource = jlib:resourceprep(Resource),

  case fxml:get_attr_s(<<"regid">>, Attrs) of
    <<>> ->
      case fxml:get_attr_s(<<"token">>, Attrs) of
        <<>> ->
          ?ERROR_MSG("There is no PUSH URL set! The PUSH module won't work without the URL!", []);
        {Token}-> cache_tab:insert(tab_name, LResource, Token,
          fun() -> ?INFO_MSG("Received Token ~s for Resource ~s", [Token, LResource]) end)
      end;
    {Token}-> cache_tab:insert(tab_name, LResource, Token,
      fun() -> ?INFO_MSG("Received Token ~s for Resource ~s", [Token, LResource]) end)
  end,

  IQ#iq{type=result, sub_el=[]}. %% We don't need the result, but the handler have to send something.

start(Host, Opts) ->
  init_cache(Opts),
  case catch gen_mod:get_module_opt(Host, ?MODULE, push_url,
      fun(A) when is_binary(A) -> A end,
      "") of
		undefined -> ?ERROR_MSG("There is no PUSH URL set! The PUSH module won't work without the URL!", []);
		_ ->
			gen_iq_handler:add_iq_handler(ejabberd_local, Host, <<?NS_GCM>>, ?MODULE, iq, no_queue),
      gen_iq_handler:add_iq_handler(ejabberd_local, Host, <<?NS_APN>>, ?MODULE, iq, no_queue),
      ejabberd_hooks:add(user_send_packet, Host, ?MODULE, user_send_packet, 500),
      ejabberd_hooks:add(sm_register_connection_hook, Host, ?MODULE, user_online, 100),
      ejabberd_hooks:add(sm_remove_connection_hook, Host, ?MODULE, user_offline, 100),
			?INFO_MSG("mod_notification Has started successfully!", []),
			ok
		end.

init_cache(Opts) ->
  MaxSize = gen_mod:get_opt(cache_size, Opts,
    fun(I) when is_integer(I), I>0 -> I end,
    1000),
  LifeTime = gen_mod:get_opt(cache_life_time, Opts,
    fun(I) when is_integer(I), I>0 -> I end,
    timer:hours(1) div 1000),
  cache_tab:new(resource_tokens, [{max_size, MaxSize},
    {life_time, LifeTime}]).

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

user_online(_SID, JID, _Info) ->
  delete_resource(JID#jid.lserver, JID#jid.lresource).

user_offline(_SID, JID, _Info) ->
  LResource = JID#jid.lresource,
  case cache_tab:lookup(archive_prefs, LResource,
    fun() ->
      ?INFO_MSG("Found Token for Resource ~s", [LResource])
    end) of
    {ok, Token} ->
      TSinteger = p1_time_compat:system_time(micro_seconds),
      insert_offline_token(JID#jid.lserver, JID#jid.luser, LResource, Token, TSinteger, 0);
    _ -> ?INFO_MSG("No Token for Resource ~s", [LResource])
  end.


user_send_packet(Pkt, C2SState, JID, Peer) ->
  LUser = JID#jid.luser,
  LServer = JID#jid.lserver,
  From = JID#jid.luser,
  case should_send_notification(Pkt, LServer) of
    true ->
      send_to_offline_resources(LUser, Peer, Pkt, LServer);
    false ->
      Pkt
  end.

send_to_offline_resources(LUser, Peer, Pkt, LServer) ->
  Body = fxml:get_subtag_cdata(Pkt, <<"body">>),
  MessageFormat = get_message_format(Pkt),
  MessageBody = get_body_text(LUser, MessageFormat, Body, Pkt),
  Message = #{"msg" => MessageBody, "from" => LUser, "type" => MessageFormat, "format" => "chat"},
  PushUrl = case gen_mod:get_module_opt(Host, ?MODULE, push_url, fun(A) when is_binary(A) -> A end, "") of
    undefined -> ERROR_MSG("There is no PUSH URL set! The PUSH module won't work without the URL!", []);
    {PushUrl} -> PushUrl
  end,
  case catch ejabberd_sql:sql_query(
    LServer,
    ?SQL("select @(resource)s, @(token)s, @(badges)d from offline_tokens"
      " where username=%(Peer)s")) of
    {selected, Rows} ->
      lists:flatmap(
        fun({Resource, Token, Badges}) ->
          Badges = Badges+1,
          Args = [{"push", Token},
            {"message", Message},
            {"username", LUser},
            {"title", "PRIMO Message"},
            {"badge", Badges},
            {"category", "IM_ACTION"},
            {"body", Body}],
          send(Args, PushUrl),
          update_badge(LServer, Resource, Badges)
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
      ?INFO_MSG("Sucessfully update badge for resource ~s", [Resource]);
    _Err ->
      ?ERROR_MSG("There was a ERROR increasing badge for resource ~s", [Resource])
  end.

delete_resource(LServer, Resource) ->
  case catch ejabberd_sql:sql_query_t(
    ?SQL("delete from offline_tokens where "
    "resource=%(Resource)s")) of
    {updated, _} ->
      ?INFO_MSG("Sucessfully deleted offline_token for resource ~s", [Resource]);
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

stop(Host) ->
  ejabberd_hooks:delete(user_send_packet, Host, ?MODULE,
    user_send_packet, 500),
  ejabberd_hooks:delete(sm_register_connection_hook, Host, ?MODULE,
    user_online, 100),
  ejabberd_hooks:delete(sm_remove_connection_hook, Host, ?MODULE,
    user_offline, 100),
  gen_iq_handler:remove_iq_handler(ejabberd_local, Host, ?NS_GCM),
  gen_iq_handler:remove_iq_handler(ejabberd_local, Host, ?NS_GCM),
  ok.