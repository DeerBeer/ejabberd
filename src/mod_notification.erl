%% Push URL call for offline users for Ejabberd
%% Created: 08/07/2016 by Laslo@Primo.me
%% License: MIT/X11

-module(mod_notification).
-author("Laslo@Primo.me").

-compile([{parse_transform, ejabberd_sql_pt}]).

-include_lib("stdlib/include/ms_transform.hrl").
-include("ejabberd.hrl").
-include("logger.hrl").
-include("jlib.hrl").
-include("ejabberd_sql_pt.hrl").

-behaviour(gen_mod).

-define(NS_GCM, "urn:xmpp:gcm:0").
-define(NS_APN, "urn:xmpp:apn:0").
-define(CONTENT_TYPE, "application/json").
-define(PPS_URL, "https://aws-pns-dev-01.primo.me:3000/push/message").


-export([start/2, stop/1, user_send_packet/4, send_to_offline_resources/4, iq/3, user_offline/3, user_online/3, mod_opt_type/1]).

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
  url_encode(Data, "").

url_encode([], Acc) ->
  Acc;
url_encode([{Key, Value} | R], "") ->
  url_encode(R, escape_uri(Key) ++ "=" ++ escape_uri(Value));
url_encode([{Key, Value} | R], Acc) ->
  url_encode(R, Acc ++ "&" ++ escape_uri(Key) ++ "=" ++ escape_uri(Value)).

json_encode(Data) ->
  json_encode(Data, "").
json_encode([], Acc) ->
  Acc;
json_encode([{Key, Value} | R], "") ->
  ?INFO_MSG("Parsing KEY ~s", [Key]),
  case Key of
    "message" ->
      ?INFO_MSG("KEY ~s is array", [Key]),
      SubEl = json_encode(Value),
      ?INFO_MSG("Sub element is ~p", [SubEl]),
      json_encode(R, lists:append([",\"", Key, "\":{"] ,SubEl, ["}"]));
    _ ->
      ?INFO_MSG("KEY ~s, Value ~s is binary", [Key, Value]),
      json_encode(R, [",\"",Key, "\":\"" ,Value, "\""])

end;
json_encode([{Key, Value} | R], Acc) ->
  ?INFO_MSG("Parsing KEY ~s", [Key]),
  case Key of
    "message" ->
      ?INFO_MSG("KEY ~s is array", [Key]),
      SubEl = json_encode(Value),
      ?INFO_MSG("Previous result ~p", [Acc]),
      ?INFO_MSG("Sub element is ~p", [SubEl]),
      json_encode(R, lists:append(Acc, [",\"",Key, "\":{"] ,SubEl, ["}"]));
    _ ->
      ?INFO_MSG("KEY ~s, Value ~s is binary", [Key, Value]),
      json_encode(R, lists:append(Acc, [",\"",Key, "\":\"" ,Value, "\""))
  end.

mod_opt_type(push_url) -> fun(B) when is_binary(B) -> B end.

%% Send an HTTP request to Google APIs and handle the response
send([{Key, Value} | R], PUSH_URL) ->
  Header = [],
  Body = list_to_binary(["{" ,json_encode([{Key, Value} | R]) , "}"]),
  ?INFO_MSG("Generated body: ~s", [Body]),
  ssl:start(),
  application:start(inets),
  {ok, RawResponse} = httpc:request(post, {?PPS_URL, Header, ?CONTENT_TYPE, Body}, [], []),
  %% {{"HTTP/1.1",200,"OK"} ..}
  {{_, SCode, Status}, ResponseBody} = {element(1, RawResponse), element(3, RawResponse)},
  case catch SCode of
    200 -> ?INFO_MSG("mod_notification: A message was sent", []);
    401 -> ?ERROR_MSG("mod_notification: ~s", [Status]);
    _ -> ?ERROR_MSG("mod_notification: ~s", [ResponseBody])
  end.

iq(From,
    To,
    #iq{type = set, sub_el = SubEl} = IQ) ->
  LResource = From#jid.lresource,
  case {SubEl} of
    {#xmlel{name = <<"register">>}} ->
      ?INFO_MSG("Starting to process token IQ for resource ~s", [From#jid.lresource]),
      process_iq(From#jid.lresource, SubEl);
    {#xmlel{name = <<"unregister">>}} ->
      cache_tab:delete(resource_tokens, LResource,
        fun() -> ?INFO_MSG("IQ Token unregistered for Resource ~s", [LResource]) end);
    _ ->
      ?ERROR_MSG("Unknow element name for token IQ", [])
  end,
  IQ#iq{type = result, sub_el = []}. %% We don't need the result, but the handler have to send something.

process_iq(Resource, SubEl) ->
  LResource = jlib:resourceprep(Resource),
  case fxml:get_tag_attr(<<"regid">>, SubEl) of
    {Key, Token} -> cache_tab:insert(resource_tokens, LResource, Token,
      fun() -> ?INFO_MSG("Received Token ~s for Resource ~s", [Token, LResource]) end);
    _ ->
      case fxml:get_tag_attr(<<"token">>, SubEl) of
        {Key, Token} -> cache_tab:insert(resource_tokens, LResource, Token,
          fun() -> ?INFO_MSG("Caching Token ~s for Resource ~s", [Token, LResource]) end);
        _ ->
          ?ERROR_MSG("There is no PUSH URL set! The PUSH module won't work without the URL!", [])
      end
  end,
  ?INFO_MSG("Finished processing Token for Resource ~s", [LResource]).

start(Host, Opts) ->
  init_cache(Opts),
  case catch gen_mod:get_module_opt(Host, ?MODULE, push_url,
    fun(A) when is_binary(A) -> A end,
    "") of
    undefined -> ?ERROR_MSG("There is no PUSH URL set! The PUSH module won't work without the URL!", []);
    _ ->
      gen_iq_handler:add_iq_handler(ejabberd_sm, Host, <<?NS_GCM>>, ?MODULE, iq, no_queue),
      gen_iq_handler:add_iq_handler(ejabberd_sm, Host, <<?NS_APN>>, ?MODULE, iq, no_queue),
      ejabberd_hooks:add(user_send_packet, Host, ?MODULE, user_send_packet, 500),
      ejabberd_hooks:add(sm_register_connection_hook, Host, ?MODULE, user_online, 100),
      ejabberd_hooks:add(sm_remove_connection_hook, Host, ?MODULE, user_offline, 100),
      ?INFO_MSG("mod_notification Has started successfully on Host ~s", [Host]),
      ok
  end.

init_cache(Opts) ->
  MaxSize = gen_mod:get_opt(cache_size, Opts,
    fun(I) when is_integer(I), I > 0 -> I end,
    1000),
  LifeTime = gen_mod:get_opt(cache_life_time, Opts,
    fun(I) when is_integer(I), I > 0 -> I end,
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
  end;
should_send_notification(#xmlel{}, _LServer) ->
  false.


user_online(_SID, JID, _Info) ->
  delete_resource(JID#jid.lserver, JID#jid.lresource).

user_offline(_SID, JID, _Info) ->
  LResource = jlib:resourceprep(JID#jid.lresource),
  case cache_tab:lookup(resource_tokens, LResource,
    fun() ->
      ?INFO_MSG("Token search finished for Resource ~s", [LResource])
    end) of
    {ok, Token} ->
      TSinteger = p1_time_compat:system_time(micro_seconds),
      insert_offline_token(JID#jid.lserver, JID#jid.luser, LResource, Token, TSinteger, 1),
      cache_tab:delete(resource_tokens, LResource,
        fun() -> ?INFO_MSG("Token deleted for Resource ~s", [LResource]) end);
    error -> ?INFO_MSG("No Token for Resource ~s, error: ~s", [LResource, error])
  end.


user_send_packet(Pkt, C2SState, JID, Peer) ->
  LUser = JID#jid.luser,
  LServer = JID#jid.lserver,
  case should_send_notification(Pkt, LServer) of
    true ->
      send_to_offline_resources(LUser, Peer, Pkt, LServer),
      Pkt;
    false ->
      Pkt
  end.

send_to_offline_resources(LUser, Peer, Pkt, LServer) ->
  BarePeer = Peer#jid.luser,
  ?INFO_MSG("sending to ~s", [BarePeer]),
  Body = fxml:get_subtag_cdata(Pkt, <<"body">>),
  MessageFormat = get_message_format(Pkt),
  ChatBody = escape_uri(LUser) ++ ": " ++ escape_uri(Body),
  MessageBody = get_body_text(LUser, MessageFormat, ChatBody, Pkt),
  PushUrl = gen_mod:get_module_opt(LServer, ?MODULE, push_url, fun(A) -> A end, ""),
  ?INFO_MSG("push_url is ~s", [PushUrl]),
  case PushUrl of
    undefined ->  ?ERROR_MSG("There is no PUSH URL set! The PUSH module won't work without the URL!", []);
    _ ->
      case catch ejabberd_sql:sql_query(
        LServer,
        ?SQL("select @(resource)s, @(token)s, @(badges)d from offline_tokens"
        " where user=%(BarePeer)s")) of
        {selected, Rows} ->
          lists:flatmap(
            fun({Resource, Token, Badges}) ->

              MessageData = [{"msg", Body},
              {"from", LUser},
              {"type", MessageFormat},
              {"format", "chat"}],

              Args = [{"push", Token},
                {"message", MessageData},
                {"username", LUser},
                {"title", "PRIMO Message"},
                {"badge", integer_to_binary(Badges)},
                {"category", "IM_ACTION"},
                {"body", MessageBody}],
              send(Args, PushUrl),
              update_badge(LServer, Resource),
              Pkt
            end, Rows);
        _Err ->
          []
      end
  end.


update_badge(LServer, Resource) ->
  case catch ejabberd_sql:sql_query(
    LServer,
    ?SQL("update offline_tokens set"
    " badges=badges + 1 "
    "where resource=%(Resource)s")) of
    {updated, _} ->
      ?INFO_MSG("Sucessfully update badge for resource ~s", [Resource]);
    _Err ->
      ?ERROR_MSG("There was a ERROR increasing badge for resource ~s", [Resource])
  end.

delete_resource(LServer, Resource) ->
  case catch ejabberd_sql:sql_query(
    LServer,
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
    {MessageFormat} ->
      case xml:get_subtag_cdata(MessageFormat, <<"format">>) of
        {Format} -> Format;
        _ ->
          "application/chat"
      end;
    _ -> "application/chat"
  end.

get_body_text(From, MessageFormat, Body, Pkt) ->
  case MessageFormat of
    {"application/file_sharing"} ->
      escape_uri(From) ++ escape_uri(" sent you a file");
    {"application/ping"} ->
      escape_uri(From) ++ escape_uri(" pinged you");
    {"announcement"} ->
      case fxml:get_subtag_cdata(Pkt, <<"subject">>) of
        {Subject} -> Subject;
        _ -> Body
      end;
    _ -> Body
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