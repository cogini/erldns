%% Copyright (c) 2012-2018, DNSimple Corporation
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

%% @doc Worker module that asynchronously accepts a single DNS packet and
%% hands it to a worker process that has a set timeout.
-module(erldns_worker).

-include_lib("kernel/include/logger.hrl").

-include_lib("dns_erlang/include/dns.hrl").

-define(DEFAULT_UDP_PROCESS_TIMEOUT, 500).
-define(DEFAULT_TCP_PROCESS_TIMEOUT, 1000).

-behaviour(gen_server).

-export([start_link/1]).
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3
        ]).

-record(state, {worker_process_sup, worker_process}).

start_link(Args) ->
  gen_server:start_link(?MODULE, Args, []).

init([WorkerId]) ->
  {ok, WorkerProcessSup} = erldns_worker_process_sup:start_link([WorkerId]),
  WorkerProcess = lists:last(supervisor:which_children(WorkerProcessSup)),
  {ok, #state{worker_process_sup = WorkerProcessSup, worker_process = WorkerProcess}}.

handle_call(_Request, From, State) ->
  ?LOG_DEBUG("Received unexpected call (from: ~p)", [From]),
  {reply, ok, State}.

handle_cast({tcp_query, Socket, Bin}, State) ->
  % telemetry:execute([erldns, accepted], #{count => 1}, #{proto => tcp}),
  case handle_tcp_dns_query(Socket, Bin, {State#state.worker_process_sup, State#state.worker_process}) of
    ok ->
      {noreply, State};
    {error, timeout, NewWorkerPid} ->
      {Id, _, Type, Modules} = State#state.worker_process,
      {noreply, State#state{worker_process = {Id, NewWorkerPid, Type, Modules}}};
    Error ->
      % ?LOG_DEBUG("Error handling query: ~p", [Error]),
      telemetry:execute([erldns, error], #{count => 1},
                        #{reason => handle, detail => Error, bin => Bin, proto => tcp}),
      {noreply, State}
  end;
handle_cast({udp_query, Socket, Host, Port, Bin}, State) ->
  % telemetry:execute([erldns, accepted], #{count => 1}, #{proto => udp}),
  case handle_udp_dns_query(Socket, Host, Port, Bin, {State#state.worker_process_sup, State#state.worker_process}) of
    ok ->
      {noreply, State};
    {error, timeout, NewWorkerPid} ->
      {Id, _, Type, Modules} = State#state.worker_process,
      {noreply, State#state{worker_process = {Id, NewWorkerPid, Type, Modules}}};
    Error ->
      % ?LOG_DEBUG("Error handling query (address: ~p): ~p", [Host, Error]),
      telemetry:execute([erldns, error], #{count => 1},
                        #{reason => handle, detail => Error, host => Host, port => Port, bin => Bin, proto => udp}),
      {noreply, State}
  end;
handle_cast(_Msg, State) ->
  {noreply, State}.
handle_info(_Info, State) ->
  {noreply, State}.
terminate(_Reason, _State) ->
  ok.
code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

%% @doc Handle DNS query that comes in over TCP
-spec handle_tcp_dns_query(gen_tcp:socket(), iodata(), {pid(), term()}) -> ok | {error, timeout} | {error, timeout, pid()}.
handle_tcp_dns_query(Socket, <<_Len:16, Bin/binary>>, {WorkerProcessSup, WorkerProcess}) ->
  case inet:peername(Socket) of
    {ok, {Address, Port}} ->
      StartTime = os:system_time(microsecond),
      telemetry:execute([erldns, worker, start], #{count => 1},
                        #{host => Address, port => Port, proto => tcp}),
      Result = case Bin of
        <<>> ->
            % ?LOG_DEBUG("TCP empty request from ~p", [Address]),
            telemetry:execute([erldns, invalid], #{count => 1},
                              #{reason => empty, host => Address, port => Port}),
            ok;
        _ ->
          case erldns_decoder:decode_message(Bin) of
            {truncated, DecodedMessage, Rest} ->
              % ?LOG_DEBUG("TCP truncated request from ~s ~p ~p", [inet:ntoa(Address), DecodedMessage, Rest]),
              telemetry:execute([erldns, invalid], #{count => 1},
                                #{reason => truncated, host => Address, port => Port, bin => Bin, message => DecodedMessage, rest => Rest}),
              ok;
            {trailing_garbage, DecodedMessage, Rest} ->
              % ?LOG_DEBUG("TCP request with trailing garbage from ~s ~p ~p", [inet:ntoa(Address), DecodedMessage, Rest]),
              telemetry:execute([erldns, garbage], #{count => 1},
                                #{reason => trailing_garbage, host => Address, port => Port, bin => Bin, message => DecodedMessage, rest => Rest}),
              handle_decoded_tcp_message(DecodedMessage, Socket, Address, {WorkerProcessSup, WorkerProcess});
            {formerr, DecodedMessage, Rest} ->
              ?LOG_INFO("TCP invalid request from ~s ~p ~p", [inet:ntoa(Address), DecodedMessage, Rest]),
              telemetry:execute([erldns, invalid], #{count => 1},
                                #{reason => formerr, host => Address, port => Port, bin => Bin, message => DecodedMessage, rest => Rest}),
              ok;
            DecodedMessage ->
              ?LOG_DEBUG("TCP request from address ~s ~p ~p", [inet:ntoa(Address), DecodedMessage, Bin]),
              handle_decoded_tcp_message(DecodedMessage, Socket, Address, {WorkerProcessSup, WorkerProcess})
          end
      end,
      Duration = os:system_time(microsecond) - StartTime,
      telemetry:execute([erldns, worker, stop], #{duration => Duration},
                        #{host => Address, proto => tcp}),
      gen_tcp:close(Socket),
      Result;
    {error, Reason} ->
      telemetry:execute([erldns, invalid], #{count => 1},
                        #{reason => tcp, detail => Reason, proto => tcp})
  end;
handle_tcp_dns_query(Socket, BadPacket, _) ->
  telemetry:execute([erldns, invalid], #{count => 1}, #{reason => bad_packet, bin => BadPacket}),
  gen_tcp:close(Socket).
handle_decoded_tcp_message(#dns_message{qr = false} = DecodedMessage, Socket, Address, {WorkerProcessSup, {WorkerProcessId, WorkerProcessPid, _, _}}) ->
  % Query (0)
  try gen_server:call(WorkerProcessPid, {process, DecodedMessage, Socket, {tcp, Address}}, _Timeout = ?DEFAULT_TCP_PROCESS_TIMEOUT) of
    _ -> ok
  catch
    exit:{timeout, _} ->
      telemetry:execute([erldns, error], #{count => 1},
                        #{reason => timeout, host => Address, message => DecodedMessage}),
      handle_timeout(DecodedMessage, WorkerProcessSup, WorkerProcessId);
    Error:Reason ->
      ?LOG_INFO("TCP worker process crashed ~s ~p ~p ~p ~p", [inet:ntoa(Address), Error, Reason, DecodedMessage]),
      telemetry:execute([erldns, error], #{count => 1},
                        #{reason => exception, exception => Error, detail => Reason, host => Address, message => DecodedMessage}),
      {error, {Error, Reason}}
  end;

handle_decoded_tcp_message(#dns_message{qr = true} = DecodedMessage, _, Address, _) ->
  % Response (1)
  ?LOG_INFO("TCP dropping invalid request (not a question) ~s ~p", [inet:ntoa(Address), DecodedMessage]),
  telemetry:execute([erldns, invalid], #{count => 1},
                    #{reason => qr, host => Address, message => DecodedMessage}),
  % {error, not_a_question}
  ok;

handle_decoded_tcp_message(DecodedMessage, _, Address, _) ->
  ?LOG_INFO("TCP dropping invalid message ~s ~p", [inet:ntoa(Address), DecodedMessage]),
  telemetry:execute([erldns, invalid], #{count => 1},
                    #{reason => invalid, host => Address, message => DecodedMessage}),
  ok.


%% @doc Handle DNS query that comes in over UDP
-spec handle_udp_dns_query(gen_udp:socket(), gen_udp:ip(), inet:port_number(), binary(), {pid(), term()}) -> ok | {error, not_owner | timeout | inet:posix() | atom()} | {error, timeout, pid()}.
handle_udp_dns_query(Socket, Host, Port, Bin, {WorkerProcessSup, WorkerProcess}) ->
  % ?LOG_DEBUG("handle_udp_dns_query(~p ~p ~p)", [Socket, Host, Port]),
  StartTime = os:system_time(microsecond),
  telemetry:execute([erldns, worker, start], #{count => 1},
                    #{host => Host, port => Port, proto => udp}),
  Result = case erldns_decoder:decode_message(Bin) of
    {trailing_garbage, DecodedMessage, Rest} ->
      ?LOG_INFO("UDP message trailing garbage ~s ~d ~p ~p", [Host, Port, DecodedMessage, Rest]),
      % Invalid but not final disposition
      telemetry:execute([erldns, garbage], #{count => 1},
                        #{reason => trailing_garbage, host => Host, bin => Bin, message => DecodedMessage, rest => Rest}),
      handle_decoded_udp_message(DecodedMessage, Socket, Host, Port, {WorkerProcessSup, WorkerProcess});
    {formerr, DecodedMessage, Rest} ->
      ?LOG_INFO("UDP message invalid request ~s ~d ~p ~p", [inet:ntoa(Host), Port, DecodedMessage, Rest]),
      telemetry:execute([erldns, invalid], #{count => 1},
                        #{reason => formerr, host => Host, bin => Bin, message => DecodedMessage, rest => Rest}),
      ok;
    {truncated, DecodedMessage, Rest} ->
      ?LOG_INFO("UDP truncated request ~s ~d ~p ~p", [inet:ntoa(Host), Port, DecodedMessage, Rest]),
      telemetry:execute([erldns, invalid], #{count => 1},
                        #{reason => truncated, host => Host, bin => Bin, message => DecodedMessage, rest => Rest}),
      ok;
    DecodedMessage ->
      handle_decoded_udp_message(DecodedMessage, Socket, Host, Port, {WorkerProcessSup, WorkerProcess})
  end,
  Duration = os:system_time(microsecond) - StartTime,
  telemetry:execute([erldns, worker, stop], #{duration => Duration},
                    #{host => Host, port => Port, proto => udp}),
  Result.

-spec handle_decoded_udp_message(dns:message(), gen_udp:socket(), gen_udp:ip(), inet:port_number(), {pid(), term()}) ->
  ok | {error, not_owner | timeout | inet:posix() | atom()} | {error, timeout, term()}.
handle_decoded_udp_message(#dns_message{qr = false} = DecodedMessage, Socket, Host, Port, {WorkerProcessSup, {WorkerProcessId, WorkerProcessPid, _, _}}) ->
  % Query (0)
  try gen_server:call(WorkerProcessPid, {process, DecodedMessage, Socket, Port, {udp, Host}}, _Timeout = ?DEFAULT_UDP_PROCESS_TIMEOUT) of
    _ -> ok
  catch
    exit:{timeout, _} ->
      telemetry:execute([erldns, error], #{count => 1},
                        #{reason => timeout, host => Host, port => Port, message => DecodedMessage}),
      handle_timeout(DecodedMessage, WorkerProcessSup, WorkerProcessId);
    Error:Reason ->
      ?LOG_INFO("UDP worker process crashed ~s ~d ~p ~p)", [inet:ntoa(Host), Port, Error, Reason]),
      telemetry:execute([erldns, error], #{count => 1},
                        #{reason => exception, detail => Reason, host => Host, port => Port, message => DecodedMessage}),
      {error, {Error, Reason}}
  end;
handle_decoded_udp_message(#dns_message{qr = true} = DecodedMessage, _, Host, Port, _) ->
      % Response (1)
      ?LOG_INFO("UDP dropping invalid request (not a question) ~s ~d ~p", [inet:ntoa(Host), Port, DecodedMessage]),
      telemetry:execute([erldns, invalid], #{count => 1},
                        #{reason => qr, host => Host, port => Port, message => DecodedMessage}),
      % {error, not_a_question}
      ok;
handle_decoded_udp_message(DecodedMessage, _, Host, Port, _) ->
  ?LOG_INFO("UDP dropping invalid message ~s ~d ~p", [inet:ntoa(Host), Port, DecodedMessage]),
  telemetry:execute([erldns, invalid], #{count => 1},
                    #{reason => invalid, host => Host, port => Port, message => DecodedMessage}),
  ok.

-spec handle_timeout(dns:message(), pid(), term()) -> {error, timeout, term()} | {error, timeout}.
handle_timeout(DecodedMessage, WorkerProcessSup, WorkerProcessId) ->
  % ?LOG_DEBUG("Worker timeout (message: ~p)", [DecodedMessage]),

  _TerminateResult = supervisor:terminate_child(WorkerProcessSup, WorkerProcessId),
  % ?LOG_DEBUG("Terminate result: ~p", [TerminateResult]),

  case supervisor:restart_child(WorkerProcessSup, WorkerProcessId) of
    {ok, NewChild} ->
      {error, timeout, NewChild};
    {ok, NewChild, _Info} ->
      {error, timeout, NewChild};
    {error, Error} ->
      telemetry:execute([erldns, error], #{count => 1},
                        #{reason => restart_failed, detail => Error, message => DecodedMessage}),
      {error, timeout}
  end.
