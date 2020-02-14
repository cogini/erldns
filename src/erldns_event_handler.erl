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

%% @doc Application event handler implementation.
-module(erldns_event_handler).

-behavior(gen_event).

-export([
         init/1,
         handle_event/2,
         handle_call/2,
         handle_info/2,
         code_change/3,
         terminate/2
        ]).

-record(state, {servers_running = false}).

init(_Args) ->
  {ok, #state{}}.

handle_event(start_servers, State) ->
  case State#state.servers_running of
    false ->
      % Start up the UDP and TCP servers
      lager:info("Starting the UDP and TCP supervisor"),
      erldns_server_sup:start_link(),
      telemetry:execute([erldns, servers, started], 1),
      {ok, State#state{servers_running = true}};
    _ ->
      telemetry:execute([erldns, servers, started, already], 1),
      {ok, State}
  end;

handle_event({end_udp, [{host, _Host}]}, State) ->
  telemetry:execute([erldns, udp, request], 1),
  {ok, State};

handle_event({end_tcp, [{host, _Host}]}, State) ->
  telemetry:execute([erldns, tcp, request], 1),
  {ok, State};

handle_event({udp_error, Reason}, State) ->
  telemetry:execute([erldns, udp, error], 1, #{reason => Reason}),
  {ok, State};

handle_event({tcp_error, Reason}, State) ->
  telemetry:execute([erldns, tcp, error], 1, #{reason => Reason}),
  {ok, State};

handle_event({refused_response, Questions}, State) ->
  telemetry:execute([erldns, refused, response], 1),
  lager:debug("Refused response: ~p", [Questions]),
  {ok, State};

handle_event({empty_response, Message}, State) ->
  telemetry:execute([erldns, empty, response], 1),
  lager:info("Empty response: ~p", [Message]),
  {ok, State};

handle_event({dnssec_request, _Host, _Qname}, State) ->
  telemetry:execute([erldns, dnssec, request], 1),
  {ok, State};

handle_event(_Event, State) ->
  {ok, State}.

handle_call(_Message, State) ->
  {ok, ok, State}.

handle_info(_Message, State) ->
  {ok, State}.

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

terminate(_Reason, _State) ->
  ok.
