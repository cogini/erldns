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

%% @doc The erldns OTP application.
-module(erldns_app).
-behavior(application).

-include_lib("kernel/include/logger.hrl").

% Application hooks
-export([start/2, start_phase/3, stop/1]).

start(_Type, _Args) ->
  ?LOG_INFO("Starting erldns application"),

  % erldns_telemetry:init(),
  erldns_metrics:init(),

  erldns_sup:start_link().

start_phase(post_start, _StartType, _PhaseArgs) ->
  erldns_events:add_handler(erldns_event_handler),

  case application:get_env(erldns, custom_zone_parsers) of
    {ok, Parsers} -> erldns_zone_parser:register_parsers(Parsers);
    _ -> ok
  end,

  case application:get_env(erldns, custom_zone_encoders) of
    {ok, Encoders} -> erldns_zone_encoder:register_encoders(Encoders);
    _ -> ok
  end,

  ?LOG_INFO("Loading zones from local file"),
  erldns_zone_loader:load_zones(),

  ?LOG_INFO("Notifying servers to start"),
  erldns_events:notify({?MODULE, start_servers}),

  ok.

stop(_State) ->
  ?LOG_INFO("Stop erldns application"),
  ok.
