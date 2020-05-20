%% @doc Telemetry handler which records metrics.
-module(erldns_metrics).

-include_lib("kernel/include/logger.hrl").

-export([init/0, handle_event/4]).

%% @doc Handle telemetry events.

handle_event([erldns, request], _Measurements, #{proto := udp}, _Config) ->
  folsom_metrics:notify({udp_request_meter, 1}),
  folsom_metrics:notify({udp_request_counter, {inc, 1}});

handle_event([erldns, request], _Measurements, #{proto := tcp}, _Config) ->
  folsom_metrics:notify({tcp_request_meter, 1}),
  folsom_metrics:notify({tcp_request_counter, {inc, 1}});

handle_event([erldns, dnssec, request], _Measurements, _MetaData, _Config) ->
  folsom_metrics:notify(dnssec_request_counter, {inc, 1}),
  folsom_metrics:notify(dnssec_request_meter, 1);

handle_event([erldns, error], _Measurements,
             #{reason := resolve}, _Config) ->
  folsom_metrics:notify({erldns_handler_error_counter, {inc, 1}}),
  folsom_metrics:notify({erldns_handler_error_meter, 1});

handle_event([erldns, error], _Measurements,
             #{reason := tcp, detail := Detail}, _Config) ->
  folsom_metrics:notify({tcp_error_meter, 1}),
  folsom_metrics:notify({tcp_error_history, Detail});

handle_event([erldns, error], _Measurements,
             #{reason := handle, detail := Detail, proto := tcp}, _Config) ->
  folsom_metrics:notify({tcp_error_meter, 1}),
  folsom_metrics:notify({tcp_error_history, Detail});

handle_event([erldns, error], _Measurements,
             #{reason := handle, detail := Detail, proto := udp}, _Config) ->
  folsom_metrics:notify({udp_error_meter, 1}),
  folsom_metrics:notify({udp_error_history, Detail});

handle_event([erldns, error], _Measurements, #{reason := timeout}, _Config) ->
  folsom_metrics:notify({worker_timeout_counter, {inc, 1}}),
  folsom_metrics:notify({worker_timeout_meter, 1});

handle_event([erldns, refused], _Measurements, _MetaData, _Config) ->
  folsom_metrics:new_meter(refused_response_meter),
  folsom_metrics:new_counter(refused_response_counter);

handle_event([erldns, empty], _Measurements, _MetaData, _Config) ->
  folsom_metrics:new_meter(empty_response_meter),
  folsom_metrics:new_counter(empty_response_counter);

handle_event(EventName, Measurements, Metadata, _Config) ->
  ?LOG_ERROR("~p ~p ~p", [EventName, Measurements, Metadata]).

%% @doc Initialize event handler.
init() ->
  ?LOG_INFO("Initializing Telemetry event handler for metrics"),
  create_metrics(),

  Events = [
    [erldns, dnssec, request],
    [erldns, empty],
    [erldns, error],
    [erldns, refused],
    [erldns, request]
  ],
  telemetry:attach_many(?MODULE, Events, fun ?MODULE:handle_event/4, #{}).

create_metrics() ->
  ?LOG_DEBUG("Creating Folsom metrics"),
  folsom_metrics:new_counter(udp_request_counter),
  folsom_metrics:new_counter(tcp_request_counter),
  folsom_metrics:new_meter(udp_request_meter),
  folsom_metrics:new_meter(tcp_request_meter),

  folsom_metrics:new_meter(udp_error_meter),
  folsom_metrics:new_meter(tcp_error_meter),
  folsom_metrics:new_history(udp_error_history),
  folsom_metrics:new_history(tcp_error_history),

  folsom_metrics:new_counter(erldns_handler_error_counter),
  folsom_metrics:new_meter(erldns_handler_error_meter),

  folsom_metrics:new_counter(worker_timeout_counter),
  folsom_metrics:new_meter(worker_timeout_meter),

  folsom_metrics:new_counter(dnssec_request_counter),
  folsom_metrics:new_meter(dnssec_request_meter),


  folsom_metrics:new_histogram(udp_handoff_histogram),
  folsom_metrics:new_histogram(tcp_handoff_histogram),

  folsom_metrics:new_counter(request_throttled_counter),
  folsom_metrics:new_meter(request_throttled_meter),
  folsom_metrics:new_histogram(request_handled_histogram),

  folsom_metrics:new_counter(packet_dropped_empty_queue_counter),
  folsom_metrics:new_meter(packet_dropped_empty_queue_meter),

  folsom_metrics:new_meter(cache_hit_meter),
  folsom_metrics:new_meter(cache_expired_meter),
  folsom_metrics:new_meter(cache_miss_meter).
