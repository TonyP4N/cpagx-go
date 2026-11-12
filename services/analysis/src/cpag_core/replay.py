"""Opt-in arrival-driven bounded replay skeleton; no alignment or inference.

Caller supplies only records already available. push never reads another record,
looks ahead, sorts a dataset, or treats packet raw ticks as aligned event time.
"""
import json
from copy import deepcopy
from datetime import datetime, timedelta
from .contracts import validate


def instant(text):
    if not isinstance(text,str):raise ValueError('explicit zoned timestamp required')
    value=datetime.fromisoformat(text.replace('Z','+00:00'))
    if value.tzinfo is None:raise ValueError('explicit zoned timestamp required')
    return value


class ReplayWindow:
    def __init__(self, *, window_seconds=60, max_events=1000, max_bytes=8388608):
        if type(window_seconds) is not int or window_seconds<=0 or type(max_events) is not int or max_events<=0 or type(max_bytes) is not int or max_bytes<=0:
            raise ValueError('positive integer limits required')
        self.window=timedelta(seconds=window_seconds);self.max_events=max_events;self.max_bytes=max_bytes
        self.clock=None;self.events={};self.revision=0

    def advance(self, available_at):
        now=instant(available_at)
        if self.clock is not None and now<self.clock:raise ValueError('arrival clock cannot go backwards')
        self.clock=now
        self.events={key:item for key,item in self.events.items() if instant(item['event_time'])>=now-self.window}
        self.revision+=1
        return self.snapshot('clock_advanced')

    def push(self, event, *, available_at):
        # Validate before mutating state. Arrival time is a declared replay input,
        # not inferred from event_time or raw capture timestamps.
        if event.get('synthetic') is not True:raise ValueError('synthetic replay only')
        name='NetworkEvent' if 'protocol' in event else 'ProcessObservation'
        validate(name,event)
        now=instant(available_at)
        if self.clock is not None and now<self.clock:raise ValueError('arrival clock cannot go backwards')
        at=instant(event['event_time']) if event['event_time'] is not None else None
        current={key:item for key,item in self.events.items() if instant(item['event_time'])>=now-self.window}
        status='accepted'
        if at is None:status='timestamp_unavailable'
        elif at>now:status='future_timestamp_rejected'
        elif at<now-self.window:status='outside_window'
        elif event['event_id'] in current:
            status='duplicate' if event==current[event['event_id']] else 'conflicting_duplicate'
        elif len(current)>=self.max_events or sum(len(json.dumps(e).encode()) for e in current.values())+len(json.dumps(event).encode())>self.max_bytes:status='capacity_rejected'
        else:
            current[event['event_id']]=deepcopy(event)
            if at<now:status='late_revision'
        self.events=current;self.clock=now;self.revision+=1
        return self.snapshot(status)

    def snapshot(self, status='snapshot'):
        return {'synthetic':True,'mode':'arrival_replay_skeleton','revision':self.revision,
                'available_at':self.clock.isoformat() if self.clock else None,'status':status,
                'events':deepcopy(list(self.events.values())),
                'limitations':['No clock alignment, watermark finality, causal inference or industrial evaluation.']}
