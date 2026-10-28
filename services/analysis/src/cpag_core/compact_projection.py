"""DAG6 complete standard projection with writer-local child composition.

No mutable identity cache survives a call. Each graph child is supplied in full
to the sink; only references computed by that same sink are composed. This is
an internal storage optimization, not a different graph or identity format.
"""
from .dual_source_export import event_graph
from .measurement import phase
from .shared_artifact_store_compact import FORMAT

STRATEGY_VERSION='stored-graph-composition-1'


@phase('stored_graph_composition_1')
def store_standard_projection(result, writer, *, replay=False, graph_name=None, events_name=None):
    """Return full projection values and their exact stored typed descriptors.

    Names register final roots when provided; None creates anonymous values for
    a history snapshot. Source verification uses the same complete-value sink
    protocol without accepting an expected stored root as an answer.
    """
    if getattr(writer,'version',None)!=FORMAT:
        raise ValueError('compact_projection_requires_dag6_sink')
    stored={}

    def identity(complete_graph):
        values={};references={}
        for key,value in complete_graph.items():
            if isinstance(value,(dict,list,tuple)):
                references[key]=writer.intern(value)['digest']
            else:values[key]=value
        sans_id=writer.compose(None,values,references)
        stored['graph']=writer.compose(graph_name,
            dict(values,graph_id='dual-graph-merkle-'+sans_id['digest']),references)
        return sans_id['digest']

    projected=event_graph(result,replay=replay,identity_strategy='merkle-json-dag-1',
                          graph_identity_callback=identity)
    # Schema checks above must finish before the caller may publish a history
    # reference/seal. A failed attempt can retain unsealed graph nodes.
    events=projected['events.json']
    stored['events']=writer.intern(events) if events_name is None else writer.add(events_name,events)
    return {'projection':projected,'graph':stored['graph'],'events':stored['events'],
            'strategy':STRATEGY_VERSION}
